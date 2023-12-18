// SPDX-License-Identifier: GPL-2.0
#if defined(CONFIG_PAGE_POOL)
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/io_uring.h>
#include <linux/netdevice.h>
#include <linux/nospec.h>
#include <net/busy_poll.h>
#include <net/tcp.h>
#include <trace/events/page_pool.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "zc_rx.h"
#include "rsrc.h"

struct io_zc_rx_args {
	struct io_zc_rx_ifq	*ifq;
	struct socket		*sock;
};

struct io_zc_refill_data {
	struct io_zc_rx_ifq *ifq;
	struct io_zc_rx_buf *buf;
};

typedef int (*bpf_op_t)(struct net_device *dev, struct netdev_bpf *bpf);

static inline u32 io_zc_rx_cqring_entries(struct io_zc_rx_ifq *ifq)
{
	struct io_rbuf_ring *ring = ifq->ring;

	return ifq->cached_cq_tail - READ_ONCE(ring->cq.head);
}

static inline struct device *netdev2dev(struct net_device *dev)
{
	return dev->dev.parent;
}

static int __io_queue_mgmt(struct net_device *dev, struct io_zc_rx_ifq *ifq,
			   u16 queue_id)
{
	struct netdev_bpf cmd;
	bpf_op_t ndo_bpf;

	ndo_bpf = dev->netdev_ops->ndo_bpf;
	if (!ndo_bpf)
		return -EINVAL;

	cmd.command = XDP_SETUP_ZC_RX;
	cmd.zc_rx.ifq = ifq;
	cmd.zc_rx.queue_id = queue_id;
	return ndo_bpf(dev, &cmd);
}

static int io_open_zc_rxq(struct io_zc_rx_ifq *ifq)
{
	return __io_queue_mgmt(ifq->dev, ifq, ifq->if_rxq_id);
}

static int io_close_zc_rxq(struct io_zc_rx_ifq *ifq)
{
	return __io_queue_mgmt(ifq->dev, NULL, ifq->if_rxq_id);
}

static int io_allocate_rbuf_ring(struct io_zc_rx_ifq *ifq,
				 struct io_uring_zc_rx_ifq_reg *reg)
{
	gfp_t gfp = GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN | __GFP_COMP;
	size_t off, size, rq_size, cq_size;
	void *ptr;

	off = sizeof(struct io_rbuf_ring);
	rq_size = reg->rq_entries * sizeof(struct io_uring_rbuf_rqe);
	cq_size = reg->cq_entries * sizeof(struct io_uring_rbuf_cqe);
	size = off + rq_size + cq_size;
	ptr = (void *) __get_free_pages(gfp, get_order(size));
	if (!ptr)
		return -ENOMEM;
	ifq->ring = (struct io_rbuf_ring *)ptr;
	ifq->rqes = (struct io_uring_rbuf_rqe *)((char *)ptr + off);
	ifq->cqes = (struct io_uring_rbuf_cqe *)((char *)ifq->rqes + rq_size);
	return 0;
}

static void io_free_rbuf_ring(struct io_zc_rx_ifq *ifq)
{
	if (ifq->ring)
		folio_put(virt_to_folio(ifq->ring));
}

static int io_zc_rx_init_buf(struct device *dev, struct page *page, u16 pool_id,
			     u32 pgid, struct io_zc_rx_buf *buf)
{
	dma_addr_t addr = 0;

	/* Skip dma setup for devices that don't do any DMA transfers */
	if (dev) {
		addr = dma_map_page_attrs(dev, page, 0, PAGE_SIZE,
					  DMA_BIDIRECTIONAL,
					  DMA_ATTR_SKIP_CPU_SYNC);
		if (dma_mapping_error(dev, addr))
			return -ENOMEM;
	}

	buf->dma = addr;
	buf->page = page;
	refcount_set(&buf->ppiov.refcount, 0);
	buf->ppiov.owner = NULL;
	buf->ppiov.pp = NULL;
	get_page(page);
	return 0;
}

static void io_zc_rx_free_buf(struct device *dev, struct io_zc_rx_buf *buf)
{
	struct page *page = buf->page;

	if (dev)
		dma_unmap_page_attrs(dev, buf->dma, PAGE_SIZE,
				     DMA_BIDIRECTIONAL,
				     DMA_ATTR_SKIP_CPU_SYNC);
	put_page(page);
}

static int io_zc_rx_map_pool(struct io_zc_rx_pool *pool,
			     struct io_mapped_ubuf *imu,
			     struct device *dev)
{
	struct io_zc_rx_buf *buf;
	struct page *page;
	int i, ret;

	for (i = 0; i < imu->nr_bvecs; i++) {
		page = imu->bvec[i].bv_page;
		buf = &pool->bufs[i];
		ret = io_zc_rx_init_buf(dev, page, pool->pool_id, i, buf);
		if (ret)
			goto err;

		pool->freelist[i] = i;
	}

	pool->free_count = imu->nr_bvecs;
	return 0;
err:
	while (i--) {
		buf = &pool->bufs[i];
		io_zc_rx_free_buf(dev, buf);
	}
	return ret;
}

static int io_zc_rx_create_pool(struct io_ring_ctx *ctx,
				struct io_zc_rx_ifq *ifq,
				u16 id)
{
	struct device *dev = netdev2dev(ifq->dev);
	struct io_mapped_ubuf *imu;
	struct io_zc_rx_pool *pool;
	int nr_pages;
	int ret;

	if (ifq->pool)
		return -EFAULT;

	if (unlikely(id >= ctx->nr_user_bufs))
		return -EFAULT;
	id = array_index_nospec(id, ctx->nr_user_bufs);
	imu = ctx->user_bufs[id];
	if (imu->ubuf & ~PAGE_MASK || imu->ubuf_end & ~PAGE_MASK)
		return -EFAULT;

	ret = -ENOMEM;
	nr_pages = imu->nr_bvecs;
	pool = kvmalloc(struct_size(pool, freelist, nr_pages), GFP_KERNEL);
	if (!pool)
		goto err;

	pool->bufs = kvmalloc_array(nr_pages, sizeof(*pool->bufs), GFP_KERNEL);
	if (!pool->bufs)
		goto err_buf;

	ret = io_zc_rx_map_pool(pool, imu, dev);
	if (ret)
		goto err_map;

	pool->ifq = ifq;
	pool->pool_id = id;
	pool->nr_bufs = nr_pages;
	spin_lock_init(&pool->freelist_lock);
	ifq->pool = pool;
	return 0;
err_map:
	kvfree(pool->bufs);
err_buf:
	kvfree(pool);
err:
	return ret;
}

static void io_zc_rx_destroy_pool(struct io_zc_rx_pool *pool)
{
	struct device *dev = netdev2dev(pool->ifq->dev);
	struct io_zc_rx_buf *buf;

	for (int i = 0; i < pool->nr_bufs; i++) {
		buf = &pool->bufs[i];
		io_zc_rx_free_buf(dev, buf);
	}
	kvfree(pool->bufs);
	kvfree(pool);
}

static struct io_zc_rx_ifq *io_zc_rx_ifq_alloc(struct io_ring_ctx *ctx)
{
	struct io_zc_rx_ifq *ifq;

	ifq = kzalloc(sizeof(*ifq), GFP_KERNEL);
	if (!ifq)
		return NULL;

	ifq->if_rxq_id = -1;
	ifq->ctx = ctx;
	return ifq;
}

static void io_shutdown_ifq(struct io_zc_rx_ifq *ifq)
{
	int i;

	if (!ifq)
		return;

	for (i = 0; i < ifq->nr_sockets; i++) {
		if (ifq->sockets[i]) {
			fput(ifq->sockets[i]);
			ifq->sockets[i] = NULL;
		}
	}
	ifq->nr_sockets = 0;

	if (ifq->if_rxq_id != -1) {
		io_close_zc_rxq(ifq);
		ifq->if_rxq_id = -1;
	}
}

static void io_zc_rx_ifq_free(struct io_zc_rx_ifq *ifq)
{
	io_shutdown_ifq(ifq);

	if (ifq->pool)
		io_zc_rx_destroy_pool(ifq->pool);
	if (ifq->dev)
		dev_put(ifq->dev);
	io_free_rbuf_ring(ifq);
	kfree(ifq);
}

int io_register_zc_rx_ifq(struct io_ring_ctx *ctx,
			  struct io_uring_zc_rx_ifq_reg __user *arg)
{
	struct io_uring_zc_rx_ifq_reg reg;
	struct io_zc_rx_ifq *ifq;
	size_t ring_sz, rqes_sz, cqes_sz;
	int ret;

	if (!(ctx->flags & IORING_SETUP_DEFER_TASKRUN))
		return -EINVAL;
	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	if (ctx->ifq)
		return -EBUSY;
	if (reg.if_rxq_id == -1)
		return -EINVAL;

	ifq = io_zc_rx_ifq_alloc(ctx);
	if (!ifq)
		return -ENOMEM;

	ret = io_allocate_rbuf_ring(ifq, &reg);
	if (ret)
		goto err;

	ret = -ENODEV;
	ifq->dev = dev_get_by_index(current->nsproxy->net_ns, reg.if_idx);
	if (!ifq->dev)
		goto err;

	ret = io_zc_rx_create_pool(ctx, ifq, reg.region_id);
	if (ret)
		goto err;

	ifq->rq_entries = reg.rq_entries;
	ifq->cq_entries = reg.cq_entries;
	ifq->if_rxq_id = reg.if_rxq_id;

	ret = io_open_zc_rxq(ifq);
	if (ret)
		goto err;

	ring_sz = sizeof(struct io_rbuf_ring);
	rqes_sz = sizeof(struct io_uring_rbuf_rqe) * ifq->rq_entries;
	cqes_sz = sizeof(struct io_uring_rbuf_cqe) * ifq->cq_entries;
	reg.mmap_sz = ring_sz + rqes_sz + cqes_sz;
	reg.rq_off.rqes = ring_sz;
	reg.cq_off.cqes = ring_sz + rqes_sz;
	reg.rq_off.head = offsetof(struct io_rbuf_ring, rq.head);
	reg.rq_off.tail = offsetof(struct io_rbuf_ring, rq.tail);
	reg.cq_off.head = offsetof(struct io_rbuf_ring, cq.head);
	reg.cq_off.tail = offsetof(struct io_rbuf_ring, cq.tail);

	if (copy_to_user(arg, &reg, sizeof(reg))) {
		ret = -EFAULT;
		goto err;
	}

	ctx->ifq = ifq;
	return 0;
err:
	io_zc_rx_ifq_free(ifq);
	return ret;
}

void io_unregister_zc_rx_ifqs(struct io_ring_ctx *ctx)
{
	struct io_zc_rx_ifq *ifq = ctx->ifq;

	lockdep_assert_held(&ctx->uring_lock);

	if (!ifq)
		return;

	WARN_ON_ONCE(ifq->nr_sockets);

	ctx->ifq = NULL;
	io_zc_rx_ifq_free(ifq);
}

void io_shutdown_zc_rx_ifqs(struct io_ring_ctx *ctx)
{
	lockdep_assert_held(&ctx->uring_lock);

	io_shutdown_ifq(ctx->ifq);
}

int io_register_zc_rx_sock(struct io_ring_ctx *ctx,
			   struct io_uring_zc_rx_sock_reg __user *arg)
{
	struct io_uring_zc_rx_sock_reg sr;
	struct io_zc_rx_ifq *ifq;
	struct socket *sock;
	struct file *file;
	int ret = -EEXIST;
	int idx;

	if (copy_from_user(&sr, arg, sizeof(sr)))
		return -EFAULT;
	if (sr.__resv[0] || sr.__resv[1])
		return -EINVAL;
	if (sr.zc_rx_ifq_idx != 0 || !ctx->ifq)
		return -EINVAL;

	ifq = ctx->ifq;
	if (ifq->nr_sockets >= ARRAY_SIZE(ifq->sockets))
		return -EINVAL;

	BUILD_BUG_ON(ARRAY_SIZE(ifq->sockets) > IO_ZC_IFQ_IDX_MASK);

	file = fget(sr.sockfd);
	if (!file)
		return -EBADF;

	if (io_file_need_scm(file)) {
		fput(file);
		return -EBADF;
	}

	sock = sock_from_file(file);
	if (unlikely(!sock || !sock->sk)) {
		fput(file);
		return -ENOTSOCK;
	}

	idx = ifq->nr_sockets;
	lock_sock(sock->sk);
	if (!sock->zc_rx_idx) {
		unsigned token;

		token = idx + (sr.zc_rx_ifq_idx << IO_ZC_IFQ_IDX_OFFSET);
		WRITE_ONCE(sock->zc_rx_idx, token);
		ret = 0;
	}
	release_sock(sock->sk);

	if (ret) {
		fput(file);
		return -EINVAL;
	}
	ifq->sockets[idx] = file;
	ifq->nr_sockets++;
	return 0;
}

static inline struct io_zc_rx_buf *io_iov_to_buf(struct page_pool_iov *iov)
{
	return container_of(iov, struct io_zc_rx_buf, ppiov);
}

static inline unsigned io_buf_pgid(struct io_zc_rx_pool *pool,
				   struct io_zc_rx_buf *buf)
{
	return buf - pool->bufs;
}

static void io_zc_rx_get_buf_uref(struct io_zc_rx_buf *buf)
{
	refcount_add(IO_ZC_RX_UREF, &buf->ppiov.refcount);
}

static bool io_zc_rx_put_buf_uref(struct io_zc_rx_buf *buf)
{
	if (page_pool_iov_refcount(&buf->ppiov) < IO_ZC_RX_UREF)
		return false;

	return page_pool_iov_sub_and_test(&buf->ppiov, IO_ZC_RX_UREF);
}

static inline struct page *io_zc_buf_to_pp_page(struct io_zc_rx_buf *buf)
{
	return page_pool_mangle_ppiov(&buf->ppiov);
}

static inline void io_zc_add_pp_cache(struct page_pool *pp,
				      struct io_zc_rx_buf *buf)
{
	refcount_set(&buf->ppiov.refcount, 1);
	pp->alloc.cache[pp->alloc.count++] = io_zc_buf_to_pp_page(buf);
}

static inline u32 io_zc_rx_rqring_entries(struct io_zc_rx_ifq *ifq)
{
	struct io_rbuf_ring *ring = ifq->ring;
	u32 entries;

	entries = smp_load_acquire(&ring->rq.tail) - ifq->cached_rq_head;
	return min(entries, ifq->rq_entries);
}

static void io_zc_rx_ring_refill(struct page_pool *pp,
				 struct io_zc_rx_ifq *ifq)
{
	unsigned int entries = io_zc_rx_rqring_entries(ifq);
	unsigned int mask = ifq->rq_entries - 1;
	struct io_zc_rx_pool *pool = ifq->pool;

	if (unlikely(!entries))
		return;

	while (entries--) {
		unsigned int rq_idx = ifq->cached_rq_head++ & mask;
		struct io_uring_rbuf_rqe *rqe = &ifq->rqes[rq_idx];
		u32 pgid = rqe->off / PAGE_SIZE;
		struct io_zc_rx_buf *buf = &pool->bufs[pgid];

		if (!io_zc_rx_put_buf_uref(buf))
			continue;
		io_zc_add_pp_cache(pp, buf);
		if (pp->alloc.count >= PP_ALLOC_CACHE_REFILL)
			break;
	}
	smp_store_release(&ifq->ring->rq.head, ifq->cached_rq_head);
}

static void io_zc_rx_refill_slow(struct page_pool *pp, struct io_zc_rx_ifq *ifq)
{
	struct io_zc_rx_pool *pool = ifq->pool;

	spin_lock_bh(&pool->freelist_lock);
	while (pool->free_count && pp->alloc.count < PP_ALLOC_CACHE_REFILL) {
		struct io_zc_rx_buf *buf;
		u32 pgid;

		pgid = pool->freelist[--pool->free_count];
		buf = &pool->bufs[pgid];

		io_zc_add_pp_cache(pp, buf);
		pp->pages_state_hold_cnt++;
		trace_page_pool_state_hold(pp, io_zc_buf_to_pp_page(buf),
					   pp->pages_state_hold_cnt);
	}
	spin_unlock_bh(&pool->freelist_lock);
}

static void io_zc_rx_recycle_buf(struct io_zc_rx_pool *pool,
				 struct io_zc_rx_buf *buf)
{
	spin_lock_bh(&pool->freelist_lock);
	pool->freelist[pool->free_count++] = io_buf_pgid(pool, buf);
	spin_unlock_bh(&pool->freelist_lock);
}

static struct page *io_pp_zc_alloc_pages(struct page_pool *pp, gfp_t gfp)
{
	struct io_zc_rx_ifq *ifq = pp->mp_priv;

	/* pp should already be ensuring that */
	if (unlikely(pp->alloc.count))
		goto out_return;

	io_zc_rx_ring_refill(pp, ifq);
	if (likely(pp->alloc.count))
		goto out_return;

	io_zc_rx_refill_slow(pp, ifq);
	if (!pp->alloc.count)
		return NULL;
out_return:
	return pp->alloc.cache[--pp->alloc.count];
}

static bool io_pp_zc_release_page(struct page_pool *pp, struct page *page)
{
	struct io_zc_rx_ifq *ifq = pp->mp_priv;
	struct page_pool_iov *ppiov;

	if (WARN_ON_ONCE(!page_is_page_pool_iov(page)))
		return false;

	ppiov = page_to_page_pool_iov(page);

	if (!page_pool_iov_sub_and_test(ppiov, 1))
		return false;

	io_zc_rx_recycle_buf(ifq->pool, io_iov_to_buf(ppiov));
	return true;
}

static void io_pp_zc_scrub(struct page_pool *pp)
{
	struct io_zc_rx_ifq *ifq = pp->mp_priv;
	struct io_zc_rx_pool *pool = ifq->pool;
	struct io_zc_rx_buf *buf;
	int i;

	for (i = 0; i < pool->nr_bufs; i++) {
		buf = &pool->bufs[i];

		if (io_zc_rx_put_buf_uref(buf)) {
			/* just return it to the page pool, it'll clean it up */
			refcount_set(&buf->ppiov.refcount, 1);
			page_pool_iov_put_many(&buf->ppiov, 1);
		}
	}
}

static void io_zc_rx_init_pool(struct io_zc_rx_pool *pool,
			       struct page_pool *pp)
{
	struct io_zc_rx_buf *buf;
	int i;

	for (i = 0; i < pool->nr_bufs; i++) {
		buf = &pool->bufs[i];
		buf->ppiov.pp = pp;
	}
}

static int io_pp_zc_init(struct page_pool *pp)
{
	struct io_zc_rx_ifq *ifq = pp->mp_priv;

	if (!ifq)
		return -EINVAL;
	if (pp->p.order != 0)
		return -EINVAL;
	if (!pp->p.napi)
		return -EINVAL;

	io_zc_rx_init_pool(ifq->pool, pp);
	percpu_ref_get(&ifq->ctx->refs);
	ifq->pp = pp;
	return 0;
}

static void io_pp_zc_destroy(struct page_pool *pp)
{
	struct io_zc_rx_ifq *ifq = pp->mp_priv;
	struct io_zc_rx_pool *pool = ifq->pool;

	ifq->pp = NULL;

	if (WARN_ON_ONCE(pool->free_count != pool->nr_bufs))
		return;
	percpu_ref_put(&ifq->ctx->refs);
}

const struct pp_memory_provider_ops io_uring_pp_zc_ops = {
	.alloc_pages		= io_pp_zc_alloc_pages,
	.release_page		= io_pp_zc_release_page,
	.init			= io_pp_zc_init,
	.destroy		= io_pp_zc_destroy,
	.scrub			= io_pp_zc_scrub,
};
EXPORT_SYMBOL(io_uring_pp_zc_ops);

static void io_napi_refill(void *data)
{
	struct io_zc_refill_data *rd = data;
	struct io_zc_rx_ifq *ifq = rd->ifq;
	void *page;

	if (WARN_ON_ONCE(!ifq->pp))
		return;

	page = page_pool_dev_alloc_pages(ifq->pp);
	if (!page)
		return;
	if (WARN_ON_ONCE(!page_is_page_pool_iov(page)))
		return;

	rd->buf = io_iov_to_buf(page_to_page_pool_iov(page));
}

static struct io_zc_rx_buf *io_zc_get_buf_task_safe(struct io_zc_rx_ifq *ifq)
{
	struct io_zc_refill_data rd = {
		.ifq = ifq,
	};

	napi_execute(ifq->pp->p.napi, io_napi_refill, &rd);
	return rd.buf;
}

static inline void io_zc_return_rbuf_cqe(struct io_zc_rx_ifq *ifq)
{
	ifq->cached_cq_tail--;
}

static inline struct io_uring_rbuf_cqe *io_zc_get_rbuf_cqe(struct io_zc_rx_ifq *ifq)
{
	struct io_uring_rbuf_cqe *cqe;
	unsigned int cq_idx, queued, free, entries;
	unsigned int mask = ifq->cq_entries - 1;

	cq_idx = ifq->cached_cq_tail & mask;
	smp_rmb();
	queued = min(io_zc_rx_cqring_entries(ifq), ifq->cq_entries);
	free = ifq->cq_entries - queued;
	entries = min(free, ifq->cq_entries - cq_idx);
	if (!entries)
		return NULL;

	cqe = &ifq->cqes[cq_idx];
	ifq->cached_cq_tail++;
	return cqe;
}

static ssize_t zc_rx_copy_chunk(struct io_zc_rx_ifq *ifq, void *data,
				unsigned int offset, size_t len,
				unsigned sock_idx)
{
	size_t copy_size, copied = 0;
	struct io_uring_rbuf_cqe *cqe;
	struct io_zc_rx_buf *buf;
	int ret = 0, off = 0;
	u8 *vaddr;

	do {
		cqe = io_zc_get_rbuf_cqe(ifq);
		if (!cqe) {
			ret = -ENOBUFS;
			break;
		}
		buf = io_zc_get_buf_task_safe(ifq);
		if (!buf) {
			io_zc_return_rbuf_cqe(ifq);
			ret = -ENOMEM;
			break;
		}

		vaddr = kmap_local_page(buf->page);
		copy_size = min_t(size_t, PAGE_SIZE, len);
		memcpy(vaddr, data + offset, copy_size);
		kunmap_local(vaddr);

		cqe->region = 0;
		cqe->off = io_buf_pgid(ifq->pool, buf) * PAGE_SIZE + off;
		cqe->len = copy_size;
		cqe->flags = 0;
		cqe->sock = sock_idx;

		io_zc_rx_get_buf_uref(buf);
		page_pool_iov_put_many(&buf->ppiov, 1);

		offset += copy_size;
		len -= copy_size;
		copied += copy_size;
	} while (offset < len);

	return copied ? copied : ret;
}

static int zc_rx_recv_frag(struct io_zc_rx_ifq *ifq, const skb_frag_t *frag,
			   int off, int len, unsigned sock_idx)
{
	off += skb_frag_off(frag);

	if (likely(page_is_page_pool_iov(frag->bv_page))) {
		struct io_uring_rbuf_cqe *cqe;
		struct io_zc_rx_buf *buf;
		struct page_pool_iov *ppiov;

		ppiov = page_to_page_pool_iov(frag->bv_page);
		if (ppiov->pp->p.memory_provider != PP_MP_IOU_ZCRX ||
		    ppiov->pp->mp_priv != ifq)
			return -EFAULT;

		cqe = io_zc_get_rbuf_cqe(ifq);
		if (!cqe)
			return -ENOBUFS;

		buf = io_iov_to_buf(ppiov);
		io_zc_rx_get_buf_uref(buf);

		cqe->region = 0;
		cqe->off = io_buf_pgid(ifq->pool, buf) * PAGE_SIZE + off;
		cqe->len = len;
		cqe->sock = sock_idx;
		cqe->flags = 0;
	} else {
		struct page *page = skb_frag_page(frag);
		u32 p_off, p_len, t, copied = 0;
		u8 *vaddr;
		int ret = 0;

		skb_frag_foreach_page(frag, off, len,
				      page, p_off, p_len, t) {
			vaddr = kmap_local_page(page);
			ret = zc_rx_copy_chunk(ifq, vaddr, p_off, p_len, sock_idx);
			kunmap_local(vaddr);

			if (ret < 0)
				return copied ? copied : ret;
			copied += ret;
		}
		len = copied;
	}

	return len;
}

static int
zc_rx_recv_skb(read_descriptor_t *desc, struct sk_buff *skb,
	       unsigned int offset, size_t len)
{
	struct io_zc_rx_args *args = desc->arg.data;
	struct io_zc_rx_ifq *ifq = args->ifq;
	struct socket *sock = args->sock;
	unsigned sock_idx = sock->zc_rx_idx & IO_ZC_IFQ_IDX_MASK;
	struct sk_buff *frag_iter;
	unsigned start, start_off = offset;
	int i, copy, end, off;
	int ret = 0;

	if (unlikely(offset < skb_headlen(skb))) {
		ssize_t copied;
		size_t to_copy;

		to_copy = min_t(size_t, skb_headlen(skb) - offset, len);
		copied = zc_rx_copy_chunk(ifq, skb->data, offset, to_copy,
					  sock_idx);
		if (copied < 0) {
			ret = copied;
			goto out;
		}
		offset += copied;
		len -= copied;
		if (!len)
			goto out;
		if (offset != skb_headlen(skb))
			goto out;
	}

	start = skb_headlen(skb);

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *frag;

		WARN_ON(start > offset + len);

		frag = &skb_shinfo(skb)->frags[i];
		end = start + skb_frag_size(frag);

		if (offset < end) {
			copy = end - offset;
			if (copy > len)
				copy = len;

			off = offset - start;
			ret = zc_rx_recv_frag(ifq, frag, off, copy, sock_idx);
			if (ret < 0)
				goto out;

			offset += ret;
			len -= ret;
			if (len == 0 || ret != copy)
				goto out;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if (offset < end) {
			copy = end - offset;
			if (copy > len)
				copy = len;

			off = offset - start;
			ret = zc_rx_recv_skb(desc, frag_iter, off, copy);
			if (ret < 0)
				goto out;

			offset += ret;
			len -= ret;
			if (len == 0 || ret != copy)
				goto out;
		}
		start = end;
	}

out:
	smp_store_release(&ifq->ring->cq.tail, ifq->cached_cq_tail);
	if (offset == start_off)
		return ret;
	return offset - start_off;
}

static int io_zc_rx_tcp_read(struct io_zc_rx_ifq *ifq, struct sock *sk)
{
	struct io_zc_rx_args args = {
		.ifq = ifq,
		.sock = sk->sk_socket,
	};
	read_descriptor_t rd_desc = {
		.count = 1,
		.arg.data = &args,
	};

	return tcp_read_sock(sk, &rd_desc, zc_rx_recv_skb);
}

static int io_zc_rx_tcp_recvmsg(struct io_zc_rx_ifq *ifq, struct sock *sk,
				unsigned int recv_limit,
				int flags, int *addr_len)
{
	size_t used;
	long timeo;
	int ret;

	ret = used = 0;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
	while (recv_limit) {
		ret = io_zc_rx_tcp_read(ifq, sk);
		if (ret < 0)
			break;
		if (!ret) {
			if (used)
				break;
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				ret = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;
			if (sk->sk_state == TCP_CLOSE) {
				ret = -ENOTCONN;
				break;
			}
			if (!timeo) {
				ret = -EAGAIN;
				break;
			}
			if (!skb_queue_empty(&sk->sk_receive_queue))
				break;
			sk_wait_data(sk, &timeo, NULL);
			if (signal_pending(current)) {
				ret = sock_intr_errno(timeo);
				break;
			}
			continue;
		}
		recv_limit -= ret;
		used += ret;

		if (!timeo)
			break;
		release_sock(sk);
		lock_sock(sk);

		if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
		    (sk->sk_shutdown & RCV_SHUTDOWN) ||
		    signal_pending(current))
			break;
	}
	release_sock(sk);
	/* TODO: handle timestamping */
	return used ? used : ret;
}

int io_zc_rx_recv(struct io_zc_rx_ifq *ifq, struct socket *sock,
		  unsigned int limit, unsigned int flags)
{
	struct sock *sk = sock->sk;
	const struct proto *prot;
	int addr_len = 0;
	int ret;

	if (flags & MSG_ERRQUEUE)
		return -EOPNOTSUPP;

	prot = READ_ONCE(sk->sk_prot);
	if (prot->recvmsg != tcp_recvmsg)
		return -EPROTONOSUPPORT;

	sock_rps_record_flow(sk);

	ret = io_zc_rx_tcp_recvmsg(ifq, sk, limit, flags, &addr_len);

	return ret;
}

#endif
