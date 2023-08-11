// SPDX-License-Identifier: GPL-2.0
#if defined(CONFIG_PAGE_POOL)
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/io_uring.h>
#include <linux/netdevice.h>
#include <linux/nospec.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "zc_rx.h"
#include "rsrc.h"

typedef int (*bpf_op_t)(struct net_device *dev, struct netdev_bpf *bpf);

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

static int io_zc_rx_init_buf(struct device *dev, struct page *page,
			     struct io_zc_rx_buf *buf)
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

	memset(&buf->niov, 0, sizeof(buf->niov));
	atomic_long_set(&buf->niov.pp_ref_count, 0);
	buf->niov.dma_addr = addr;
	buf->page = page;
	get_page(page);
	return 0;
}

static void io_zc_rx_free_buf(struct device *dev, struct io_zc_rx_buf *buf)
{
	struct page *page = buf->page;

	if (dev)
		dma_unmap_page_attrs(dev, buf->niov.dma_addr, PAGE_SIZE,
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
		ret = io_zc_rx_init_buf(dev, page, buf);
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

	if (!!unix_get_socket(file)) {
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
		return ret;
	}
	ifq->sockets[idx] = file;
	ifq->nr_sockets++;
	return 0;
}

#endif
