// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/nospec.h>
#include <linux/netdevice.h>
#include <linux/io_uring.h>
#include <linux/skbuff_ref.h>
#include <linux/io_uring/net.h>
#include <net/netdev_rx_queue.h>
#include <net/busy_poll.h>
#include <net/page_pool/helpers.h>
#include <trace/events/page_pool.h>
#include <net/tcp.h>
#include <net/rps.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "memmap.h"
#include "zcrx.h"
#include "rsrc.h"

#define IO_RQ_MAX_ENTRIES		32768

#if defined(CONFIG_PAGE_POOL) && defined(CONFIG_INET)

struct io_zcrx_args {
	struct io_kiocb		*req;
	struct io_zcrx_ifq	*ifq;
	struct socket		*sock;
};

struct io_zc_refill_data {
	struct io_zcrx_ifq *ifq;
	struct net_iov *niov;
};

static inline struct io_zcrx_area *io_zcrx_iov_to_area(const struct net_iov *niov)
{
	struct net_iov_area *owner = net_iov_owner(niov);

	return container_of(owner, struct io_zcrx_area, nia);
}

static inline struct page *io_zcrx_iov_page(const struct net_iov *niov)
{
	struct io_zcrx_area *area = io_zcrx_iov_to_area(niov);

	return area->pages[net_iov_idx(niov)];
}

static int io_open_zc_rxq(struct io_zcrx_ifq *ifq, unsigned ifq_idx)
{
	struct netdev_rx_queue *rxq;
	struct net_device *dev = ifq->dev;
	int ret;

	ASSERT_RTNL();

	if (ifq_idx >= dev->num_rx_queues)
		return -EINVAL;
	ifq_idx = array_index_nospec(ifq_idx, dev->num_rx_queues);

	rxq = __netif_get_rx_queue(ifq->dev, ifq_idx);
	if (rxq->mp_params.mp_priv)
		return -EEXIST;

	ifq->if_rxq = ifq_idx;
	rxq->mp_params.mp_ops = &io_uring_pp_zc_ops;
	rxq->mp_params.mp_priv = ifq;
	ret = netdev_rx_queue_restart(ifq->dev, ifq->if_rxq);
	if (ret) {
		rxq->mp_params.mp_ops = NULL;
		rxq->mp_params.mp_priv = NULL;
		ifq->if_rxq = -1;
	}
	return ret;
}

static void io_close_zc_rxq(struct io_zcrx_ifq *ifq)
{
	struct netdev_rx_queue *rxq;
	int err;

	if (ifq->if_rxq == -1)
		return;

	rtnl_lock();
	if (WARN_ON_ONCE(ifq->if_rxq >= ifq->dev->num_rx_queues)) {
		rtnl_unlock();
		return;
	}

	rxq = __netif_get_rx_queue(ifq->dev, ifq->if_rxq);

	WARN_ON_ONCE(rxq->mp_params.mp_priv != ifq);

	rxq->mp_params.mp_ops = NULL;
	rxq->mp_params.mp_priv = NULL;

	err = netdev_rx_queue_restart(ifq->dev, ifq->if_rxq);
	if (err)
		pr_devel("io_uring: can't restart a queue on zcrx close\n");

	rtnl_unlock();
	ifq->if_rxq = -1;
}

static int io_allocate_rbuf_ring(struct io_zcrx_ifq *ifq,
				 struct io_uring_zcrx_ifq_reg *reg)
{
	size_t off, size;
	void *ptr;

	off = sizeof(struct io_uring);
	size = off + sizeof(struct io_uring_zcrx_rqe) * reg->rq_entries;

	ptr = io_pages_map(&ifq->rqe_pages, &ifq->n_rqe_pages, size);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	ifq->rq_ring = (struct io_uring *)ptr;
	ifq->rqes = (struct io_uring_zcrx_rqe *)((char *)ptr + off);
	return 0;
}

static void io_free_rbuf_ring(struct io_zcrx_ifq *ifq)
{
	io_pages_unmap(ifq->rq_ring, &ifq->rqe_pages, &ifq->n_rqe_pages, true);
	ifq->rq_ring = NULL;
	ifq->rqes = NULL;
}

static void io_zcrx_free_area(struct io_zcrx_area *area)
{
	if (area->freelist)
		kvfree(area->freelist);
	if (area->nia.niovs)
		kvfree(area->nia.niovs);
	if (area->pages) {
		unpin_user_pages(area->pages, area->nia.num_niovs);
		kvfree(area->pages);
	}
	kfree(area);
}

static int io_zcrx_create_area(struct io_ring_ctx *ctx,
			       struct io_zcrx_ifq *ifq,
			       struct io_zcrx_area **res,
			       struct io_uring_zcrx_area_reg *area_reg)
{
	struct io_zcrx_area *area;
	int i, ret, nr_pages;
	struct iovec iov;

	if (area_reg->flags || area_reg->rq_area_token)
		return -EINVAL;
	if (area_reg->__resv1 || area_reg->__resv2[0] || area_reg->__resv2[1])
		return -EINVAL;
	if (area_reg->addr & ~PAGE_MASK || area_reg->len & ~PAGE_MASK)
		return -EINVAL;

	iov.iov_base = u64_to_user_ptr(area_reg->addr);
	iov.iov_len = area_reg->len;
	ret = io_buffer_validate(&iov);
	if (ret)
		return ret;

	ret = -ENOMEM;
	area = kzalloc(sizeof(*area), GFP_KERNEL);
	if (!area)
		goto err;

	area->pages = io_pin_pages((unsigned long)area_reg->addr, area_reg->len,
				   &nr_pages);
	if (IS_ERR(area->pages)) {
		ret = PTR_ERR(area->pages);
		area->pages = NULL;
		goto err;
	}
	area->nia.num_niovs = nr_pages;

	area->nia.niovs = kvmalloc_array(nr_pages, sizeof(area->nia.niovs[0]),
					 GFP_KERNEL | __GFP_ZERO);
	if (!area->nia.niovs)
		goto err;

	area->freelist = kvmalloc_array(nr_pages, sizeof(area->freelist[0]),
					GFP_KERNEL | __GFP_ZERO);
	if (!area->freelist)
		goto err;

	for (i = 0; i < nr_pages; i++) {
		struct net_iov *niov = &area->nia.niovs[i];

		niov->owner = &area->nia;
		area->freelist[i] = i;
	}

	area->free_count = nr_pages;
	area->ifq = ifq;
	/* we're only supporting one area per ifq for now */
	area->area_id = 0;
	area_reg->rq_area_token = (u64)area->area_id << IORING_ZCRX_AREA_SHIFT;
	spin_lock_init(&area->freelist_lock);
	*res = area;
	return 0;
err:
	if (area)
		io_zcrx_free_area(area);
	return ret;
}

static struct io_zcrx_ifq *io_zcrx_ifq_alloc(struct io_ring_ctx *ctx)
{
	struct io_zcrx_ifq *ifq;

	ifq = kzalloc(sizeof(*ifq), GFP_KERNEL);
	if (!ifq)
		return NULL;

	ifq->if_rxq = -1;
	ifq->ctx = ctx;
	return ifq;
}

static void io_zcrx_ifq_free(struct io_zcrx_ifq *ifq)
{
	io_close_zc_rxq(ifq);

	if (ifq->area)
		io_zcrx_free_area(ifq->area);
	if (ifq->dev)
		dev_put(ifq->dev);
	io_free_rbuf_ring(ifq);
	kfree(ifq);
}

int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
			  struct io_uring_zcrx_ifq_reg __user *arg)
{
	struct io_uring_zcrx_area_reg area;
	struct io_uring_zcrx_ifq_reg reg;
	struct io_zcrx_ifq *ifq;
	size_t ring_sz, rqes_sz;
	int ret;

	/*
	 * 1. Interface queue allocation.
	 * 2. It can observe data destined for sockets of other tasks.
	 */
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	/* mandatory io_uring features for zc rx */
	if (!(ctx->flags & IORING_SETUP_DEFER_TASKRUN &&
	      ctx->flags & IORING_SETUP_CQE32))
		return -EINVAL;
	if (ctx->ifq)
		return -EBUSY;
	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	if (reg.__resv[0] || reg.__resv[1] || reg.__resv[2])
		return -EINVAL;
	if (reg.if_rxq == -1 || !reg.rq_entries || reg.flags)
		return -EINVAL;
	if (reg.rq_entries > IO_RQ_MAX_ENTRIES) {
		if (!(ctx->flags & IORING_SETUP_CLAMP))
			return -EINVAL;
		reg.rq_entries = IO_RQ_MAX_ENTRIES;
	}
	reg.rq_entries = roundup_pow_of_two(reg.rq_entries);

	if (copy_from_user(&area, u64_to_user_ptr(reg.area_ptr), sizeof(area)))
		return -EFAULT;

	ifq = io_zcrx_ifq_alloc(ctx);
	if (!ifq)
		return -ENOMEM;

	ret = io_allocate_rbuf_ring(ifq, &reg);
	if (ret)
		goto err;

	ret = io_zcrx_create_area(ctx, ifq, &ifq->area, &area);
	if (ret)
		goto err;

	ifq->rq_entries = reg.rq_entries;

	ret = -ENODEV;
	rtnl_lock();
	ifq->dev = dev_get_by_index(current->nsproxy->net_ns, reg.if_idx);
	if (!ifq->dev)
		goto err_rtnl_unlock;

	ret = io_open_zc_rxq(ifq, reg.if_rxq);
	if (ret)
		goto err_rtnl_unlock;
	rtnl_unlock();

	ring_sz = sizeof(struct io_uring);
	rqes_sz = sizeof(struct io_uring_zcrx_rqe) * ifq->rq_entries;
	reg.offsets.mmap_sz = ring_sz + rqes_sz;
	reg.offsets.rqes = ring_sz;
	reg.offsets.head = offsetof(struct io_uring, head);
	reg.offsets.tail = offsetof(struct io_uring, tail);

	if (copy_to_user(arg, &reg, sizeof(reg))) {
		io_close_zc_rxq(ifq);
		ret = -EFAULT;
		goto err;
	}
	if (copy_to_user(u64_to_user_ptr(reg.area_ptr), &area, sizeof(area))) {
		io_close_zc_rxq(ifq);
		ret = -EFAULT;
		goto err;
	}
	ctx->ifq = ifq;
	return 0;

err_rtnl_unlock:
	rtnl_unlock();
err:
	io_zcrx_ifq_free(ifq);
	return ret;
}

void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx)
{
	struct io_zcrx_ifq *ifq = ctx->ifq;

	lockdep_assert_held(&ctx->uring_lock);

	if (!ifq)
		return;

	ctx->ifq = NULL;
	io_zcrx_ifq_free(ifq);
}

void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx)
{
	lockdep_assert_held(&ctx->uring_lock);

	if (ctx->ifq)
		io_close_zc_rxq(ctx->ifq);
}

static void io_zcrx_get_buf_uref(struct net_iov *niov)
{
	atomic_long_add(IO_ZC_RX_UREF, &niov->pp_ref_count);
}

static bool io_zcrx_niov_put(struct net_iov *niov, int nr)
{
	return atomic_long_sub_and_test(nr, &niov->pp_ref_count);
}

static bool io_zcrx_put_niov_uref(struct net_iov *niov)
{
	if (atomic_long_read(&niov->pp_ref_count) < IO_ZC_RX_UREF)
		return false;

	return io_zcrx_niov_put(niov, IO_ZC_RX_UREF);
}

static inline void io_zc_add_pp_cache(struct page_pool *pp,
				      struct net_iov *niov)
{
	netmem_ref netmem = net_iov_to_netmem(niov);

#if defined(CONFIG_HAS_DMA) && defined(CONFIG_DMA_NEED_SYNC)
	if (pp->dma_sync && dma_dev_need_sync(pp->p.dev)) {
		dma_addr_t dma_addr = page_pool_get_dma_addr_netmem(netmem);

		dma_sync_single_range_for_device(pp->p.dev, dma_addr,
						 pp->p.offset, pp->p.max_len,
						 pp->p.dma_dir);
	}
#endif

	page_pool_fragment_netmem(netmem, 1);
	pp->alloc.cache[pp->alloc.count++] = netmem;
}

static inline u32 io_zcrx_rqring_entries(struct io_zcrx_ifq *ifq)
{
	u32 entries;

	entries = smp_load_acquire(&ifq->rq_ring->tail) - ifq->cached_rq_head;
	return min(entries, ifq->rq_entries);
}

static struct io_uring_zcrx_rqe *io_zcrx_get_rqe(struct io_zcrx_ifq *ifq,
						 unsigned mask)
{
	unsigned int idx = ifq->cached_rq_head++ & mask;

	return &ifq->rqes[idx];
}

static void io_zcrx_ring_refill(struct page_pool *pp,
				struct io_zcrx_ifq *ifq)
{
	unsigned int entries = io_zcrx_rqring_entries(ifq);
	unsigned int mask = ifq->rq_entries - 1;

	entries = min_t(unsigned, entries, PP_ALLOC_CACHE_REFILL - pp->alloc.count);
	if (unlikely(!entries))
		return;

	do {
		struct io_uring_zcrx_rqe *rqe = io_zcrx_get_rqe(ifq, mask);
		struct io_zcrx_area *area;
		struct net_iov *niov;
		unsigned niov_idx, area_idx;

		area_idx = rqe->off >> IORING_ZCRX_AREA_SHIFT;
		niov_idx = (rqe->off & ~IORING_ZCRX_AREA_MASK) / PAGE_SIZE;

		if (unlikely(rqe->__pad || area_idx))
			continue;
		area = ifq->area;

		if (unlikely(niov_idx >= area->nia.num_niovs))
			continue;
		niov_idx = array_index_nospec(niov_idx, area->nia.num_niovs);

		niov = &area->nia.niovs[niov_idx];
		if (!io_zcrx_put_niov_uref(niov))
			continue;
		io_zc_add_pp_cache(pp, niov);
	} while (--entries);

	smp_store_release(&ifq->rq_ring->head, ifq->cached_rq_head);
}

static void io_zcrx_refill_slow(struct page_pool *pp, struct io_zcrx_ifq *ifq)
{
	struct io_zcrx_area *area = ifq->area;

	spin_lock_bh(&area->freelist_lock);
	while (area->free_count && pp->alloc.count < PP_ALLOC_CACHE_REFILL) {
		struct net_iov *niov;
		u32 pgid;

		pgid = area->freelist[--area->free_count];
		niov = &area->nia.niovs[pgid];

		io_zc_add_pp_cache(pp, niov);

		pp->pages_state_hold_cnt++;
		trace_page_pool_state_hold(pp, net_iov_to_netmem(niov),
					   pp->pages_state_hold_cnt);
	}
	spin_unlock_bh(&area->freelist_lock);
}

static void io_zcrx_recycle_niov(struct net_iov *niov)
{
	struct io_zcrx_area *area = io_zcrx_iov_to_area(niov);

	spin_lock_bh(&area->freelist_lock);
	area->freelist[area->free_count++] = net_iov_idx(niov);
	spin_unlock_bh(&area->freelist_lock);
}

static netmem_ref io_pp_zc_alloc_netmems(struct page_pool *pp, gfp_t gfp)
{
	struct io_zcrx_ifq *ifq = pp->mp_priv;

	/* pp should already be ensuring that */
	if (unlikely(pp->alloc.count))
		goto out_return;

	io_zcrx_ring_refill(pp, ifq);
	if (likely(pp->alloc.count))
		goto out_return;

	io_zcrx_refill_slow(pp, ifq);
	if (!pp->alloc.count)
		return 0;
out_return:
	return pp->alloc.cache[--pp->alloc.count];
}

static bool io_pp_zc_release_netmem(struct page_pool *pp, netmem_ref netmem)
{
	struct net_iov *niov;

	if (WARN_ON_ONCE(!netmem_is_net_iov(netmem)))
		return false;

	niov = netmem_to_net_iov(netmem);

	if (io_zcrx_niov_put(niov, 1))
		io_zcrx_recycle_niov(niov);
	return false;
}

static void io_pp_zc_scrub(struct page_pool *pp)
{
	struct io_zcrx_ifq *ifq = pp->mp_priv;
	struct io_zcrx_area *area = ifq->area;
	int i;

	/* Reclaim back all buffers given to the user space. */
	for (i = 0; i < area->nia.num_niovs; i++) {
		struct net_iov *niov = &area->nia.niovs[i];
		int count;

		if (!io_zcrx_put_niov_uref(niov))
			continue;
		io_zcrx_recycle_niov(niov);

		count = atomic_inc_return_relaxed(&pp->pages_state_release_cnt);
		trace_page_pool_state_release(pp, net_iov_to_netmem(niov), count);
	}
}

static int io_pp_zc_init(struct page_pool *pp)
{
	struct io_zcrx_ifq *ifq = pp->mp_priv;
	struct io_zcrx_area *area = ifq->area;
	int ret;

	if (!ifq)
		return -EINVAL;
	if (pp->p.order != 0)
		return -EINVAL;
	if (!pp->p.napi)
		return -EINVAL;
	if (!pp->p.napi->napi_id)
		return -EINVAL;

	ret = page_pool_init_paged_area(pp, &area->nia, area->pages);
	if (ret)
		return ret;

	ifq->napi_id = pp->p.napi->napi_id;
	percpu_ref_get(&ifq->ctx->refs);
	ifq->pp = pp;
	return 0;
}

static void io_pp_zc_destroy(struct page_pool *pp)
{
	struct io_zcrx_ifq *ifq = pp->mp_priv;
	struct io_zcrx_area *area = ifq->area;

	page_pool_release_area(pp, &ifq->area->nia);

	ifq->pp = NULL;
	ifq->napi_id = 0;

	if (WARN_ON_ONCE(area->free_count != area->nia.num_niovs))
		return;
	percpu_ref_put(&ifq->ctx->refs);
}

const struct memory_provider_ops io_uring_pp_zc_ops = {
	.alloc_netmems		= io_pp_zc_alloc_netmems,
	.release_netmem		= io_pp_zc_release_netmem,
	.init			= io_pp_zc_init,
	.destroy		= io_pp_zc_destroy,
	.scrub			= io_pp_zc_scrub,
};

static void io_napi_refill(void *data)
{
	struct io_zc_refill_data *rd = data;
	struct io_zcrx_ifq *ifq = rd->ifq;
	netmem_ref netmem;

	if (WARN_ON_ONCE(!ifq->pp))
		return;

	netmem = page_pool_alloc_netmem(ifq->pp, GFP_ATOMIC | __GFP_NOWARN);
	if (!netmem)
		return;
	if (WARN_ON_ONCE(!netmem_is_net_iov(netmem)))
		return;

	rd->niov = netmem_to_net_iov(netmem);
}

static struct net_iov *io_zc_get_buf_task_safe(struct io_zcrx_ifq *ifq)
{
	struct io_zc_refill_data rd = {
		.ifq = ifq,
	};

	napi_execute(ifq->napi_id, io_napi_refill, &rd);
	return rd.niov;
}

static bool io_zcrx_queue_cqe(struct io_kiocb *req, struct net_iov *niov,
			      struct io_zcrx_ifq *ifq, int off, int len)
{
	struct io_uring_zcrx_cqe *rcqe;
	struct io_zcrx_area *area;
	struct io_uring_cqe *cqe;
	u64 offset;

	if (!io_defer_get_uncommited_cqe(req->ctx, &cqe))
		return false;

	cqe->user_data = req->cqe.user_data;
	cqe->res = len;
	cqe->flags = IORING_CQE_F_MORE;

	area = io_zcrx_iov_to_area(niov);
	offset = off + (net_iov_idx(niov) << PAGE_SHIFT);
	rcqe = (struct io_uring_zcrx_cqe *)(cqe + 1);
	rcqe->off = offset + ((u64)area->area_id << IORING_ZCRX_AREA_SHIFT);
	memset(&rcqe->__pad, 0, sizeof(rcqe->__pad));
	return true;
}

static ssize_t io_zcrx_copy_chunk(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
				  void *data, unsigned int offset, size_t len)
{
	size_t copy_size, copied = 0;
	int ret = 0, off = 0;
	struct page *page;
	u8 *vaddr;

	do {
		struct net_iov *niov;

		niov = io_zc_get_buf_task_safe(ifq);
		if (!niov) {
			ret = -ENOMEM;
			break;
		}

		page = io_zcrx_iov_page(niov);
		vaddr = kmap_local_page(page);
		copy_size = min_t(size_t, PAGE_SIZE, len);
		memcpy(vaddr, data + offset, copy_size);
		kunmap_local(vaddr);

		if (!io_zcrx_queue_cqe(req, niov, ifq, off, copy_size)) {
			napi_pp_put_page(net_iov_to_netmem(niov));
			return -ENOSPC;
		}

		io_zcrx_get_buf_uref(niov);
		napi_pp_put_page(net_iov_to_netmem(niov));

		offset += copy_size;
		len -= copy_size;
		copied += copy_size;
	} while (offset < len);

	return copied ? copied : ret;
}

static int io_zcrx_recv_frag(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
			     const skb_frag_t *frag, int off, int len)
{
	struct net_iov *niov;

	off += skb_frag_off(frag);

	if (unlikely(!skb_frag_is_net_iov(frag))) {
		struct page *page = skb_frag_page(frag);
		u32 p_off, p_len, t, copied = 0;
		u8 *vaddr;
		int ret = 0;

		skb_frag_foreach_page(frag, off, len,
				      page, p_off, p_len, t) {
			vaddr = kmap_local_page(page);
			ret = io_zcrx_copy_chunk(req, ifq, vaddr, p_off, p_len);
			kunmap_local(vaddr);

			if (ret < 0)
				return copied ? copied : ret;
			copied += ret;
		}
		return copied;
	}

	niov = netmem_to_net_iov(frag->netmem);
	if (niov->pp->mp_ops != &io_uring_pp_zc_ops ||
	    niov->pp->mp_priv != ifq)
		return -EFAULT;

	if (!io_zcrx_queue_cqe(req, niov, ifq, off, len))
		return -ENOSPC;
	io_zcrx_get_buf_uref(niov);
	return len;
}

static int
io_zcrx_recv_skb(read_descriptor_t *desc, struct sk_buff *skb,
		 unsigned int offset, size_t len)
{
	struct io_zcrx_args *args = desc->arg.data;
	struct io_zcrx_ifq *ifq = args->ifq;
	struct io_kiocb *req = args->req;
	struct sk_buff *frag_iter;
	unsigned start, start_off = offset;
	int i, copy, end, off;
	int ret = 0;

	if (unlikely(offset < skb_headlen(skb))) {
		ssize_t copied;
		size_t to_copy;

		to_copy = min_t(size_t, skb_headlen(skb) - offset, len);
		copied = io_zcrx_copy_chunk(req, ifq, skb->data, offset, to_copy);
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

		if (WARN_ON(start > offset + len))
			return -EFAULT;

		frag = &skb_shinfo(skb)->frags[i];
		end = start + skb_frag_size(frag);

		if (offset < end) {
			copy = end - offset;
			if (copy > len)
				copy = len;

			off = offset - start;
			ret = io_zcrx_recv_frag(req, ifq, frag, off, copy);
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
		if (WARN_ON(start > offset + len))
			return -EFAULT;

		end = start + frag_iter->len;
		if (offset < end) {
			copy = end - offset;
			if (copy > len)
				copy = len;

			off = offset - start;
			ret = io_zcrx_recv_skb(desc, frag_iter, off, copy);
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
	if (offset == start_off)
		return ret;
	return offset - start_off;
}

static int io_zcrx_tcp_recvmsg(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
				struct sock *sk, int flags)
{
	struct io_zcrx_args args = {
		.req = req,
		.ifq = ifq,
		.sock = sk->sk_socket,
	};
	read_descriptor_t rd_desc = {
		.count = 1,
		.arg.data = &args,
	};
	int ret;

	lock_sock(sk);
	ret = tcp_read_sock(sk, &rd_desc, io_zcrx_recv_skb);
	if (ret <= 0) {
		if (ret < 0 || sock_flag(sk, SOCK_DONE))
			goto out;
		if (sk->sk_err)
			ret = sock_error(sk);
		else if (sk->sk_shutdown & RCV_SHUTDOWN)
			goto out;
		else if (sk->sk_state == TCP_CLOSE)
			ret = -ENOTCONN;
		else
			ret = -EAGAIN;
	} else if (sock_flag(sk, SOCK_DONE)) {
		/* Make it to retry until it finally gets 0. */
		ret = -EAGAIN;
	}
out:
	release_sock(sk);
	return ret;
}

int io_zcrx_recv(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
		 struct socket *sock, unsigned int flags)
{
	struct sock *sk = sock->sk;
	const struct proto *prot = READ_ONCE(sk->sk_prot);

	if (prot->recvmsg != tcp_recvmsg)
		return -EPROTONOSUPPORT;

	sock_rps_record_flow(sk);
	return io_zcrx_tcp_recvmsg(req, ifq, sk, flags);
}

#endif
