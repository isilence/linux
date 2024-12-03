// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/dma-map-ops.h>
#include <linux/mm.h>
#include <linux/nospec.h>
#include <linux/io_uring.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff_ref.h>

#include <net/page_pool/helpers.h>
#include <net/page_pool/memory_provider.h>
#include <net/netlink.h>
#include <net/netdev_rx_queue.h>
#include <net/tcp.h>
#include <net/rps.h>

#include <trace/events/page_pool.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "memmap.h"
#include "zcrx.h"
#include "rsrc.h"

#define IO_DMA_ATTR (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)

static struct device *io_zcrx_get_device(struct io_zcrx_ifq *ifq)
{
	return ifq->dev->dev.parent;
}

static void __io_zcrx_unmap_area(struct io_zcrx_ifq *ifq,
				 struct io_zcrx_area *area, int nr_mapped)
{
	int i;

	for (i = 0; i < nr_mapped; i++) {
		struct net_iov *niov = &area->nia.niovs[i];
		dma_addr_t dma;

		dma = page_pool_get_dma_addr_netmem(net_iov_to_netmem(niov));
		if (dma && io_zcrx_get_device(ifq)) {
			dma_unmap_page_attrs(io_zcrx_get_device(ifq), dma, PAGE_SIZE, DMA_FROM_DEVICE,
					     IO_DMA_ATTR);
			page_pool_set_dma_addr_netmem(net_iov_to_netmem(niov), 0);
		}
	}
}

static void io_zcrx_unmap_area(struct io_zcrx_ifq *ifq, struct io_zcrx_area *area)
{
	if (area->is_mapped)
		__io_zcrx_unmap_area(ifq, area, area->nia.num_niovs);
}

static int io_zcrx_map_area(struct io_zcrx_ifq *ifq, struct io_zcrx_area *area)
{
	struct device *dev = io_zcrx_get_device(ifq);
	int i;

	for (i = 0; i < area->nia.num_niovs; i++) {
		struct net_iov *niov = &area->nia.niovs[i];
		dma_addr_t dma = 0;

		if (dev) {
			dma = dma_map_page_attrs(dev, area->pages[i], 0, PAGE_SIZE,
						 DMA_FROM_DEVICE, IO_DMA_ATTR);
			if (dma_mapping_error(dev, dma))
				break;
		}

		if (page_pool_set_dma_addr_netmem(net_iov_to_netmem(niov), dma)) {
			dma_unmap_page_attrs(dev, dma, PAGE_SIZE,
					     DMA_FROM_DEVICE, IO_DMA_ATTR);
			break;
		}
	}

	if (i != area->nia.num_niovs) {
		__io_zcrx_unmap_area(ifq, area, i);
		return -EINVAL;
	}

	area->is_mapped = true;
	return 0;
}

static void io_zcrx_sync_for_device(const struct page_pool *pool,
				    struct net_iov *niov)
{
#if defined(CONFIG_HAS_DMA) && defined(CONFIG_DMA_NEED_SYNC)
	dma_addr_t dma_addr;

	if (!dma_dev_need_sync(pool->p.dev))
		return;

	dma_addr = page_pool_get_dma_addr_netmem(net_iov_to_netmem(niov));
	__dma_sync_single_for_device(pool->p.dev, dma_addr + pool->p.offset,
				     PAGE_SIZE, pool->p.dma_dir);
#endif
}

#define IO_RQ_MAX_ENTRIES		32768

#define IO_SKBS_PER_CALL_LIMIT	20

struct io_zcrx_args {
	struct io_kiocb		*req;
	struct io_zcrx_ifq	*ifq;
	struct socket		*sock;
	unsigned		nr_skbs;
};

static const struct memory_provider_ops io_uring_pp_zc_ops;

static inline struct io_zcrx_area *io_zcrx_iov_to_area(const struct net_iov *niov)
{
	struct net_iov_area *owner = net_iov_owner(niov);

	return container_of(owner, struct io_zcrx_area, nia);
}

static inline atomic_t *io_get_user_counter(struct net_iov *niov)
{
	struct io_zcrx_area *area = io_zcrx_iov_to_area(niov);

	return &area->user_refs[net_iov_idx(niov)];
}

static bool io_zcrx_put_niov_uref(struct net_iov *niov)
{
	atomic_t *uref = io_get_user_counter(niov);

	if (unlikely(!atomic_read(uref)))
		return false;
	atomic_dec(uref);
	return true;
}

static void io_zcrx_get_niov_uref(struct net_iov *niov)
{
	atomic_inc(io_get_user_counter(niov));
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
	if (ret)
		goto fail;

	return 0;
fail:
	rxq->mp_params.mp_ops = NULL;
	rxq->mp_params.mp_priv = NULL;
	ifq->if_rxq = -1;
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
				 struct io_uring_zcrx_ifq_reg *reg,
				 struct io_uring_region_desc *rd)
{
	size_t off, size;
	void *ptr;
	int ret;

	off = sizeof(struct io_uring);
	size = off + sizeof(struct io_uring_zcrx_rqe) * reg->rq_entries;
	if (size > rd->size)
		return -EINVAL;

	ret = io_create_region_mmap_safe(ifq->ctx, &ifq->ctx->zcrx_region, rd,
					 IORING_MAP_OFF_ZCRX_REGION);
	if (ret < 0)
		return ret;

	ptr = io_region_get_ptr(&ifq->ctx->zcrx_region);
	ifq->rq_ring = (struct io_uring *)ptr;
	ifq->rqes = (struct io_uring_zcrx_rqe *)(ptr + off);
	return 0;
}

static void io_free_rbuf_ring(struct io_zcrx_ifq *ifq)
{
	io_free_region(ifq->ctx, &ifq->ctx->zcrx_region);
	ifq->rq_ring = NULL;
	ifq->rqes = NULL;
}

static void io_zcrx_free_area(struct io_zcrx_area *area)
{
	io_zcrx_unmap_area(area->ifq, area);

	kvfree(area->freelist);
	kvfree(area->nia.niovs);
	kvfree(area->user_refs);
	if (area->pages) {
		unpin_user_pages(area->pages, area->nia.num_niovs);
		kvfree(area->pages);
	}
	kfree(area);
}

static int io_zcrx_create_area(struct io_zcrx_ifq *ifq,
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

	for (i = 0; i < nr_pages; i++)
		area->freelist[i] = i;

	area->user_refs = kvmalloc_array(nr_pages, sizeof(area->user_refs[0]),
					GFP_KERNEL | __GFP_ZERO);
	if (!area->user_refs)
		goto err;

	for (i = 0; i < nr_pages; i++) {
		struct net_iov *niov = &area->nia.niovs[i];

		niov->owner = &area->nia;
		area->freelist[i] = i;
		atomic_set(&area->user_refs[i], 0);
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
	spin_lock_init(&ifq->rq_lock);
	return ifq;
}

static void io_zcrx_ifq_free(struct io_zcrx_ifq *ifq)
{
	io_close_zc_rxq(ifq);

	if (ifq->area)
		io_zcrx_free_area(ifq->area);

	if (ifq->dev)
		netdev_put(ifq->dev, &ifq->netdev_tracker);
	io_free_rbuf_ring(ifq);
	kfree(ifq);
}

int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
			  struct io_uring_zcrx_ifq_reg __user *arg)
{
	struct io_uring_zcrx_area_reg area;
	struct io_uring_zcrx_ifq_reg reg;
	struct io_uring_region_desc rd;
	struct io_zcrx_ifq *ifq;
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
	if (copy_from_user(&rd, u64_to_user_ptr(reg.region_ptr), sizeof(rd)))
		return -EFAULT;
	if (memchr_inv(&reg.__resv, 0, sizeof(reg.__resv)))
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

	ret = io_allocate_rbuf_ring(ifq, &reg, &rd);
	if (ret)
		goto err;

	ret = io_zcrx_create_area(ifq, &ifq->area, &area);
	if (ret)
		goto err;

	ifq->rq_entries = reg.rq_entries;

	ret = -ENODEV;
	ifq->dev = netdev_get_by_index(current->nsproxy->net_ns, reg.if_idx,
					&ifq->netdev_tracker, GFP_KERNEL);
	if (!ifq->dev)
		goto err;

	ret = io_zcrx_map_area(ifq, ifq->area);
	if (ret)
		goto err;

	rtnl_lock();
	ret = io_open_zc_rxq(ifq, reg.if_rxq);
	rtnl_unlock();
	if (ret)
		goto err;

	reg.offsets.rqes = sizeof(struct io_uring);
	reg.offsets.head = offsetof(struct io_uring, head);
	reg.offsets.tail = offsetof(struct io_uring, tail);

	if (copy_to_user(arg, &reg, sizeof(reg)) ||
	    copy_to_user(u64_to_user_ptr(reg.region_ptr), &rd, sizeof(rd)) ||
	    copy_to_user(u64_to_user_ptr(reg.area_ptr), &area, sizeof(area))) {
		io_close_zc_rxq(ifq);
		ret = -EFAULT;
		goto err;
	}
	ctx->ifq = ifq;
	return 0;
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

static struct net_iov *__io_zcrx_get_free_niov(struct io_zcrx_area *area)
{
	unsigned niov_idx;

	lockdep_assert_held(&area->freelist_lock);

	niov_idx = area->freelist[--area->free_count];
	return &area->nia.niovs[niov_idx];
}

static void io_zcrx_return_niov_freelist(struct net_iov *niov)
{
	struct io_zcrx_area *area = io_zcrx_iov_to_area(niov);

	spin_lock_bh(&area->freelist_lock);
	area->freelist[area->free_count++] = net_iov_idx(niov);
	spin_unlock_bh(&area->freelist_lock);
}

static void io_zcrx_return_niov(struct net_iov *niov)
{
	netmem_ref netmem = net_iov_to_netmem(niov);

	if (!niov->pp) {
		/* copy fallback allocated niovs */
		io_zcrx_return_niov_freelist(niov);
		return;
	}
	page_pool_put_unrefed_netmem(niov->pp, netmem, -1, false);
}

static void io_zcrx_scrub(struct io_zcrx_ifq *ifq)
{
	struct io_zcrx_area *area = ifq->area;
	int i;

	if (!area)
		return;

	/* Reclaim back all buffers given to the user space. */
	for (i = 0; i < area->nia.num_niovs; i++) {
		struct net_iov *niov = &area->nia.niovs[i];
		int nr;

		if (!atomic_read(io_get_user_counter(niov)))
			continue;
		nr = atomic_xchg(io_get_user_counter(niov), 0);
		if (nr && !page_pool_unref_netmem(net_iov_to_netmem(niov), nr))
			io_zcrx_return_niov(niov);
	}
}

void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx)
{
	lockdep_assert_held(&ctx->uring_lock);

	if (ctx->ifq)
		io_zcrx_scrub(ctx->ifq);

	io_close_zc_rxq(ctx->ifq);
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
	unsigned int mask = ifq->rq_entries - 1;
	unsigned int entries;
	netmem_ref netmem;

	spin_lock_bh(&ifq->rq_lock);

	entries = io_zcrx_rqring_entries(ifq);
	entries = min_t(unsigned, entries, PP_ALLOC_CACHE_REFILL - pp->alloc.count);
	if (unlikely(!entries)) {
		spin_unlock_bh(&ifq->rq_lock);
		return;
	}

	do {
		struct io_uring_zcrx_rqe *rqe = io_zcrx_get_rqe(ifq, mask);
		struct io_zcrx_area *area;
		struct net_iov *niov;
		unsigned niov_idx, area_idx;

		area_idx = rqe->off >> IORING_ZCRX_AREA_SHIFT;
		niov_idx = (rqe->off & ~IORING_ZCRX_AREA_MASK) >> PAGE_SHIFT;

		if (unlikely(rqe->__pad || area_idx))
			continue;
		area = ifq->area;

		if (unlikely(niov_idx >= area->nia.num_niovs))
			continue;
		niov_idx = array_index_nospec(niov_idx, area->nia.num_niovs);

		niov = &area->nia.niovs[niov_idx];
		if (!io_zcrx_put_niov_uref(niov))
			continue;

		netmem = net_iov_to_netmem(niov);
		if (page_pool_unref_netmem(netmem, 1) != 0)
			continue;

		if (unlikely(niov->pp != pp)) {
			io_zcrx_return_niov(niov);
			continue;
		}

		io_zcrx_sync_for_device(pp, niov);
		net_mp_netmem_place_in_cache(pp, netmem);
	} while (--entries);

	smp_store_release(&ifq->rq_ring->head, ifq->cached_rq_head);
	spin_unlock_bh(&ifq->rq_lock);
}

static void io_zcrx_refill_slow(struct page_pool *pp, struct io_zcrx_ifq *ifq)
{
	struct io_zcrx_area *area = ifq->area;

	spin_lock_bh(&area->freelist_lock);
	while (area->free_count && pp->alloc.count < PP_ALLOC_CACHE_REFILL) {
		struct net_iov *niov = __io_zcrx_get_free_niov(area);
		netmem_ref netmem = net_iov_to_netmem(niov);

		net_mp_niov_set_page_pool(pp, niov);
		io_zcrx_sync_for_device(pp, niov);
		net_mp_netmem_place_in_cache(pp, netmem);
	}
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
	if (WARN_ON_ONCE(!netmem_is_net_iov(netmem)))
		return false;

	if (page_pool_unref_netmem(netmem, 1) == 0) {
		struct net_iov *niov = netmem_to_net_iov(netmem);

		net_mp_niov_clear_page_pool(niov);
		io_zcrx_return_niov_freelist(niov);
	}
	return false;
}

static int io_pp_zc_init(struct page_pool *pp)
{
	struct io_zcrx_ifq *ifq = pp->mp_priv;

	if (WARN_ON_ONCE(!ifq))
		return -EINVAL;
	if (WARN_ON_ONCE(ifq->dev != pp->slow.netdev))
		return -EINVAL;
	if (io_zcrx_get_device(ifq)) {
		if (WARN_ON_ONCE(io_zcrx_get_device(ifq) != pp->p.dev))
			return -EINVAL;
	}
	// if (WARN_ON_ONCE(!pp->dma_map))
	// 	return -EOPNOTSUPP;
	if (pp->p.order != 0)
		return -EOPNOTSUPP;
	// if (pp->p.dma_dir != DMA_FROM_DEVICE)
	// 	return -EOPNOTSUPP;

	percpu_ref_get(&ifq->ctx->refs);
	return 0;
}

static void io_pp_zc_destroy(struct page_pool *pp)
{
	struct io_zcrx_ifq *ifq = pp->mp_priv;
	struct io_zcrx_area *area = ifq->area;

	if (WARN_ON_ONCE(area->free_count != area->nia.num_niovs))
		return;
	percpu_ref_put(&ifq->ctx->refs);
}

static int io_pp_nl_report(const struct page_pool *pool, struct sk_buff *rsp)
{
	return nla_put_u32(rsp, NETDEV_A_PAGE_POOL_IO_URING, 0);
}

static const struct memory_provider_ops io_uring_pp_zc_ops = {
	.alloc_netmems		= io_pp_zc_alloc_netmems,
	.release_netmem		= io_pp_zc_release_netmem,
	.init			= io_pp_zc_init,
	.destroy		= io_pp_zc_destroy,
	.nl_report		= io_pp_nl_report,
};

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
	rcqe->__pad = 0;
	return true;
}

static struct net_iov *io_zcrx_alloc_fallback(struct io_zcrx_area *area)
{
	struct net_iov *niov = NULL;

	spin_lock_bh(&area->freelist_lock);
	if (area->free_count)
		niov = __io_zcrx_get_free_niov(area);
	spin_unlock_bh(&area->freelist_lock);

	if (niov)
		page_pool_fragment_netmem(net_iov_to_netmem(niov), 1);
	return niov;
}

static ssize_t io_zcrx_copy_chunk(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
				  void *src_base, struct page *src_page,
				  unsigned int src_offset, size_t len)
{
	struct io_zcrx_area *area = ifq->area;
	size_t copied = 0;
	int ret = 0;

	while (len) {
		size_t copy_size = min_t(size_t, PAGE_SIZE, len);
		const int dst_off = 0;
		struct net_iov *niov;
		struct page *dst_page;
		void *dst_addr;

		niov = io_zcrx_alloc_fallback(area);
		if (!niov) {
			ret = -ENOMEM;
			break;
		}

		dst_page = io_zcrx_iov_page(niov);
		dst_addr = kmap_local_page(dst_page);
		if (src_page)
			src_base = kmap_local_page(src_page);

		memcpy(dst_addr, src_base + src_offset, copy_size);

		if (src_page)
			kunmap_local(src_base);
		kunmap_local(dst_addr);

		if (!io_zcrx_queue_cqe(req, niov, ifq, dst_off, copy_size)) {
			io_zcrx_return_niov(niov);
			ret = -ENOSPC;
			break;
		}

		io_zcrx_get_niov_uref(niov);
		src_offset += copy_size;
		len -= copy_size;
		copied += copy_size;
	}

	return copied ? copied : ret;
}

static int io_zcrx_copy_frag(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
			     const skb_frag_t *frag, int off, int len,
			     bool steal_ref)
{
	struct page *page = skb_frag_page(frag);
	u32 p_off, p_len, t, copied = 0;
	int ret = 0;

	off += skb_frag_off(frag);

	skb_frag_foreach_page(frag, off, len,
			      page, p_off, p_len, t) {
		ret = io_zcrx_copy_chunk(req, ifq, NULL, page, p_off, p_len);
		if (ret < 0)
			return copied ? copied : ret;
		copied += ret;
	}

	if (steal_ref)
		napi_pp_put_page(frag->netmem);
	return copied;
}

static int io_zcrx_recv_frag(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
			     const skb_frag_t *frag, int off, int len,
			     bool steal_ref)
{
	struct net_iov *niov;

	if (unlikely(!skb_frag_is_net_iov(frag)))
		return io_zcrx_copy_frag(req, ifq, frag, off, len, steal_ref);

	niov = netmem_to_net_iov(frag->netmem);
	if (niov->pp->mp_ops != &io_uring_pp_zc_ops ||
	    niov->pp->mp_priv != ifq)
		return -EFAULT;

	if (!io_zcrx_queue_cqe(req, niov, ifq, off + skb_frag_off(frag), len))
		return -ENOSPC;

	/*
	 * Prevent it from being recycled while user is accessing it.
	 * It has to be done before grabbing a user reference.
	 */
	if (!steal_ref)
		page_pool_ref_netmem(net_iov_to_netmem(niov));
	io_zcrx_get_niov_uref(niov);
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
	bool steal_frags;
	int i, copy, end, off;
	int ret = 0;

	if (unlikely(args->nr_skbs++ > IO_SKBS_PER_CALL_LIMIT))
		return -EAGAIN;

	if (unlikely(offset < skb_headlen(skb))) {
		ssize_t copied;
		size_t to_copy;

		to_copy = min_t(size_t, skb_headlen(skb) - offset, len);
		copied = io_zcrx_copy_chunk(req, ifq, skb->data, NULL,
					    offset, to_copy);
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
	steal_frags = !skb->cloned && len >= skb->len;

	for (i = 0; len && i < skb_shinfo(skb)->nr_frags; i++) {
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
			ret = io_zcrx_recv_frag(req, ifq, frag, off, copy,
						steal_frags);
			if (ret < 0)
				break;

			offset += ret;
			len -= ret;
			if (ret != copy) {
				ret = -1;
				break;
			}
		}
		start = end;
	}

	if (steal_frags) {
		struct skb_shared_info *shi = skb_shinfo(skb);
		unsigned left = shi->nr_frags - i;

		if (left)
			memmove(&shi->frags[0], &shi->frags[i],
				(shi->nr_frags - i) * sizeof(shi->frags[0]));
		shi->nr_frags = left;
	}

	if (ret < 0)
		goto out;

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
				struct sock *sk, int flags,
				unsigned issue_flags)
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
	} else if (unlikely(args.nr_skbs > IO_SKBS_PER_CALL_LIMIT) &&
		   (issue_flags & IO_URING_F_MULTISHOT)) {
		ret = IOU_REQUEUE;
	} else if (sock_flag(sk, SOCK_DONE)) {
		/* Make it to retry until it finally gets 0. */
		if (issue_flags & IO_URING_F_MULTISHOT)
			ret = IOU_REQUEUE;
		else
			ret = -EAGAIN;
	}
out:
	release_sock(sk);
	return ret;
}

int io_zcrx_recv(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
		 struct socket *sock, unsigned int flags,
		 unsigned issue_flags)
{
	struct sock *sk = sock->sk;
	const struct proto *prot = READ_ONCE(sk->sk_prot);

	if (prot->recvmsg != tcp_recvmsg)
		return -EPROTONOSUPPORT;

	sock_rps_record_flow(sk);
	return io_zcrx_tcp_recvmsg(req, ifq, sk, flags, issue_flags);
}

#include <linux/io_uring/net.h>

struct page *io_iov_get_page(netmem_ref netmem)
{
	struct net_iov *niov;

	if (WARN_ON_ONCE(!netmem_is_net_iov(netmem)))
		return NULL;
	niov = netmem_to_net_iov(netmem);

	if (WARN_ON_ONCE(niov->pp->mp_ops != &io_uring_pp_zc_ops))
		return  NULL;
	return io_zcrx_iov_page(niov);
}
EXPORT_SYMBOL_GPL(io_iov_get_page);
