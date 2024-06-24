// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *      Devmem TCP
 *
 *      Authors:	Mina Almasry <almasrymina@google.com>
 *			Willem de Bruijn <willemdebruijn.kernel@gmail.com>
 *			Kaiyuan Zhang <kaiyuanz@google.com
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/netdevice.h>
#include <trace/events/page_pool.h>
#include <net/netdev_rx_queue.h>
#include <net/page_pool/types.h>
#include <net/page_pool/helpers.h>
#include <linux/genalloc.h>
#include <linux/dma-buf.h>
#include <net/devmem.h>
#include <net/mp_dmabuf_devmem.h>
#include <net/netdev_queues.h>

/* Device memory support */

#if defined(CONFIG_DMA_SHARED_BUFFER) && defined(CONFIG_GENERIC_ALLOCATOR)

static void net_devmem_dmabuf_free_chunk_owner(struct gen_pool *genpool,
					       struct gen_pool_chunk *chunk,
					       void *not_used)
{
	struct dmabuf_genpool_chunk_owner *owner = chunk->owner;

	kvfree(owner->area.niovs);
	kfree(owner);
}

static dma_addr_t net_devmem_get_dma_addr(const struct net_iov *niov)
{
	struct dmabuf_genpool_chunk_owner *owner;

	owner = net_devmem_iov_to_chunk_owner(niov);
	return owner->base_dma_addr +
	       ((dma_addr_t)net_iov_idx(niov) << PAGE_SHIFT);
}

void __net_devmem_dmabuf_binding_free(struct net_devmem_dmabuf_binding *binding)
{
	size_t size, avail;

	gen_pool_for_each_chunk(binding->chunk_pool,
				net_devmem_dmabuf_free_chunk_owner, NULL);

	size = gen_pool_size(binding->chunk_pool);
	avail = gen_pool_avail(binding->chunk_pool);

	if (!WARN(size != avail, "can't destroy genpool. size=%zu, avail=%zu",
		  size, avail))
		gen_pool_destroy(binding->chunk_pool);

	dma_buf_unmap_attachment(binding->attachment, binding->sgt,
				 DMA_FROM_DEVICE);
	dma_buf_detach(binding->dmabuf, binding->attachment);
	dma_buf_put(binding->dmabuf);
	xa_destroy(&binding->bound_rxq_list);
	kfree(binding);
}

struct net_iov *
net_devmem_alloc_dmabuf(struct net_devmem_dmabuf_binding *binding)
{
	struct dmabuf_genpool_chunk_owner *owner;
	unsigned long dma_addr;
	struct net_iov *niov;
	ssize_t offset;
	ssize_t index;

	dma_addr = gen_pool_alloc_owner(binding->chunk_pool, PAGE_SIZE,
					(void **)&owner);
	if (!dma_addr)
		return NULL;

	offset = dma_addr - owner->base_dma_addr;
	index = offset / PAGE_SIZE;
	niov = &owner->area.niovs[index];

	niov->pp_magic = 0;
	niov->pp = NULL;
	niov->dma_addr = 0;
	atomic_long_set(&niov->pp_ref_count, 0);

	net_devmem_dmabuf_binding_get(binding);

	return niov;
}

void net_devmem_free_dmabuf(struct net_iov *niov)
{
	struct net_devmem_dmabuf_binding *binding = net_devmem_iov_binding(niov);
	unsigned long dma_addr = net_devmem_get_dma_addr(niov);

	if (gen_pool_has_addr(binding->chunk_pool, dma_addr, PAGE_SIZE))
		gen_pool_free(binding->chunk_pool, dma_addr, PAGE_SIZE);

	net_devmem_dmabuf_binding_put(binding);
}

/* Protected by rtnl_lock() */
static DEFINE_XARRAY_FLAGS(net_devmem_dmabuf_bindings, XA_FLAGS_ALLOC1);

void net_devmem_unbind_dmabuf(struct net_devmem_dmabuf_binding *binding)
{
	struct netdev_rx_queue *rxq;
	unsigned long xa_idx;
	unsigned int rxq_idx;

	if (!binding)
		return;

	if (binding->list.next)
		list_del(&binding->list);

	xa_for_each(&binding->bound_rxq_list, xa_idx, rxq) {
		if (rxq->mp_params.mp_priv == binding) {
			/* We hold the rtnl_lock while binding/unbinding
			 * dma-buf, so we can't race with another thread that
			 * is also modifying this value. However, the page_pool
			 * may read this config while it's creating its
			 * rx-queues. WRITE_ONCE() here to match the
			 * READ_ONCE() in the page_pool.
			 */
			WRITE_ONCE(rxq->mp_params.mp_priv, NULL);
			WRITE_ONCE(rxq->mp_params.mp_ops, NULL);

			rxq_idx = get_netdev_rx_queue_index(rxq);

			netdev_rx_queue_restart(binding->dev, rxq_idx);
		}
	}

	xa_erase(&net_devmem_dmabuf_bindings, binding->id);

	net_devmem_dmabuf_binding_put(binding);
}

int net_devmem_bind_dmabuf_to_queue(struct net_device *dev, u32 rxq_idx,
				    struct net_devmem_dmabuf_binding *binding)
{
	struct netdev_rx_queue *rxq;
	u32 xa_idx;
	int err;

	if (rxq_idx >= dev->num_rx_queues)
		return -ERANGE;

	rxq = __netif_get_rx_queue(dev, rxq_idx);
	if (rxq->mp_params.mp_priv)
		return -EEXIST;

	err = xa_alloc(&binding->bound_rxq_list, &xa_idx, rxq, xa_limit_32b,
		       GFP_KERNEL);
	if (err)
		return err;

	/* We hold the rtnl_lock while binding/unbinding dma-buf, so we can't
	 * race with another thread that is also modifying this value. However,
	 * the driver may read this config while it's creating its * rx-queues.
	 * WRITE_ONCE() here to match the READ_ONCE() in the driver.
	 */
	WRITE_ONCE(rxq->mp_params.mp_priv, binding);
	WRITE_ONCE(rxq->mp_params.mp_ops, &dmabuf_devmem_ops);

	err = netdev_rx_queue_restart(dev, rxq_idx);
	if (err)
		goto err_xa_erase;

	return 0;

err_xa_erase:
	WRITE_ONCE(rxq->mp_params.mp_priv, NULL);
	WRITE_ONCE(rxq->mp_params.mp_ops, NULL);
	xa_erase(&binding->bound_rxq_list, xa_idx);

	return err;
}

int net_devmem_bind_dmabuf(struct net_device *dev, unsigned int dmabuf_fd,
			   struct net_devmem_dmabuf_binding **out)
{
	struct net_devmem_dmabuf_binding *binding;
	static u32 id_alloc_next;
	struct scatterlist *sg;
	struct dma_buf *dmabuf;
	unsigned int sg_idx, i;
	unsigned long virtual;
	int err;

	dmabuf = dma_buf_get(dmabuf_fd);
	if (IS_ERR(dmabuf))
		return -EBADFD;

	binding = kzalloc_node(sizeof(*binding), GFP_KERNEL,
			       dev_to_node(&dev->dev));
	if (!binding) {
		err = -ENOMEM;
		goto err_put_dmabuf;
	}

	binding->dev = dev;

	err = xa_alloc_cyclic(&net_devmem_dmabuf_bindings, &binding->id,
			      binding, xa_limit_32b, &id_alloc_next,
			      GFP_KERNEL);
	if (err < 0)
		goto err_free_binding;

	xa_init_flags(&binding->bound_rxq_list, XA_FLAGS_ALLOC);

	refcount_set(&binding->ref, 1);

	binding->dmabuf = dmabuf;

	binding->attachment = dma_buf_attach(binding->dmabuf, dev->dev.parent);
	if (IS_ERR(binding->attachment)) {
		err = PTR_ERR(binding->attachment);
		goto err_free_id;
	}

	binding->sgt =
		dma_buf_map_attachment(binding->attachment, DMA_BIDIRECTIONAL);
	if (IS_ERR(binding->sgt)) {
		err = PTR_ERR(binding->sgt);
		goto err_detach;
	}

	/* For simplicity we expect to make PAGE_SIZE allocations, but the
	 * binding can be much more flexible than that. We may be able to
	 * allocate MTU sized chunks here. Leave that for future work...
	 */
	binding->chunk_pool =
		gen_pool_create(PAGE_SHIFT, dev_to_node(&dev->dev));
	if (!binding->chunk_pool) {
		err = -ENOMEM;
		goto err_unmap;
	}

	virtual = 0;
	for_each_sgtable_dma_sg(binding->sgt, sg, sg_idx) {
		dma_addr_t dma_addr = sg_dma_address(sg);
		struct dmabuf_genpool_chunk_owner *owner;
		size_t len = sg_dma_len(sg);
		struct net_iov *niov;

		owner = kzalloc_node(sizeof(*owner), GFP_KERNEL,
				     dev_to_node(&dev->dev));
		owner->area.base_virtual = virtual;
		owner->base_dma_addr = dma_addr;
		owner->area.num_niovs = len / PAGE_SIZE;
		owner->binding = binding;

		err = gen_pool_add_owner(binding->chunk_pool, dma_addr,
					 dma_addr, len, dev_to_node(&dev->dev),
					 owner);
		if (err) {
			err = -EINVAL;
			goto err_free_chunks;
		}

		owner->area.niovs = kvmalloc_array(owner->area.num_niovs,
						   sizeof(*owner->area.niovs),
						   GFP_KERNEL);
		if (!owner->area.niovs) {
			err = -ENOMEM;
			goto err_free_chunks;
		}

		for (i = 0; i < owner->area.num_niovs; i++) {
			niov = &owner->area.niovs[i];
			niov->owner = &owner->area;
		}

		virtual += len;
	}

	*out = binding;

	return 0;

err_free_chunks:
	gen_pool_for_each_chunk(binding->chunk_pool,
				net_devmem_dmabuf_free_chunk_owner, NULL);
	gen_pool_destroy(binding->chunk_pool);
err_unmap:
	dma_buf_unmap_attachment(binding->attachment, binding->sgt,
				 DMA_BIDIRECTIONAL);
err_detach:
	dma_buf_detach(dmabuf, binding->attachment);
err_free_id:
	xa_erase(&net_devmem_dmabuf_bindings, binding->id);
err_free_binding:
	kfree(binding);
err_put_dmabuf:
	dma_buf_put(dmabuf);
	return err;
}

/*** "Dmabuf devmem memory provider" ***/

int mp_dmabuf_devmem_init(struct page_pool *pool)
{
	struct net_devmem_dmabuf_binding *binding = pool->mp_priv;

	if (!binding)
		return -EINVAL;

	if (!pool->dma_map)
		return -EOPNOTSUPP;

	if (pool->dma_sync)
		return -EOPNOTSUPP;

	if (pool->p.order != 0)
		return -E2BIG;

	net_devmem_dmabuf_binding_get(binding);
	return 0;
}

netmem_ref mp_dmabuf_devmem_alloc_netmems(struct page_pool *pool, gfp_t gfp)
{
	struct net_devmem_dmabuf_binding *binding = pool->mp_priv;
	netmem_ref netmem;
	struct net_iov *niov;
	dma_addr_t dma_addr;

	niov = net_devmem_alloc_dmabuf(binding);
	if (!niov)
		return 0;

	dma_addr = net_devmem_get_dma_addr(niov);

	netmem = net_iov_to_netmem(niov);

	page_pool_set_pp_info(pool, netmem);

	if (page_pool_set_dma_addr_netmem(netmem, dma_addr))
		goto err_free;

	pool->pages_state_hold_cnt++;
	trace_page_pool_state_hold(pool, netmem, pool->pages_state_hold_cnt);
	return netmem;

err_free:
	net_devmem_free_dmabuf(niov);
	return 0;
}

void mp_dmabuf_devmem_destroy(struct page_pool *pool)
{
	struct net_devmem_dmabuf_binding *binding = pool->mp_priv;

	net_devmem_dmabuf_binding_put(binding);
}

bool mp_dmabuf_devmem_release_page(struct page_pool *pool, netmem_ref netmem)
{
	WARN_ON_ONCE(!netmem_is_net_iov(netmem));
	WARN_ON_ONCE(atomic_long_read(netmem_get_pp_ref_count_ref(netmem)) !=
		     1);

	page_pool_clear_pp_info(netmem);

	net_devmem_free_dmabuf(netmem_to_net_iov(netmem));

	/* We don't want the page pool put_page()ing our net_iovs. */
	return false;
}

const struct memory_provider_ops dmabuf_devmem_ops = {
	.init			= mp_dmabuf_devmem_init,
	.destroy		= mp_dmabuf_devmem_destroy,
	.get_buffers		= mp_dmabuf_devmem_alloc_netmems,
	.put_buffer		= mp_dmabuf_devmem_release_page,
};
EXPORT_SYMBOL(dmabuf_devmem_ops);

#endif
