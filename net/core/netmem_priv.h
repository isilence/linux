/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __NETMEM_PRIV_H
#define __NETMEM_PRIV_H

static inline bool netmem_is_pp(netmem_ref netmem)
{
	if (netmem_is_net_iov(netmem))
		return true;
	return page_pool_page_is_pp(__netmem_to_page(netmem));
}

static inline void netmem_set_pp(netmem_ref netmem, struct page_pool *pool)
{
	__netmem_clear_lsb(netmem)->pp = pool;
}

static inline void netmem_set_dma_addr(netmem_ref netmem,
				       unsigned long dma_addr)
{
	__netmem_clear_lsb(netmem)->dma_addr = dma_addr;
}

static inline unsigned long netmem_get_dma_index(netmem_ref netmem)
{
	unsigned long magic;

	if (WARN_ON_ONCE(netmem_is_net_iov(netmem)))
		return 0;

	magic = __netmem_clear_lsb(netmem)->pp_magic;

	return (magic & PP_DMA_INDEX_MASK) >> PP_DMA_INDEX_SHIFT;
}

static inline void netmem_clear_dma_index(netmem_ref netmem)
{
	if (WARN_ON_ONCE(netmem_is_net_iov(netmem)))
		return;
	__netmem_clear_lsb(netmem)->pp_magic = 0;
}

static inline void netmem_set_dma_index(netmem_ref netmem,
					unsigned long id)
{
	unsigned long magic;

	if (WARN_ON_ONCE(netmem_is_net_iov(netmem)))
		return;

	magic = PP_POISON | (id << PP_DMA_INDEX_SHIFT);
	__netmem_clear_lsb(netmem)->pp_magic = magic;
}
#endif
