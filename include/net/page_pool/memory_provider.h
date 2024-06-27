#ifndef _NET_PAGE_POOL_MEMORY_PROVIDER_H
#define _NET_PAGE_POOL_MEMORY_PROVIDER_H

int page_pool_mp_init_paged_area(struct page_pool *pool,
				struct net_iov_area *area,
				struct page **pages);
void page_pool_mp_release_area(struct page_pool *pool,
				struct net_iov_area *area);

#endif
