/* SPDX-License-Identifier: GPL-2.0
 *
 * page_pool/memory_provider.h
 *	Author:	Pavel Begunkov <asml.silence@gmail.com>
 */
#ifndef _NET_PAGE_POOL_MEMORY_PROVIDER_H
#define _NET_PAGE_POOL_MEMORY_PROVIDER_H

#include <net/netmem.h>
#include <net/page_pool/types.h>

struct sk_buff;

struct memory_provider_ops {
	netmem_ref (*alloc_netmems)(struct page_pool *pool, gfp_t gfp);
	bool (*release_netmem)(struct page_pool *pool, netmem_ref netmem);
	int (*init)(struct page_pool *pool);
	void (*destroy)(struct page_pool *pool);
	int (*nl_report)(const struct page_pool *pool, struct sk_buff *rsp);
};

#endif
