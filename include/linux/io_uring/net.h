/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_IO_URING_NET_H
#define _LINUX_IO_URING_NET_H

#include <net/page_pool/types.h>

struct io_uring_cmd;

/* not for upstream, do it the dirty way */

#if defined(CONFIG_IO_URING)

#if defined(CONFIG_PAGE_POOL)
extern const struct memory_provider_ops io_uring_pp_zc_ops;

struct page *io_iov_get_page(netmem_ref netmem);
#endif

int io_uring_cmd_sock(struct io_uring_cmd *cmd, unsigned int issue_flags);

#else
static inline int io_uring_cmd_sock(struct io_uring_cmd *cmd,
				    unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}
#endif

#endif
