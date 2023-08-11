/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_IO_URING_NET_H
#define _LINUX_IO_URING_NET_H

#include <net/page_pool/types.h>

struct io_uring_cmd;

struct io_zc_rx_buf {
	struct net_iov		niov;
	struct page		*page;
};

#if defined(CONFIG_IO_URING)
int io_uring_cmd_sock(struct io_uring_cmd *cmd, unsigned int issue_flags);

#else
static inline int io_uring_cmd_sock(struct io_uring_cmd *cmd,
				    unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}
#endif

#endif
