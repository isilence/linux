/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_IO_URING_NET_H
#define _LINUX_IO_URING_NET_H

#include <net/netmem.h>

struct io_uring_cmd;

#if defined(CONFIG_IO_URING)
int io_uring_cmd_sock(struct io_uring_cmd *cmd, unsigned int issue_flags);

#else
static inline int io_uring_cmd_sock(struct io_uring_cmd *cmd,
				    unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}
#endif

#if defined(CONFIG_IO_URING_ZCRX)
void zcrx_ref_niov(struct net_iov *niov);
#else
static inline void zcrx_ref_niov(struct net_iov *niov)
{
}
#endif

#endif
