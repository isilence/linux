// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_ZC_RX_H
#define IOU_ZC_RX_H

#include <linux/io_uring_types.h>
#include <linux/skbuff.h>

#define IO_ZC_MAX_IFQ_SOCKETS		16
#define IO_ZC_IFQ_IDX_OFFSET		16
#define IO_ZC_IFQ_IDX_MASK		((1U << IO_ZC_IFQ_IDX_OFFSET) - 1)

struct io_zcrx_ifq {
	struct io_ring_ctx		*ctx;
	struct net_device		*dev;
	struct io_uring			*rq_ring;
	struct io_uring_zcrx_rqe 	*rqes;
	u32				rq_entries;

	unsigned short			n_rqe_pages;
	struct page			**rqe_pages;

	u32				if_rxq;

	unsigned			nr_sockets;
	struct file			*sockets[IO_ZC_MAX_IFQ_SOCKETS];
};

#if defined(CONFIG_PAGE_POOL)
int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
			 struct io_uring_zcrx_ifq_reg __user *arg);
void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx);
void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx);
int io_register_zcrx_sock(struct io_ring_ctx *ctx,
			  struct io_uring_zcrx_sock_reg __user *arg);
#else
static inline int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
					struct io_uring_zcrx_ifq_reg __user *arg)
{
	return -EOPNOTSUPP;
}
static inline void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx)
{
}
static inline void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx)
{
}
static inline int io_register_zcrx_sock(struct io_ring_ctx *ctx,
					struct io_uring_zcrx_sock_reg __user *arg)
{
	return -EOPNOTSUPP;
}
#endif

#endif
