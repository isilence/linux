// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_ZC_RX_H
#define IOU_ZC_RX_H

#include <linux/io_uring_types.h>
#include <linux/io_uring/net.h>
#include <linux/skbuff.h>

#define IO_ZC_MAX_IFQ_SOCKETS		16
#define IO_ZC_IFQ_IDX_OFFSET		16
#define IO_ZC_IFQ_IDX_MASK		((1U << IO_ZC_IFQ_IDX_OFFSET) - 1)

struct io_zc_rx_pool {
	struct io_zc_rx_ifq	*ifq;
	struct io_zc_rx_buf	*bufs;
	u32			nr_bufs;
	u16			pool_id;

	/* freelist */
	spinlock_t		freelist_lock;
	u32			free_count;
	u32			freelist[];
};

struct io_zc_rx_ifq {
	struct io_ring_ctx		*ctx;
	struct net_device		*dev;
	struct io_zc_rx_pool		*pool;

	struct io_uring			*rq_ring;
	struct io_uring_rbuf_rqe 	*rqes;
	u32				rq_entries;

	unsigned short			n_rqe_pages;
	struct page			**rqe_pages;

	/* hw rx descriptor ring id */
	u32				if_rxq_id;

	unsigned			nr_sockets;
	struct file			*sockets[IO_ZC_MAX_IFQ_SOCKETS];
};

#if defined(CONFIG_PAGE_POOL)
int io_register_zc_rx_ifq(struct io_ring_ctx *ctx,
			  struct io_uring_zc_rx_ifq_reg __user *arg);
void io_unregister_zc_rx_ifqs(struct io_ring_ctx *ctx);
void io_shutdown_zc_rx_ifqs(struct io_ring_ctx *ctx);
int io_register_zc_rx_sock(struct io_ring_ctx *ctx,
			   struct io_uring_zc_rx_sock_reg __user *arg);
#else
static inline int io_register_zc_rx_ifq(struct io_ring_ctx *ctx,
			  struct io_uring_zc_rx_ifq_reg __user *arg)
{
	return -EOPNOTSUPP;
}
static inline void io_unregister_zc_rx_ifqs(struct io_ring_ctx *ctx)
{
}
static inline void io_shutdown_zc_rx_ifqs(struct io_ring_ctx *ctx)
{
}
static inline int io_register_zc_rx_sock(struct io_ring_ctx *ctx,
				struct io_uring_zc_rx_sock_reg __user *arg)
{
	return -EOPNOTSUPP;
}
#endif

#endif
