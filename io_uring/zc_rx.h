// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_ZC_RX_H
#define IOU_ZC_RX_H

struct io_zc_rx_ifq {
	struct io_ring_ctx		*ctx;
	struct net_device		*dev;
	struct io_uring			*rq_ring;
	struct io_uring_rbuf_rqe 	*rqes;
	u32				rq_entries;

	unsigned short			n_rqe_pages;
	struct page			**rqe_pages;

	/* hw rx descriptor ring id */
	u32				if_rxq_id;
};

#if defined(CONFIG_PAGE_POOL)
int io_register_zc_rx_ifq(struct io_ring_ctx *ctx,
			  struct io_uring_zc_rx_ifq_reg __user *arg);
void io_unregister_zc_rx_ifqs(struct io_ring_ctx *ctx);
void io_shutdown_zc_rx_ifqs(struct io_ring_ctx *ctx);
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
#endif

#endif
