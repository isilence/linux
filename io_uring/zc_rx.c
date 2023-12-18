// SPDX-License-Identifier: GPL-2.0
#if defined(CONFIG_PAGE_POOL)
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/io_uring.h>
#include <linux/netdevice.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "zc_rx.h"

typedef int (*bpf_op_t)(struct net_device *dev, struct netdev_bpf *bpf);

static int __io_queue_mgmt(struct net_device *dev, struct io_zc_rx_ifq *ifq,
			   u16 queue_id)
{
	struct netdev_bpf cmd;
	bpf_op_t ndo_bpf;

	ndo_bpf = dev->netdev_ops->ndo_bpf;
	if (!ndo_bpf)
		return -EINVAL;

	cmd.command = XDP_SETUP_ZC_RX;
	cmd.zc_rx.ifq = ifq;
	cmd.zc_rx.queue_id = queue_id;
	return ndo_bpf(dev, &cmd);
}

static int io_open_zc_rxq(struct io_zc_rx_ifq *ifq)
{
	return __io_queue_mgmt(ifq->dev, ifq, ifq->if_rxq_id);
}

static int io_close_zc_rxq(struct io_zc_rx_ifq *ifq)
{
	return __io_queue_mgmt(ifq->dev, NULL, ifq->if_rxq_id);
}

static int io_allocate_rbuf_ring(struct io_zc_rx_ifq *ifq,
				 struct io_uring_zc_rx_ifq_reg *reg)
{
	gfp_t gfp = GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN | __GFP_COMP;
	size_t off, size, rq_size, cq_size;
	void *ptr;

	off = sizeof(struct io_rbuf_ring);
	rq_size = reg->rq_entries * sizeof(struct io_uring_rbuf_rqe);
	cq_size = reg->cq_entries * sizeof(struct io_uring_rbuf_cqe);
	size = off + rq_size + cq_size;
	ptr = (void *) __get_free_pages(gfp, get_order(size));
	if (!ptr)
		return -ENOMEM;
	ifq->ring = (struct io_rbuf_ring *)ptr;
	ifq->rqes = (struct io_uring_rbuf_rqe *)((char *)ptr + off);
	ifq->cqes = (struct io_uring_rbuf_cqe *)((char *)ifq->rqes + rq_size);
	return 0;
}

static void io_free_rbuf_ring(struct io_zc_rx_ifq *ifq)
{
	if (ifq->ring)
		folio_put(virt_to_folio(ifq->ring));
}

static struct io_zc_rx_ifq *io_zc_rx_ifq_alloc(struct io_ring_ctx *ctx)
{
	struct io_zc_rx_ifq *ifq;

	ifq = kzalloc(sizeof(*ifq), GFP_KERNEL);
	if (!ifq)
		return NULL;

	ifq->if_rxq_id = -1;
	ifq->ctx = ctx;
	return ifq;
}

static void io_zc_rx_ifq_free(struct io_zc_rx_ifq *ifq)
{
	if (ifq->if_rxq_id != -1)
		io_close_zc_rxq(ifq);
	if (ifq->dev)
		dev_put(ifq->dev);
	io_free_rbuf_ring(ifq);
	kfree(ifq);
}

int io_register_zc_rx_ifq(struct io_ring_ctx *ctx,
			  struct io_uring_zc_rx_ifq_reg __user *arg)
{
	struct io_uring_zc_rx_ifq_reg reg;
	struct io_zc_rx_ifq *ifq;
	size_t ring_sz, rqes_sz, cqes_sz;
	int ret;

	if (!(ctx->flags & IORING_SETUP_DEFER_TASKRUN))
		return -EINVAL;
	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	if (ctx->ifq)
		return -EBUSY;
	if (reg.if_rxq_id == -1)
		return -EINVAL;

	ifq = io_zc_rx_ifq_alloc(ctx);
	if (!ifq)
		return -ENOMEM;

	ret = io_allocate_rbuf_ring(ifq, &reg);
	if (ret)
		goto err;

	ret = -ENODEV;
	ifq->dev = dev_get_by_index(current->nsproxy->net_ns, reg.if_idx);
	if (!ifq->dev)
		goto err;

	/* TODO: map zc region and initialise zc pool */

	ifq->rq_entries = reg.rq_entries;
	ifq->cq_entries = reg.cq_entries;
	ifq->if_rxq_id = reg.if_rxq_id;

	ret = io_open_zc_rxq(ifq);
	if (ret)
		goto err;

	ring_sz = sizeof(struct io_rbuf_ring);
	rqes_sz = sizeof(struct io_uring_rbuf_rqe) * ifq->rq_entries;
	cqes_sz = sizeof(struct io_uring_rbuf_cqe) * ifq->cq_entries;
	reg.mmap_sz = ring_sz + rqes_sz + cqes_sz;
	reg.rq_off.rqes = ring_sz;
	reg.cq_off.cqes = ring_sz + rqes_sz;
	reg.rq_off.head = offsetof(struct io_rbuf_ring, rq.head);
	reg.rq_off.tail = offsetof(struct io_rbuf_ring, rq.tail);
	reg.cq_off.head = offsetof(struct io_rbuf_ring, cq.head);
	reg.cq_off.tail = offsetof(struct io_rbuf_ring, cq.tail);

	if (copy_to_user(arg, &reg, sizeof(reg))) {
		io_close_zc_rxq(ifq);
		ret = -EFAULT;
		goto err;
	}

	ctx->ifq = ifq;
	return 0;
err:
	io_zc_rx_ifq_free(ifq);
	return ret;
}

void io_unregister_zc_rx_ifqs(struct io_ring_ctx *ctx)
{
	struct io_zc_rx_ifq *ifq = ctx->ifq;

	lockdep_assert_held(&ctx->uring_lock);

	if (!ifq)
		return;

	ctx->ifq = NULL;
	io_zc_rx_ifq_free(ifq);
}

void io_shutdown_zc_rx_ifqs(struct io_ring_ctx *ctx)
{
	lockdep_assert_held(&ctx->uring_lock);
}

#endif
