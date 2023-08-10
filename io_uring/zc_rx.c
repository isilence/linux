// SPDX-License-Identifier: GPL-2.0
#if defined(CONFIG_PAGE_POOL)
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "memmap.h"
#include "zc_rx.h"

static int io_allocate_rbuf_ring(struct io_zc_rx_ifq *ifq,
				 struct io_uring_zc_rx_ifq_reg *reg)
{
	size_t off, size;
	void *ptr;

	off = sizeof(struct io_uring);
	size = off + sizeof(struct io_uring_rbuf_rqe) * reg->rq_entries;

	ptr = io_pages_map(&ifq->rqe_pages, &ifq->n_rqe_pages, size);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	ifq->rq_ring = (struct io_uring *)ptr;
	ifq->rqes = (struct io_uring_rbuf_rqe *)((char *)ptr + off);
	return 0;
}

static void io_free_rbuf_ring(struct io_zc_rx_ifq *ifq)
{
	io_pages_unmap(ifq->rq_ring, &ifq->rqe_pages, &ifq->n_rqe_pages, true);
	ifq->rq_ring = NULL;
	ifq->rqes = NULL;
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
	io_free_rbuf_ring(ifq);
	kfree(ifq);
}

int io_register_zc_rx_ifq(struct io_ring_ctx *ctx,
			  struct io_uring_zc_rx_ifq_reg __user *arg)
{
	struct io_uring_zc_rx_ifq_reg reg;
	struct io_zc_rx_ifq *ifq;
	size_t ring_sz, rqes_sz;
	int ret;

	if (!(ctx->flags & IORING_SETUP_DEFER_TASKRUN &&
	      ctx->flags & IORING_SETUP_CQE32))
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

	ifq->rq_entries = reg.rq_entries;
	ifq->if_rxq_id = reg.if_rxq_id;

	ring_sz = sizeof(struct io_uring);
	rqes_sz = sizeof(struct io_uring_rbuf_rqe) * ifq->rq_entries;
	reg.mmap_sz = ring_sz + rqes_sz;
	reg.rq_off.rqes = ring_sz;
	reg.rq_off.head = offsetof(struct io_uring, head);
	reg.rq_off.tail = offsetof(struct io_uring, tail);

	if (copy_to_user(arg, &reg, sizeof(reg))) {
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
