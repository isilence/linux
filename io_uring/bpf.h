// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_BPF_H
#define IOU_BPF_H

#include <linux/io_uring_types.h>
#include <linux/bpf.h>

#include "io_uring.h"

enum {
	IOU_RES_WAIT,
	IOU_RES_STOP,
};

struct io_uring_ops {
	int (*loop)(struct io_ring_ctx *ctx, struct iou_loop_state *ls);

	__u32 ring_fd;
	void *priv;
};

static inline bool io_bpf_attached(struct io_ring_ctx *ctx)
{
	return IS_ENABLED(CONFIG_IO_URING_BPF) && ctx->bpf_ops != NULL;
}

static inline bool io_has_cqwait_ops(struct io_ring_ctx *ctx)
{
	return io_bpf_attached(ctx);
}


#ifdef CONFIG_IO_URING_BPF
void io_unregister_bpf(struct io_ring_ctx *ctx);
int io_run_cqwait_ops(struct io_ring_ctx *ctx, struct iou_loop_state *ls);
#else
static inline void io_unregister_bpf(struct io_ring_ctx *ctx)
{
}
static inline int io_run_cqwait_ops(struct io_ring_ctx *ctx,
				    struct iou_loop_state *ls)
{
	return IOU_RES_STOP;
}
#endif

#endif
