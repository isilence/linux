// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_BPF_H
#define IOU_BPF_H

#include <linux/io_uring_types.h>
#include <linux/bpf.h>

#include "io_uring.h"

enum {
	IOU_EVENTS_WAIT,
	IOU_EVENTS_STOP,
};

struct io_uring_ops {
	__u32 ring_fd;

	int (*handle_events)(struct io_ring_ctx *ctx, struct iou_loop_state *state);

	struct io_ring_ctx *ctx;
};

static inline int io_run_bpf(struct io_ring_ctx *ctx, struct iou_loop_state *state)
{
	scoped_guard(mutex, &ctx->uring_lock) {
		if (!ctx->bpf_ops)
			return IOU_EVENTS_STOP;
		return ctx->bpf_ops->handle_events(ctx, state);
	}
}

static inline bool io_bpf_attached(struct io_ring_ctx *ctx)
{
	return IS_ENABLED(CONFIG_IO_URING_BPF) && ctx->bpf_ops != NULL;
}

#ifdef CONFIG_IO_URING_BPF
void io_unregister_bpf_ops(struct io_ring_ctx *ctx);
#else
static inline void io_unregister_bpf_ops(struct io_ring_ctx *ctx)
{
}
#endif

#endif
