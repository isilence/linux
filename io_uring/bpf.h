// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_BPF_H
#define IOU_BPF_H

#include <linux/io_uring_types.h>
#include <linux/bpf.h>

#include "io_uring.h"

struct io_uring_ops {
};

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
