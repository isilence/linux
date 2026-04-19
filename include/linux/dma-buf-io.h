/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __DMA_BUF_IO_H__
#define __DMA_BUF_IO_H__

#include <linux/dma-buf.h>

struct dma_buf_io_fence;
struct dma_buf_io_ctx;
struct dma_buf_io_map;

struct dma_buf_io_ops {
	/*
	 * Create a new map for the given ctx. Called with the reservation
	 * lock held.
	 */
	struct dma_buf_io_map *(*map)(struct dma_buf_io_ctx *ctx);

	/*
	 * Clean up device specific parts of the @map. Called with the
	 * reservation lock held.
	 */
	void (*unmap)(struct dma_buf_io_ctx *ctx, struct dma_buf_io_map *map);

	/*
	 * The user tries to destroy the ctx. Release all device specific
	 * parts of the token.
	 */
	void (*release)(struct dma_buf_io_ctx *);
};

struct dma_buf_io_map {
	/*
	 * Counts attached requests and other users. Device specific unmapping
	 * is deferred until all refs are dropped.
	 */
	struct percpu_ref		refs;
	unsigned			seg_shift;

	struct work_struct		release_work;
	struct dma_buf_io_fence		*fence;
	struct dma_buf_io_ctx		*ctx;
};

struct dma_buf_io_ctx {
	struct dma_buf_io_map __rcu		*map;
	struct dma_buf				*dmabuf;
	enum dma_data_direction			dir;

	atomic_t				fence_seq;
	u64					fence_ctx;
	struct work_struct			release_work;
	refcount_t				refs;

	void					*dev_priv;
	const struct dma_buf_io_ops		*dev_ops;
};

int dma_buf_io_ctx_create(struct file *file,
			   struct dma_buf_io_ctx *ctx,
			   struct dma_buf *dmabuf,
			   enum dma_data_direction dir);
void dma_buf_io_ctx_release(struct dma_buf_io_ctx *ctx);

struct dma_buf_io_map *dma_buf_io_create_map(struct dma_buf_io_ctx *ctx);

static inline struct dma_buf_io_map *
dma_buf_io_get_map(struct dma_buf_io_ctx *ctx)
{
	struct dma_buf_io_map *map;

	guard(rcu)();

	map = rcu_dereference(ctx->map);
	if (unlikely(!map || !percpu_ref_tryget_live_rcu(&map->refs)))
		return NULL;

	return map;
}

static inline void dma_buf_io_map_drop(struct dma_buf_io_map *map)
{
	percpu_ref_put(&map->refs);
}

/*
 * Device API
 */

void dma_buf_io_invalidate_mappings(struct dma_buf_io_ctx *ctx);
int dma_buf_io_init_map(struct dma_buf_io_ctx *ctx, struct dma_buf_io_map *map);

#endif
