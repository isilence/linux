/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common infrastructure for supporing dma-buf in the I/O path.
 *
 * Copyright (C) 2026 Pavel Begunkov <asml.silence@gmail.com>
 */
#include <linux/dma-buf-io.h>
#include <linux/dma-resv.h>

struct dma_buf_io_fence {
	struct dma_fence base;
	spinlock_t lock;
};

static const char *dma_buf_io_fence_drv_name(struct dma_fence *fence)
{
	/* default fence release kfree's the base pointer */
	BUILD_BUG_ON(offsetof(struct dma_buf_io_fence, base));

	return "dma-buf-io-ctx";
}

static const char *dma_buf_io_fence_timeline_name(struct dma_fence *fence)
{
	return "dma-buf-io-ctx";
}

const struct dma_fence_ops dma_buf_io_fence_ops = {
	.get_driver_name = dma_buf_io_fence_drv_name,
	.get_timeline_name = dma_buf_io_fence_timeline_name,
};

static void dma_buf_io_ctx_destroy_work(struct work_struct *work)
{
	struct dma_buf_io_ctx *ctx = container_of(work, struct dma_buf_io_ctx,
						  release_work);

	if (WARN_ON_ONCE(refcount_read(&ctx->refs)))
		return;

	ctx->dev_ops->release(ctx);
	dma_buf_put(ctx->dmabuf);
	kfree(ctx);
}

static void dma_buf_io_map_release_work(struct work_struct *work)
{
	struct dma_buf_io_map *map = container_of(work, struct dma_buf_io_map,
						  release_work);
	struct dma_buf_io_fence *fence = map->fence;
	struct dma_buf_io_ctx *ctx = map->ctx;
	struct dma_buf *dmabuf = ctx->dmabuf;

	/* the release path must wait for fences */
	if (WARN_ON_ONCE(refcount_read(&ctx->refs) == 0))
		return;

	/* Prevent from destoying the ctx while unmapping */
	refcount_inc(&ctx->refs);

	/*
	 * There are no more requests using the map, we can signal the fence.
	 * It should be done before taking the resv lock as someone could be
	 * waiting for the fence while holding the lock.
	 */
	dma_fence_signal(&fence->base);

	dma_resv_lock(dmabuf->resv, NULL);
	ctx->dev_ops->unmap(ctx, map);
	dma_resv_unlock(dmabuf->resv);

	dma_fence_put(&fence->base);
	percpu_ref_exit(&map->refs);
	kfree(map);

	if (refcount_dec_and_test(&ctx->refs)) {
		/*
		 * Destruction needs to wait for I/O and dma fences. Defer it to
		 * simplify locking.
		 */
		INIT_WORK(&ctx->release_work, dma_buf_io_ctx_destroy_work);
		queue_work(system_wq, &ctx->release_work);
	}
}

static void dma_buf_io_map_refs_release(struct percpu_ref *ref)
{
	struct dma_buf_io_map *map = container_of(ref, struct dma_buf_io_map, refs);

	/* might sleep, use a worker */
	INIT_WORK(&map->release_work, dma_buf_io_map_release_work);
	queue_work(system_wq, &map->release_work);
}

int dma_buf_io_init_map(struct dma_buf_io_ctx *ctx, struct dma_buf_io_map *map)
{
	struct dma_buf_io_fence *fence = NULL;
	int ret;

	fence = kzalloc(sizeof(*fence), GFP_KERNEL);
	if (!fence)
		return -ENOMEM;

	ret = percpu_ref_init(&map->refs, dma_buf_io_map_refs_release, 0, GFP_KERNEL);
	if (ret) {
		kfree(fence);
		return ret;
	}

	spin_lock_init(&fence->lock);
	dma_fence_init(&fence->base, &dma_buf_io_fence_ops, &fence->lock,
			ctx->fence_ctx, atomic_inc_return(&ctx->fence_seq));
	map->fence = fence;
	map->ctx = ctx;
	return 0;
}
EXPORT_SYMBOL_NS_GPL(dma_buf_io_init_map, "DMA_BUF");

struct dma_buf_io_map *dma_buf_io_create_map(struct dma_buf_io_ctx *ctx)
{
	struct dma_buf *dmabuf = ctx->dmabuf;
	struct dma_buf_io_map *map;
	long ret;

retry:
	/*
	 * ->dmabuf_map() will be calling dma_buf_map_attachment(), for which
	 * we'll need to wait for fences. Do a bit nicer and try to wait
	 * without the resv lock first.
	 */
	ret = dma_resv_wait_timeout(dmabuf->resv, DMA_RESV_USAGE_KERNEL,
				    true, MAX_SCHEDULE_TIMEOUT);
	if (!ret)
		ret = -EAGAIN;
	if (ret < 0)
		return ERR_PTR(ret);

	ret = dma_resv_lock_interruptible(dmabuf->resv, NULL);
	if (ret)
		return ERR_PTR(ret);

	map = dma_buf_io_get_map(ctx);
	if (map) {
		ret = 0;
		goto out;
	}

	if (dma_resv_wait_timeout(dmabuf->resv, DMA_RESV_USAGE_KERNEL,
				  true, 0) < 0) {
		dma_resv_unlock(dmabuf->resv);
		goto retry;
	}

	map = ctx->dev_ops->map(ctx);
	if (IS_ERR(map)) {
		ret = PTR_ERR(map);
		goto out;
	}

	if (WARN_ON_ONCE(!map->seg_shift))
		return ERR_PTR(-EFAULT);

	percpu_ref_get(&map->refs);
	rcu_assign_pointer(ctx->map, map);
out:
	dma_resv_unlock(dmabuf->resv);
	if (ret < 0)
		return ERR_PTR(ret);
	return map;
}

static void dma_buf_io_drop_map(struct dma_buf_io_ctx *ctx)
{
	struct dma_buf *dmabuf = ctx->dmabuf;
	struct dma_buf_io_map *map;
	int ret;

	dma_resv_assert_held(dmabuf->resv);

	map = rcu_dereference_protected(ctx->map,
					dma_resv_held(dmabuf->resv));
	if (!map)
		return;
	rcu_assign_pointer(ctx->map, NULL);

	ret = dma_resv_reserve_fences(dmabuf->resv, 1);
	if (WARN_ON_ONCE(ret)) {
		struct dma_fence *fence = &map->fence->base;

		dma_fence_get(fence);
		percpu_ref_kill(&map->refs);
		dma_fence_wait(fence, false);
		dma_fence_put(fence);
		return;
	}

	dma_resv_add_fence(dmabuf->resv, &map->fence->base,
			   DMA_RESV_USAGE_KERNEL);
	/*
	 * Delay destruction until all inflight requests using the map are
	 * gone. It'll also signal the fence then.
	 */
	percpu_ref_kill(&map->refs);
}

void dma_buf_io_invalidate_mappings(struct dma_buf_io_ctx *ctx)
{
	dma_buf_io_drop_map(ctx);
}
EXPORT_SYMBOL_NS_GPL(dma_buf_io_invalidate_mappings, "DMA_BUF");

static void dma_buf_io_ctx_release_work(struct work_struct *work)
{
	struct dma_buf_io_ctx *ctx = container_of(work, struct dma_buf_io_ctx,
						  release_work);
	struct dma_buf *dmabuf = ctx->dmabuf;
	long ret;

	dma_resv_lock(dmabuf->resv, NULL);
	/* Remove the last map, there should be no new ones going forward. */
	dma_buf_io_drop_map(ctx);
	dma_resv_unlock(dmabuf->resv);

	/* Wait until all maps are destroyed. */
	ret = dma_resv_wait_timeout(dmabuf->resv, DMA_RESV_USAGE_KERNEL,
				    false, MAX_SCHEDULE_TIMEOUT);

	if (WARN_ON_ONCE(ret <= 0))
		return;
	if (WARN_ON_ONCE(rcu_dereference_protected(ctx->map, true)))
		return;

	if (refcount_dec_and_test(&ctx->refs))
		dma_buf_io_ctx_destroy_work(&ctx->release_work);
}

void dma_buf_io_ctx_release(struct dma_buf_io_ctx *ctx)
{
	/*
	 * Destruction needs to wait for I/O and dma fences. Defer it to
	 * simplify locking.
	 */
	INIT_WORK(&ctx->release_work, dma_buf_io_ctx_release_work);
	queue_work(system_wq, &ctx->release_work);
}

int dma_buf_io_ctx_create(struct file *file,
			   struct dma_buf_io_ctx *ctx,
			   struct dma_buf *dmabuf,
			   enum dma_data_direction dir)
{
	int ret;

	if (!file->f_op->init_dma_buf_io_ctx)
		return -EOPNOTSUPP;

	memset(ctx, 0, sizeof(*ctx));
	ctx->fence_ctx = dma_fence_context_alloc(1);
	ctx->dir = dir;
	ctx->dmabuf = dmabuf;
	refcount_set(&ctx->refs, 1);
	get_dma_buf(dmabuf);

	ret = file->f_op->init_dma_buf_io_ctx(file, ctx);
	if (ret) {
		memset(ctx, 0, sizeof(*ctx));
		dma_buf_put(dmabuf);
		return ret;
	}

	if (WARN_ON_ONCE(!ctx->dev_ops ||
			 !ctx->dev_ops->map ||
			 !ctx->dev_ops->unmap ||
			 !ctx->dev_ops->release))
		return -EINVAL;

	return ret;
}
