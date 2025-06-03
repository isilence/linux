#include <linux/mutex.h>
#include <linux/bpf_verifier.h>

#include "io_uring.h"
#include "bpf.h"
#include "register.h"

static const struct btf_type *loop_state_type;
DEFINE_MUTEX(io_bpf_ctrl_mutex);

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_io_uring_submit_sqes(struct io_ring_ctx *ctx,
					 unsigned nr)
{
	return io_submit_sqes(ctx, nr);
}

__bpf_kfunc int bpf_io_uring_post_cqe(struct io_ring_ctx *ctx,
				      u64 data, u32 res, u32 cflags)
{
	bool posted;

	posted = io_post_aux_cqe(ctx, data, res, cflags);
	return posted ? 0 : -ENOMEM;
}

__bpf_kfunc int bpf_io_uring_queue_sqe(struct io_ring_ctx *ctx,
					void *bpf_sqe, int mem__sz)
{
	unsigned tail = ctx->rings->sq.tail;
	struct io_uring_sqe *sqe;

	if (mem__sz != sizeof(*sqe))
		return -EINVAL;

	ctx->rings->sq.tail++;
	tail &= (ctx->sq_entries - 1);
	/* double index for 128-byte SQEs, twice as long */
	if (ctx->flags & IORING_SETUP_SQE128)
		tail <<= 1;
	sqe = &ctx->sq_sqes[tail];
	memcpy(sqe, bpf_sqe, sizeof(*sqe));
	return 0;
}

__bpf_kfunc
struct io_uring_cqe *bpf_io_uring_get_cqe(struct io_ring_ctx *ctx, u32 idx)
{
	unsigned max_entries = ctx->cq_entries;
	struct io_uring_cqe *cqe_array = ctx->rings->cqes;

	if (ctx->flags & IORING_SETUP_CQE32)
		max_entries *= 2;
	return &cqe_array[idx & (max_entries - 1)];
}

__bpf_kfunc
struct io_uring_cqe *bpf_io_uring_extract_next_cqe(struct io_ring_ctx *ctx)
{
	struct io_rings *rings = ctx->rings;
	unsigned int mask = ctx->cq_entries - 1;
	unsigned head = rings->cq.head;
	struct io_uring_cqe *cqe;

	/* TODO CQE32 */
	if (head == rings->cq.tail)
		return NULL;

	cqe = &rings->cqes[head & mask];
	rings->cq.head++;
	return cqe;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(io_uring_kfunc_set)
BTF_ID_FLAGS(func, bpf_io_uring_submit_sqes, KF_SLEEPABLE);
BTF_ID_FLAGS(func, bpf_io_uring_post_cqe, KF_SLEEPABLE);
BTF_ID_FLAGS(func, bpf_io_uring_queue_sqe, KF_SLEEPABLE);
BTF_ID_FLAGS(func, bpf_io_uring_get_cqe, 0);
BTF_ID_FLAGS(func, bpf_io_uring_extract_next_cqe, KF_RET_NULL);
BTF_KFUNCS_END(io_uring_kfunc_set)

static const struct btf_kfunc_id_set bpf_io_uring_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &io_uring_kfunc_set,
};

static int io_bpf_ops__handle_events(struct io_ring_ctx *ctx,
				     struct iou_loop_state *state)
{
	return IOU_EVENTS_STOP;
}

static struct io_uring_ops io_bpf_ops_stubs = {
	.handle_events = io_bpf_ops__handle_events,
};

static bool bpf_io_is_valid_access(int off, int size,
				    enum bpf_access_type type,
				    const struct bpf_prog *prog,
				    struct bpf_insn_access_aux *info)
{
	if (type != BPF_READ)
		return false;
	if (off < 0 || off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS)
		return false;
	if (off % size != 0)
		return false;

	return btf_ctx_access(off, size, type, prog, info);
}

static int bpf_io_btf_struct_access(struct bpf_verifier_log *log,
				    const struct bpf_reg_state *reg, int off,
				    int size)
{
	const struct btf_type *t = btf_type_by_id(reg->btf, reg->btf_id);

	if (t == loop_state_type) {
		if (off >= offsetof(struct iou_loop_state, target_cq_tail) &&
		    off + size <= offsetofend(struct iou_loop_state, target_cq_tail))
			return SCALAR_VALUE;
		if (off >= offsetof(struct iou_loop_state, timeout) &&
		    off + size <= offsetofend(struct iou_loop_state, timeout))
			return SCALAR_VALUE;
	}
	return -EACCES;
}

static const struct bpf_verifier_ops bpf_io_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.is_valid_access = bpf_io_is_valid_access,
	.btf_struct_access = bpf_io_btf_struct_access,
};

static const struct btf_type *
io_lookup_struct_type(struct btf *btf, const char *name)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, name, BTF_KIND_STRUCT);
	if (type_id < 0)
		return NULL;
	return btf_type_by_id(btf, type_id);
}

static int bpf_io_init(struct btf *btf)
{
	loop_state_type = io_lookup_struct_type(btf, "iou_loop_state");
	if (!loop_state_type)
		return -EINVAL;
	return 0;
}

static int bpf_io_check_member(const struct btf_type *t,
				const struct btf_member *member,
				const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_io_init_member(const struct btf_type *t,
			       const struct btf_member *member,
			       void *kdata, const void *udata)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;
	const struct io_uring_ops *uops = udata;
	struct io_uring_ops *ops = kdata;

	switch (moff) {
	case offsetof(struct io_uring_ops, ring_fd):
		ops->ring_fd = uops->ring_fd;
		return 1;
	}
	return 0;
}

static int io_register_bpf_ops(struct io_ring_ctx *ctx, struct io_uring_ops *ops)
{
	if (ctx->bpf_ops)
		return -EBUSY;
	if (!(ctx->flags & IORING_SETUP_DEFER_TASKRUN))
		return -EOPNOTSUPP;

	percpu_ref_get(&ctx->refs);
	ops->ctx = ctx;
	ctx->bpf_ops = ops;
	return 0;
}

static int bpf_io_reg(void *kdata, struct bpf_link *link)
{
	struct io_uring_ops *ops = kdata;
	struct io_ring_ctx *ctx;
	struct file *file;
	int ret;

	file = io_uring_register_get_file(ops->ring_fd, false);
	if (IS_ERR(file))
		return PTR_ERR(file);

	ctx = file->private_data;
	scoped_guard(mutex, &ctx->uring_lock)
		ret = io_register_bpf_ops(ctx, ops);

	fput(file);
	return ret;
}

static void bpf_io_unreg(void *kdata, struct bpf_link *link)
{
	struct io_uring_ops *ops = kdata;
	struct io_ring_ctx *ctx;

	guard(mutex)(&io_bpf_ctrl_mutex);

	ctx = ops->ctx;
	ops->ctx = NULL;

	if (ctx) {
		scoped_guard(mutex, &ctx->uring_lock) {
			if (ctx->bpf_ops == ops)
				ctx->bpf_ops = NULL;
		}
		percpu_ref_put(&ctx->refs);
	}
}

void io_unregister_bpf_ops(struct io_ring_ctx *ctx)
{
	struct io_uring_ops *ops;

	guard(mutex)(&io_bpf_ctrl_mutex);
	guard(mutex)(&ctx->uring_lock);

	ops = ctx->bpf_ops;
	ctx->bpf_ops = NULL;

	if (ops && ops->ctx) {
		percpu_ref_put(&ctx->refs);
		ops->ctx = NULL;
	}
}

static struct bpf_struct_ops bpf_io_uring_ops = {
	.verifier_ops = &bpf_io_verifier_ops,
	.reg = bpf_io_reg,
	.unreg = bpf_io_unreg,
	.check_member = bpf_io_check_member,
	.init_member = bpf_io_init_member,
	.init = bpf_io_init,
	.cfi_stubs = &io_bpf_ops_stubs,
	.name = "io_uring_ops",
	.owner = THIS_MODULE,
};

static int __init io_uring_bpf_init(void)
{
	int ret;

	ret = register_bpf_struct_ops(&bpf_io_uring_ops, io_uring_ops);
	if (ret) {
		pr_err("io_uring: Failed to register struct_ops (%d)\n", ret);
		return ret;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&bpf_io_uring_kfunc_set);
	if (ret) {
		pr_err("io_uring: Failed to register kfuncs (%d)\n", ret);
		return ret;
	}
	return 0;
}
__initcall(io_uring_bpf_init);
