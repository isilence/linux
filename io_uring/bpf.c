#include <linux/mutex.h>
#include <linux/bpf_verifier.h>

#include "bpf.h"
#include "register.h"

static const struct btf_type *loop_state_type;

static int io_bpf_ops__loop(struct io_ring_ctx *ctx, struct iou_loop_state *ls)
{
	return IOU_RES_STOP;
}

static struct io_uring_ops io_bpf_ops_stubs = {
	.loop = io_bpf_ops__loop,
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
		if (off >= offsetof(struct iou_loop_state, cq_tail) &&
		    off + size <= offsetofend(struct iou_loop_state, cq_tail))
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
	if (!loop_state_type) {
		pr_err("io_uring: Failed to locate iou_loop_state\n");
		return -EINVAL;
	}

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
	return 0;
}

static int bpf_io_reg(void *kdata, struct bpf_link *link)
{
	return -EOPNOTSUPP;
}

static void bpf_io_unreg(void *kdata, struct bpf_link *link)
{
}

void io_unregister_bpf(struct io_ring_ctx *ctx)
{
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

	return 0;
}
__initcall(io_uring_bpf_init);

int io_run_cqwait_ops(struct io_ring_ctx *ctx, struct iou_loop_state *ls)
{
	int ret;

	io_run_task_work();

	guard(mutex)(&ctx->uring_lock);
	if (unlikely(!ctx->bpf_ops))
		return 1;

	if (unlikely(task_sigpending(current)))
		return -EINTR;

	ret = ctx->bpf_ops->loop(ctx, ls);
	if (ret == IOU_RES_STOP)
		return 0;


	if (io_local_work_pending(ctx)) {
		unsigned nr_wait = ls->cq_tail - READ_ONCE(ctx->rings->cq.tail);
		struct io_tw_state ts = {};

		__io_run_local_work(ctx, ts, nr_wait, nr_wait);
	}
	return 1;
}
