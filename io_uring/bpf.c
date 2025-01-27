#include <linux/mutex.h>

#include "bpf.h"
#include "register.h"

static struct io_uring_ops io_bpf_ops_stubs = {
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
	return -EACCES;
}

static const struct bpf_verifier_ops bpf_io_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.is_valid_access = bpf_io_is_valid_access,
	.btf_struct_access = bpf_io_btf_struct_access,
};

static int bpf_io_init(struct btf *btf)
{
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
