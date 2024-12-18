// SPDX-License-Identifier: GPL-2.0

#include "linux/io_uring/query.h"

#include "query.h"
#include "io_uring.h"

#define IO_MAX_QUERY_SIZE		512

static int io_query_ops(void *buffer)
{
	struct io_uring_query_opcode *e = buffer;

	BUILD_BUG_ON(sizeof(struct io_uring_query_opcode) > IO_MAX_QUERY_SIZE);

	e->hdr.size = min(e->hdr.size, sizeof(*e));
	e->nr_request_opcodes = IORING_OP_LAST;
	e->nr_register_opcodes = IORING_REGISTER_LAST;
	e->features = IORING_FEATURES;
	e->ring_flags = IORING_VALID_SETUP_FLAGS;
	return 0;
}

static int io_handle_query_entry(struct io_ring_ctx *ctx,
				 void *buffer,
				 void __user *uentry, u64 *next_entry)
{
	struct io_uring_query_hdr *hdr = buffer;
	size_t entry_size = sizeof(*hdr);
	int ret = -EINVAL;

	if (copy_from_user(hdr, uentry, sizeof(*hdr)) ||
	    hdr->size <= sizeof(*hdr))
		return -EFAULT;

	if (hdr->query_op >= __IO_URING_QUERY_MAX) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	if (!mem_is_zero(hdr->__resv, sizeof(hdr->__resv)) || hdr->result)
		goto out;

	hdr->size = min(hdr->size, IO_MAX_QUERY_SIZE);
	if (copy_from_user(buffer + sizeof(*hdr), uentry + sizeof(*hdr),
			   hdr->size - sizeof(*hdr)))
		return -EFAULT;

	switch (hdr->query_op) {
	case IO_URING_QUERY_OPCODES:
		ret = io_query_ops(buffer);
		break;
	}
	if (!ret)
		entry_size = hdr->size;
out:
	hdr->result = ret;
	hdr->size = entry_size;
	if (copy_to_user(uentry, buffer, entry_size))
		return -EFAULT;
	*next_entry = hdr->next_entry;
	return 0;
}

int io_query(struct io_ring_ctx *ctx, void __user *arg, unsigned nr_args)
{
	char entry_buffer[IO_MAX_QUERY_SIZE];
	void __user *uentry = arg;
	int ret;

	memset(entry_buffer, 0, sizeof(entry_buffer));

	if (nr_args)
		return -EINVAL;

	while (uentry) {
		u64 next;

		ret = io_handle_query_entry(ctx, entry_buffer, uentry, &next);
		if (ret)
			return ret;
		uentry = u64_to_user_ptr(next);
	}
	return 0;
}
