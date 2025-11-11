/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/types.h>
#include <linux/stddef.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "types.bpf.h"
#include "common.h"

extern int bpf_io_uring_submit_sqes(struct io_ring_ctx *ctx, unsigned int nr) __ksym;
extern __u8 *bpf_io_uring_get_region(struct io_ring_ctx *ctx, __u32 region_id,
				     const __u64 rdwr_buf_size) __ksym;

static inline void io_bpf_wait_nr(struct io_ring_ctx *ring,
				  struct iou_loop_state *ls, int nr)
{
	ls->cq_tail = ring->rings->cq.head + nr;
}

enum {
	RINGS_REGION_ID		= 0,
	SQ_REGION_ID		= 1,
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";
int reqs_to_run;

SEC("struct_ops.s/link_loop")
int BPF_PROG(link_loop, struct io_ring_ctx *ring, struct iou_loop_state *ls)
{
	struct ring_hdr *sq_hdr, *cq_hdr;
	struct io_uring_cqe *cqe, *cqes;
	struct io_uring_sqe *sqes, *sqe;
	void *rings;
	int ret;

	sqes = (void *)bpf_io_uring_get_region(ring, SQ_REGION_ID,
				SQ_ENTRIES * sizeof(struct io_uring_sqe));
	rings = (void *)bpf_io_uring_get_region(ring, RINGS_REGION_ID,
				64 + CQ_ENTRIES * sizeof(struct io_uring_cqe));
	if (!rings || !sqes) {
		bpf_printk("error: can't get regions");
		return IOU_LOOP_STOP;
	}

	sq_hdr = rings;
	cq_hdr = sq_hdr + 1;
	cqes = rings + 64;

	if (cq_hdr->tail != cq_hdr->head) {
		unsigned cq_mask = CQ_ENTRIES - 1;

		cqe = &cqes[cq_hdr->head++ & cq_mask];
		bpf_printk("found cqe: data %lu res %i",
			   (unsigned long)cqe->user_data, (int)cqe->res);

		int left = --reqs_to_run;
		if (left <= 0) {
			bpf_printk("finished");
			return IOU_LOOP_STOP;
		}
	}

	bpf_printk("queue nop request, data %lu\n", (unsigned long)reqs_to_run);
	sqe = &sqes[sq_hdr->tail & (SQ_ENTRIES - 1)];
	sqe->user_data = reqs_to_run;
	sq_hdr->tail++;

	ret = bpf_io_uring_submit_sqes(ring, 1);
	if (ret != 1) {
		bpf_printk("bpf submit failed %i", ret);
		return IOU_LOOP_STOP;
	}

	io_bpf_wait_nr(ring, ls, 1);
	return IOU_LOOP_WAIT;
}

SEC(".struct_ops")
struct io_uring_ops basic_ops = {
	.loop = (void *)link_loop,
};
