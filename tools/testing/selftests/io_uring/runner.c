#include <linux/stddef.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>

#include <io_uring/mini_liburing.h>
#include "basic.bpf.skel.h"
#include "common.h"

struct basic *skel;
struct bpf_link *basic_link;

static void setup_ring(struct io_uring *ring)
{
	struct io_uring_params params;
	int ret;

	memset(&params, 0, sizeof(params));
	params.cq_entries = CQ_ENTRIES;
	params.flags = IORING_SETUP_SINGLE_ISSUER |
			IORING_SETUP_DEFER_TASKRUN |
			IORING_SETUP_NO_SQARRAY |
			IORING_SETUP_CQSIZE;

	ret = io_uring_queue_init_params(SQ_ENTRIES, ring, &params);
	if (ret) {
		fprintf(stderr, "ring init failed\n");
		exit(1);
	}
}

static void setup_bpf_ops(struct io_uring *ring)
{
	int ret;

	skel = basic__open();
	if (!skel) {
		fprintf(stderr, "can't generate skeleton\n");
		exit(1);
	}

	skel->struct_ops.basic_ops->ring_fd = ring->ring_fd;
	skel->bss->reqs_to_run = 10;

	ret = basic__load(skel);
	if (ret) {
		fprintf(stderr, "failed to load skeleton\n");
		exit(1);
	}

	basic_link = bpf_map__attach_struct_ops(skel->maps.basic_ops);
	if (!basic_link) {
		fprintf(stderr, "failed to attach ops\n");
		exit(1);
	}
}

static void run_ring(struct io_uring *ring)
{
	int ret;

	ret = io_uring_enter(ring->ring_fd, 0, 0, IORING_ENTER_GETEVENTS, NULL);
	if (ret) {
		fprintf(stderr, "run failed\n");
		exit(1);
	}
}

int main() {
	struct io_uring ring;

	setup_ring(&ring);
	setup_bpf_ops(&ring);

	run_ring(&ring);

	bpf_link__destroy(basic_link);
	basic__destroy(skel);
	return 0;
}
