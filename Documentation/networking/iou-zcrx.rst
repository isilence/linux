.. SPDX-License-Identifier: GPL-2.0

=====================
io_uring zero copy Rx
=====================

Introduction
============

io_uring zero copy Rx (ZC Rx) is a feature that removes kernel-to-user copy on
the network receive path, allowing packet data to be received directly into
userspace memory. This feature is different to TCP_ZEROCOPY_RECEIVE in that
there are no strict alignment requirements and no need to mmap()/munmap().
Compared to kernel bypass solutions such as e.g. DPDK, the packet headers are
processed by the kernel TCP stack as normal.

NIC HW Requirements
===================

Several NIC HW features are required for io_uring ZC Rx to work:

Header/data split
-----------------

Required to split packets at the L4 boundary into a header and a payload.
Headers are received into kernel memory as normal and processed by the TCP
stack as normal. Payloads are received into userspace memory directly.

Flow steering
-------------

Specific HW Rx queues are configured for this feature, but modern NICs randomly
distribute flows across all HW Rx queues. Flow steering is required to ensure
that only desired flows are directed towards HW queues that are configured for
io_uring ZC Rx.

RSS
---

In addition to flow steering above, RSS is required to steer all other non-zero
copy flows away from queues that are configured for io_uring ZC Rx.

Usage
=====

Setup NIC
--------

Must be done out of band for now.

Ensure there are enough queues::

  ethtool -L eth0 combined 32

Enable header/data split::

  ethtool -G eth0 tcp-data-split on

Carve out half of the HW Rx queues for zero copy using RSS::

  ethtool -X eth0 equal 16

Set up flow steering::

  ethtool -N eth0 flow-type tcp6 ... action 16

Setup io_uring
--------------

Create an io_uring instance using liburing. Certain io_uring flags are required
for ZC Rx to work::

  IORING_SETUP_SINGLE_ISSUER
  IORING_SETUP_DEFER_TASKRUN

Create memory area
------------------

Allocate userspace memory area for receiving data::

  void *area_base = mmap(NULL, area_size,
                         PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE,
                         0, 0);

Register ZC Rx
--------------

Set up ZC Rx for a HW queue::

  struct io_uring_zcrx_area_reg area_reg = {
    .addr = (__u64)(unsigned long)area_base,
    .len = area_size,
    .flags = 0,
    .area_id = 0,
  };

  struct io_uring_zcrx_ifq_reg reg = {
    .if_idx = if_nametoindex("eth0"),
    .if_rxq = 16,
    .rq_entries = 4096,
    .area_ptr = (__u64)(unsigned long)&area_reg,
  };

  io_uring_register_ifq(ring, &reg);

Setup refill ring
-----------------

The kernel fills in fields for the refill ring in the registration struct
io_uring_zcrx_ifq_reg. Map it into userspace::

  struct io_uring_zcrx_rq refill_ring;

  void *ring_ptr = mmap(NULL,
                        reg.offsets.mmap_sz,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE,
                        ring->enter_ring_fd,
                        IORING_OFF_RQ_RING);

  refill_ring.khead = (unsigned *)((char *)ring_ptr + reg.offsets.head);
  refill_ring.khead = (unsigned *)((char *)ring_ptr + reg.offsets.tail);
  refill_ring.rqes =
    (struct io_uring_zcrx_rqe *)((char *)ring_ptr + reg.offsets.rqes);
  refill_ring.rq_tail = 0;
  refill_ring.ring_ptr = ring_ptr;

Receiving data
--------------

Prepare a zero copy recv request::

  struct io_uring_sqe *sqe;

  sqe = io_uring_get_sqe(ring);
  io_uring_prep_rw(IORING_OP_RECV_ZC, sqe, fd, NULL, 0, 0);
  sqe->ioprio |= IORING_RECV_MULTISHOT;

Now, submit and wait::

  io_uring_submit_and_wait(ring, 1);

Finally, process completions::

  struct io_uring_cqe *cqe;
  unsigned int count = 0;
  unsigned int head;

  io_uring_for_each_cqe(ring, head, cqe) {
    struct io_uring_zcrx_cqe *rcqe = (struct io_uring_zcrx_cqe *)(cqe + 1);

    unsigned char *data = area_ptr + (rcqe->off & IORING_ZCRX_AREA_MASK);
    /* do something with the data */

    count++;
  }
  io_uring_cq_advance(ring, count);

Recycling buffers
-----------------

Return buffers back to the kernel to be used again::

  struct io_uring_zcrx_rqe *rqe;
  unsigned mask = refill_ring.ring_entries - 1;
  rqe = &refill_ring.rqes[refill_ring.rq_tail & mask];

  area_offset = rcqe->off & IORING_ZCRX_AREA_MASK;
  rqe->off = area_offset | area_reg.rq_area_token;
  rqe->len = cqe->res;
  IO_URING_WRITE_ONCE(*refill_ring.ktail, ++refill_ring.rq_tail);

Testing
=======

See ``tools/testing/selftests/net/iou-zcrx.c``
