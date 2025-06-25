// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_DMABUF_H
#define IOU_DMABUF_H

#include <linux/io_uring_types.h>
#include <linux/dma-buf.h>

struct io_dmabuf {
	size_t				len;
	struct dma_buf_attachment	*attach;
	struct dma_buf			*dmabuf;
	struct sg_table			*sgt;
	struct device			*dev;
	enum dma_data_direction		dir;
};

#ifdef CONFIG_DMA_SHARED_BUFFER
void io_dmabuf_release(struct io_dmabuf *buf);
int io_dmabuf_import(struct io_dmabuf *buf, int dmabuf_fd,
		     struct device *dev, enum dma_data_direction dir);

#else
static inline void io_dmabuf_release(struct io_dmabuf *buf)
{
}

static inline int io_dmabuf_import(struct io_dmabuf *buf, int dmabuf_fd,
		     struct device *dev, enum dma_data_direction dir)
{
	return -EOPNOTSUPP;
}
#endif

#endif
