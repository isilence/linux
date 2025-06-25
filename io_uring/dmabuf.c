#include "dmabuf.h"

void io_dmabuf_release(struct io_dmabuf *buf)
{
	if (buf->sgt)
		dma_buf_unmap_attachment_unlocked(buf->attach, buf->sgt,
						  buf->dir);
	if (buf->attach)
		dma_buf_detach(buf->dmabuf, buf->attach);
	if (buf->dmabuf)
		dma_buf_put(buf->dmabuf);
	if (buf->dev)
		put_device(buf->dev);

	memset(buf, 0, sizeof(*buf));
}

int io_dmabuf_import(struct io_dmabuf *buf, int dmabuf_fd,
		     struct device *dev, enum dma_data_direction dir)
{
	unsigned long total_size = 0;
	struct scatterlist *sg;
	int i, ret;

	if (WARN_ON_ONCE(!dev))
		return -EFAULT;

	buf->dir = dir;
	buf->dmabuf = dma_buf_get(dmabuf_fd);
	if (IS_ERR(buf->dmabuf)) {
		ret = PTR_ERR(buf->dmabuf);
		buf->dmabuf = NULL;
		goto err;
	}

	buf->attach = dma_buf_attach(buf->dmabuf, dev);
	if (IS_ERR(buf->attach)) {
		ret = PTR_ERR(buf->attach);
		buf->attach = NULL;
		goto err;
	}

	buf->sgt = dma_buf_map_attachment_unlocked(buf->attach, dir);
	if (IS_ERR(buf->sgt)) {
		ret = PTR_ERR(buf->sgt);
		buf->sgt = NULL;
		goto err;
	}

	for_each_sgtable_dma_sg(buf->sgt, sg, i)
		total_size += sg_dma_len(sg);

	buf->dir = dir;
	buf->dev = get_device(dev);
	buf->len = total_size;
	return 0;
err:
	io_dmabuf_release(buf);
	return ret;
}
