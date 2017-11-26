/*
 * Copyright (C) 2016 - 2017 Fuzhou Rockchip Electronics Co., Ltd
 *		Randy Li, <ayaka@soulik.info>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/dma-buf.h>
#include <linux/dma-iommu.h>
#include <linux/kref.h>

/* For kzalloc issues */
#include <linux/slab.h>
/* For iommu_*_device */
#include <linux/iommu.h>

#include "vcodec_iommu_dma.h"

/* pixel buffer, stream buffer and video codec buffer */
#define BUFFER_LIST_MAX_NUMS		26

struct vcodec_dma_buffer {
	struct list_head list;
	/* dma-buf */
	struct dma_buf *dma_buf;
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;

	dma_addr_t iova;
	unsigned long size;
	/* Only be used for identifying the buffer */
	int fd;

	int index;
	struct kref ref;
};

struct vcodec_iommu_info {
	struct iommu_domain *domain;
	bool attached;

	struct device *dev;
};

struct vcodec_dma_session {
	int buffer_nums;
	struct list_head buffer_list;
	/* Mutex for the above buffer list */
	struct mutex list_mutex;

	struct device *dev;
};

static struct vcodec_dma_buffer *
vcodec_dma_get_buffer(struct vcodec_dma_session *session, int fd)
{
	struct vcodec_dma_buffer *buffer = NULL, *n;

	mutex_lock(&session->list_mutex);
	list_for_each_entry_safe(buffer, n, &session->buffer_list, list) {
		/*
		 * As long as the last reference is hold by the buffer pool,
		 * the same fd won't be assigned to the other application.
		 */
		if (buffer->fd == fd) {
			mutex_unlock(&session->list_mutex);
			return buffer;
		}
	}
	mutex_unlock(&session->list_mutex);

	return NULL;
}

static void vcodec_dma_buffer_release(struct kref *ref)
{
	struct vcodec_dma_buffer *buffer =
		container_of(ref, struct vcodec_dma_buffer, ref);

	dma_buf_unmap_attachment(buffer->attach, buffer->sgt,
				 DMA_BIDIRECTIONAL);
	dma_buf_detach(buffer->dma_buf, buffer->attach);
	dma_buf_put(buffer->dma_buf);

	list_del(&buffer->list);
	kfree(buffer);
}

int vcodec_dma_release_fd(struct vcodec_dma_session *session, int fd)
{
	struct device *dev = session->dev;
	struct vcodec_dma_buffer *buffer = NULL;

	buffer = vcodec_dma_get_buffer(session, fd);
	if (IS_ERR_OR_NULL(buffer)) {
		dev_err(dev, "can not find %d buffer in list to release\n", fd);

		return -EINVAL;
	}

	kref_put(&buffer->ref, vcodec_dma_buffer_release);

	return 0;
}

dma_addr_t vcodec_dma_import_fd(struct vcodec_dma_session *session, int fd)
{
	struct vcodec_dma_buffer *buffer = NULL;
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
	struct dma_buf *dma_buf;
	int ret = 0;

	if (!session)
		return -EINVAL;

	buffer = vcodec_dma_get_buffer(session, fd);
	if (!IS_ERR_OR_NULL(buffer)) {
		kref_get(&buffer->ref);
		return buffer->iova;
	}

	dma_buf = dma_buf_get(fd);
	if (IS_ERR(dma_buf)) {
		ret = PTR_ERR(dma_buf);
		return ret;
	}

	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto err;
	}

	buffer->dma_buf = dma_buf;
	buffer->fd = fd;

	kref_init(&buffer->ref);

	attach = dma_buf_attach(buffer->dma_buf, session->dev);
	if (IS_ERR(attach)) {
		ret = PTR_ERR(attach);
		goto fail_out;
	}

	sgt = dma_buf_map_attachment(attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(sgt)) {
		ret = PTR_ERR(sgt);
		goto fail_detach;
	}

	buffer->iova = sg_dma_address(sgt->sgl);
	buffer->size = sg_dma_len(sgt->sgl);

	buffer->attach = attach;
	buffer->sgt = sgt;

	/* Increase the reference for used outside the buffer pool */
	kref_get(&buffer->ref);

	INIT_LIST_HEAD(&buffer->list);
	mutex_lock(&session->list_mutex);

	if (session->buffer_nums >= BUFFER_LIST_MAX_NUMS - 1) {
		struct vcodec_dma_buffer *loop_buffer = NULL, *n;
		/*
		 * Clear those buffer not be referenced beyond the buffer pool
		 * 1. unreference all the buffer in the list
		 * 2. reference count callback clean and remove it from the list
		 * 3. Put back the reference from the list
		 */
		list_for_each_entry_safe(loop_buffer, n,
					 &session->buffer_list, list) {
			kref_put(&loop_buffer->ref, vcodec_dma_buffer_release);
		}

		session->buffer_nums = 0;

		list_for_each_entry(loop_buffer, &session->buffer_list, list) {
			kref_get(&loop_buffer->ref);
			session->buffer_nums++;
		}
	}

	buffer->index = session->buffer_nums++;
	list_add_tail(&buffer->list, &session->buffer_list);
	mutex_unlock(&session->list_mutex);

	return buffer->iova;

fail_detach:
	dma_buf_detach(buffer->dma_buf, attach);
	dma_buf_put(buffer->dma_buf);
fail_out:
	kfree(buffer);
err:
	dma_buf_put(dma_buf);
	return ret;
}

void vcodec_dma_destroy_session(struct vcodec_dma_session *session)
{
	struct vcodec_dma_buffer *buffer = NULL, *n;

	if (!session)
		return;

	list_for_each_entry_safe(buffer, n, &session->buffer_list, list) {
		if (buffer->attach) {
			dma_buf_unmap_attachment(buffer->attach, buffer->sgt,
						 DMA_BIDIRECTIONAL);
			dma_buf_detach(buffer->dma_buf, buffer->attach);
			dma_buf_put(buffer->dma_buf);
			buffer->attach = NULL;
		}
		dma_buf_put(buffer->dma_buf);
		list_del(&buffer->list);
		kfree(buffer);
	}

	kfree(session);
}

struct vcodec_dma_session *vcodec_dma_session_create(struct device *dev)
{
	struct vcodec_dma_session *session = NULL;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		return session;

	INIT_LIST_HEAD(&session->buffer_list);
	mutex_init(&session->list_mutex);
	session->buffer_nums = 0;

	session->dev = dev;

	return session;
}

void vcodec_iommu_detach(struct vcodec_iommu_info *info)
{
	struct device *dev = info->dev;
	struct iommu_domain *domain = info->domain;

	if (!info->attached)
		return;

	iommu_detach_device(domain, dev);
	info->attached = false;
}

int vcodec_iommu_attach(struct vcodec_iommu_info *info)
{
	struct device *dev = info->dev;
	struct iommu_domain *domain = info->domain;
	int ret;

	if (info->attached)
		return 0;

	ret = iommu_attach_device(domain, dev);
	if (ret)
		return ret;

	info->attached = true;

	return ret;
}

struct vcodec_iommu_info *vcodec_iommu_probe(struct device *dev)
{
	struct vcodec_iommu_info *info = NULL;
	int ret = 0;

	dev->dma_parms = devm_kzalloc(dev, sizeof(*dev->dma_parms), GFP_KERNEL);
	if (!dev->dma_parms) {
		ret = -ENOMEM;
		goto err_free_parms;
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		ret = -ENOMEM;
		goto err_free_parms;
	}
	info->dev = dev;

	info->domain = iommu_domain_alloc(dev->bus);
	if (!info->domain) {
		ret = -ENOMEM;
		goto err_free_info;
	}

	ret = iommu_get_dma_cookie(info->domain);
	if (ret)
		goto err_free_domain;

	ret = dma_set_coherent_mask(dev, DMA_BIT_MASK(32));
	if (ret)
		goto err_put_cookie;

	dma_set_max_seg_size(dev, DMA_BIT_MASK(32));

	ret = iommu_attach_device(info->domain, dev);
	if (ret)
		goto err_put_cookie;

	/*
	 * You may use the arch_setup_dma_ops() instead in the future kernel
	 * version, but the iommu_domain_alloc() will create an unnamed domain.
	 */
	/* ??? - Myy */
	arch_setup_dma_ops(dev, 0x0, dev->coherent_dma_mask + 1,
				   info->domain->ops, true);

	return info;

err_put_cookie:
	iommu_put_dma_cookie(info->domain);
err_free_domain:
	iommu_domain_free(info->domain);
err_free_info:
	kfree(info);
err_free_parms:
	return ERR_PTR(ret);
}

int vcodec_iommu_remove(struct vcodec_iommu_info *info)
{
	iommu_detach_device(info->domain, info->dev);
	info->attached = false;

	iommu_put_dma_cookie(info->domain);
	iommu_domain_free(info->domain);

	kfree(info);

	return 0;
}
