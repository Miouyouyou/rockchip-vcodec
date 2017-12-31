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
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/iommu.h>

#include "mpp_iommu_dma.h"

/* pixel buffer, stream buffer and video codec buffer */
#define BUFFER_LIST_MAX_NUMS		30

struct mpp_dma_buffer {
	struct list_head list;
	struct mpp_dma_session *session;
	/* dma-buf */
	struct dma_buf *dma_buf;
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
	enum dma_data_direction dir;

	dma_addr_t iova;
	unsigned long size;
	/* Only be used for identifying the buffer */
	int fd;

	struct kref ref;
	struct rcu_head rcu;
};

struct mpp_iommu_info {
	struct iommu_domain *domain;
	struct device *dev;
};

struct mpp_dma_session {
	struct list_head buffer_list;
	/* the mutex for the above buffer list */
	struct mutex list_mutex;

	struct device *dev;
};

static struct mpp_dma_buffer *
mpp_dma_find_buffer(struct mpp_dma_session *session, int fd)
{
	struct mpp_dma_buffer *buffer = NULL;

	list_for_each_entry_rcu(buffer, &session->buffer_list, list) {
		/*
		 * As long as the last reference is hold by the buffer pool,
		 * the same fd won't be assigned to the other application.
		 */
		if (buffer->fd == fd)
			return buffer;
	}

	return NULL;
}

/* Release the buffer from the current list */
static void mpp_dma_buffer_delete_rcu(struct kref *ref)
{
	struct mpp_dma_buffer *buffer =
		container_of(ref, struct mpp_dma_buffer, ref);

	mutex_lock(&buffer->session->list_mutex);
	list_del_rcu(&buffer->list);
	mutex_unlock(&buffer->session->list_mutex);

	dma_buf_unmap_attachment(buffer->attach, buffer->sgt, buffer->dir);
	dma_buf_detach(buffer->dma_buf, buffer->attach);
	dma_buf_put(buffer->dma_buf);
	kfree_rcu(buffer, rcu);
}

int mpp_dma_release_fd(struct mpp_dma_session *session, int fd)
{
	struct device *dev = session->dev;
	struct mpp_dma_buffer *buffer = NULL;

	rcu_read_lock();
	buffer = mpp_dma_find_buffer(session, fd);
	rcu_read_unlock();
	if (IS_ERR_OR_NULL(buffer)) {
		dev_err(dev, "can not find %d buffer in list to release\n", fd);

		return -EINVAL;
	}

	kref_put(&buffer->ref, mpp_dma_buffer_delete_rcu);

	return 0;
}

dma_addr_t mpp_dma_import_fd(struct mpp_dma_session *session, int fd)
{
	struct mpp_dma_buffer *buffer = NULL;
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
	struct dma_buf *dma_buf;
	int ret = 0;

	if (!session)
		return -EINVAL;

	dma_buf = dma_buf_get(fd);
	if (IS_ERR(dma_buf)) {
		ret = PTR_ERR(dma_buf);
		return ret;
	}

	rcu_read_lock();
	buffer = mpp_dma_find_buffer(session, fd);
	if (!IS_ERR_OR_NULL(buffer)) {
		if (buffer->dma_buf == dma_buf) {
			if (kref_get_unless_zero(&buffer->ref)) {
				rcu_read_unlock();
				return buffer->iova;
			}
		}
		rcu_read_unlock();
		dev_dbg(session->dev,
			"missing the fd %d\n", fd);
		kref_put(&buffer->ref, mpp_dma_buffer_delete_rcu);
	} else {
		rcu_read_unlock();
	}

	/* A new DMA buffer */
	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto err;
	}

	buffer->dma_buf = dma_buf;
	buffer->fd = fd;
	/* TODO */
	buffer->dir = DMA_BIDIRECTIONAL;

	kref_init(&buffer->ref);

	attach = dma_buf_attach(buffer->dma_buf, session->dev);
	if (IS_ERR(attach)) {
		ret = PTR_ERR(attach);
		goto fail_out;
	}

	sgt = dma_buf_map_attachment(attach, buffer->dir);
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
	buffer->session = session;
	list_add_tail_rcu(&buffer->list, &session->buffer_list);
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

void mpp_dma_destroy_session(struct mpp_dma_session *session)
{
	struct mpp_dma_buffer *buffer = NULL;

	if (!session)
		return;

	mutex_lock(&session->list_mutex);
	list_for_each_entry_rcu(buffer, &session->buffer_list, list) {
		list_del_rcu(&buffer->list);
		dma_buf_unmap_attachment(buffer->attach, buffer->sgt,
					 buffer->dir);
		dma_buf_detach(buffer->dma_buf, buffer->attach);
		dma_buf_put(buffer->dma_buf);
		kfree_rcu(buffer, rcu);
	}
	mutex_unlock(&session->list_mutex);

	kfree(session);
}

struct mpp_dma_session *mpp_dma_session_create(struct device *dev)
{
	struct mpp_dma_session *session = NULL;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		return session;

	INIT_LIST_HEAD(&session->buffer_list);
	mutex_init(&session->list_mutex);

	session->dev = dev;

	return session;
}

void mpp_iommu_detach(struct mpp_iommu_info *info)
{
	struct device *dev = info->dev;
	struct iommu_domain *domain = info->domain;

	iommu_detach_device(domain, dev);
}

int mpp_iommu_attach(struct mpp_iommu_info *info)
{
	struct device *dev = info->dev;
	struct iommu_domain *domain = info->domain;
	int ret;

	ret = iommu_attach_device(domain, dev);
	if (ret)
		return ret;

	return 0;
}

struct mpp_iommu_info *mpp_iommu_probe(struct device *dev)
{
	struct mpp_iommu_info *info = NULL;
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

int mpp_iommu_remove(struct mpp_iommu_info *info)
{
	iommu_detach_device(info->domain, info->dev);

	iommu_put_dma_cookie(info->domain);
	iommu_domain_free(info->domain);

	kfree(info);

	return 0;
}
