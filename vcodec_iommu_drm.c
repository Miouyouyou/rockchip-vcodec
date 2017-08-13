/*
 * Copyright (C) 2016 Fuzhou Rockchip Electronics Co., Ltd
 * author: Jung Zhao jung.zhao@rock-chips.com
 *         Randy Li, randy.li@rock-chips.com
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
#include <drm/drmP.h>
#include <drm/drm_atomic.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_fb_helper.h>
#include <linux/dma-mapping.h>
#include <asm/dma-iommu.h>
#include <linux/pm_runtime.h>
#include <linux/memblock.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_graph.h>
#include <linux/component.h>
#include <linux/iommu.h>
#include <linux/console.h>
#include <linux/kref.h>
#include <linux/fdtable.h>
#include <linux/ktime.h>
#include <linux/iova.h>
#include <linux/dma-iommu.h>

#include "vcodec_iommu_ops.h"

struct vcodec_drm_buffer {
	struct list_head list;
	struct dma_buf *dma_buf;
	union {
		unsigned long iova;
		unsigned long phys;
	};
	void *cpu_addr;
	unsigned long size;
	int index;
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
	struct page **pages;
	struct kref ref;
	struct vcodec_iommu_session_info *session_info;
	ktime_t last_used;
};

struct vcodec_iommu_drm_info {
	struct iommu_domain *domain;
	bool attached;
};

static struct vcodec_drm_buffer *
vcodec_drm_get_buffer_no_lock(struct vcodec_iommu_session_info *session_info,
			      int idx)
{
	struct vcodec_drm_buffer *drm_buffer = NULL, *n;

	print_enter_func(session_info->dev);
	list_for_each_entry_safe(drm_buffer, n, &session_info->buffer_list,
				 list) {
		if (drm_buffer->index == idx) {
			drm_buffer->last_used = ktime_get();
			return drm_buffer;
		}
	}
	print_exit_func(session_info->dev);
	return NULL;
}

static struct vcodec_drm_buffer *
vcodec_drm_get_buffer_fd_no_lock(struct vcodec_iommu_session_info *session_info,
				 int fd)
{
	struct vcodec_drm_buffer *drm_buffer = NULL, *n;
	struct dma_buf *dma_buf = NULL;

	print_enter_func(session_info->dev);
	dma_buf = dma_buf_get(fd);

	list_for_each_entry_safe(drm_buffer, n, &session_info->buffer_list,
				 list) {
		if (drm_buffer->dma_buf == dma_buf) {
			drm_buffer->last_used = ktime_get();
			dma_buf_put(dma_buf);
			return drm_buffer;
		}
	}

	dma_buf_put(dma_buf);
	print_exit_func(session_info->dev);
	return NULL;
}

static void vcodec_drm_detach(struct vcodec_iommu_info *iommu_info)
{
	struct vcodec_iommu_drm_info *drm_info = iommu_info->private;
	struct device *dev = iommu_info->dev;
	struct iommu_domain *domain = drm_info->domain;

	print_enter_func(iommu_info->dev);
	mutex_lock(&iommu_info->iommu_mutex);

	if (!drm_info->attached) {
		mutex_unlock(&iommu_info->iommu_mutex);
		return;
	}

	iommu_detach_device(domain, dev);
	drm_info->attached = false;

	mutex_unlock(&iommu_info->iommu_mutex);
	print_exit_func(iommu_info->dev);
}

static int vcodec_drm_attach_unlock(struct vcodec_iommu_info *iommu_info)
{
	struct vcodec_iommu_drm_info *drm_info = iommu_info->private;
	struct device *dev = iommu_info->dev;
	struct iommu_domain *domain = drm_info->domain;
	int ret = 0;

	print_enter_func(iommu_info->dev);
	ret = dma_set_coherent_mask(dev, DMA_BIT_MASK(32));
	if (ret)
		return ret;

	dma_set_max_seg_size(dev, DMA_BIT_MASK(32));
	ret = iommu_attach_device(domain, dev);
	if (ret) {
		dev_err(dev, "Failed to attach iommu device\n");
		return ret;
	}

	print_exit_func(iommu_info->dev);
	return ret;
}

static int vcodec_drm_attach(struct vcodec_iommu_info *iommu_info)
{
	struct vcodec_iommu_drm_info *drm_info = iommu_info->private;
	int ret;

	print_enter_func(iommu_info->dev);
	mutex_lock(&iommu_info->iommu_mutex);

	if (drm_info->attached) {
		mutex_unlock(&iommu_info->iommu_mutex);
		return 0;
	}

	ret = vcodec_drm_attach_unlock(iommu_info);
	if (ret) {
		mutex_unlock(&iommu_info->iommu_mutex);
		return ret;
	}

	drm_info->attached = true;

	mutex_unlock(&iommu_info->iommu_mutex);

	print_exit_func(iommu_info->dev);
	return ret;
}

/* Has nothing to do with DRM... AT ALL ! This just VMAP some pages
 * somewhere and return the address. What the fuck... */
static void *vcodec_drm_sgt_map_kernel(struct vcodec_drm_buffer *drm_buffer)
{
	struct vcodec_iommu_session_info *session_info =
		drm_buffer->session_info;
	struct device *dev = session_info->dev;
	struct scatterlist *sgl, *sg;
	int nr_pages = PAGE_ALIGN(drm_buffer->size) >> PAGE_SHIFT;
	int i = 0, j = 0, k = 0;
	struct page *page;

	print_enter_func(dev);
	drm_buffer->pages = kmalloc_array(nr_pages, sizeof(*drm_buffer->pages),
					  GFP_KERNEL);
	if (!(drm_buffer->pages)) {
		dev_err(dev, "drm map can not alloc pages\n");

		return NULL;
	}

	sgl = drm_buffer->sgt->sgl;

	for_each_sg(sgl, sg, drm_buffer->sgt->nents, i) {
		page = sg_page(sg);
		for (j = 0; j < sg->length / PAGE_SIZE; j++)
			drm_buffer->pages[k++] = page++;
	}

	print_exit_func(dev);
	return vmap(drm_buffer->pages, nr_pages, VM_MAP,
		    pgprot_noncached(PAGE_KERNEL));
}

/* Nothing to do with DRM TOO ! */
static void vcodec_drm_sgt_unmap_kernel(struct vcodec_drm_buffer *drm_buffer)
{
	print_enter_func(drm_buffer->session_info->dev);
	vunmap(drm_buffer->cpu_addr);
	kfree(drm_buffer->pages);
	print_exit_func(drm_buffer->session_info->dev);
}

/* ... */
static void vcodec_dma_unmap_sg(struct iommu_domain *domain,
				dma_addr_t dma_addr)
{
	struct iova_domain *iovad = domain->iova_cookie;
	unsigned long shift = iova_shift(iovad);
	unsigned long pfn = dma_addr >> shift;
	struct iova *iova = find_iova(iovad, pfn);
	size_t size;

	if (WARN_ON(!iova))
		return;

	size = iova_size(iova) << shift;
	size -= iommu_unmap(domain, pfn << shift, size);
	/* ...and if we can't, then something is horribly, horribly wrong */
	WARN_ON(size > 0);
	__free_iova(iovad, iova);
	printk(KERN_INFO
		"... Getting out a function that should not be there");
}

/* WhatTheFuckDoesItHaveToDoWithDRM.com */
static void vcodec_drm_clear_map(struct kref *ref)
{
	struct vcodec_drm_buffer *drm_buffer =
		container_of(ref, struct vcodec_drm_buffer, ref);
	struct vcodec_iommu_session_info *session_info =
		drm_buffer->session_info;
	struct vcodec_iommu_info *iommu_info = session_info->iommu_info;
	struct vcodec_iommu_drm_info *drm_info = iommu_info->private;

	print_enter_func(iommu_info->dev);
	mutex_lock(&iommu_info->iommu_mutex);
	drm_info = session_info->iommu_info->private;

	if (drm_buffer->cpu_addr) {
		vcodec_drm_sgt_unmap_kernel(drm_buffer);
		drm_buffer->cpu_addr = NULL;
	}

	if (drm_buffer->attach) {
		vcodec_dma_unmap_sg(drm_info->domain, drm_buffer->iova);
		dma_buf_unmap_attachment(drm_buffer->attach, drm_buffer->sgt,
					 DMA_BIDIRECTIONAL);
		dma_buf_detach(drm_buffer->dma_buf, drm_buffer->attach);
		dma_buf_put(drm_buffer->dma_buf);
		drm_buffer->attach = NULL;
	}

	mutex_unlock(&iommu_info->iommu_mutex);
	print_exit_func(iommu_info->dev);
}

/* This just dump buffers and their addresses */
static void vcodec_drm_dump_info(struct vcodec_iommu_session_info *session_info)
{
	struct vcodec_drm_buffer *drm_buffer = NULL, *n;

	print_enter_func(session_info->dev);

	vpu_iommu_debug(session_info->debug_level, DEBUG_IOMMU_OPS_DUMP,
			"still there are below buffers stored in list\n");
	list_for_each_entry_safe(drm_buffer, n, &session_info->buffer_list,
				 list) {
		vpu_iommu_debug(session_info->debug_level, DEBUG_IOMMU_OPS_DUMP,
				"index %d drm_buffer dma_buf %p cpu_addr %p\n",
				drm_buffer->index,
				drm_buffer->dma_buf, drm_buffer->cpu_addr);
	}
	print_exit_func(session_info->dev);
}

/* This just frees some session infos and put back the DRM Buffer it
 * gots earlier, for what ever fucking reason it needed it.
 * Don't GUESS ! Seriously ! Guessing things with this driver
 * will lead you to a wall !
 */
static int vcodec_drm_free(struct vcodec_iommu_session_info *session_info,
			   int idx)
{
	struct device *dev = session_info->dev;
	/* please double-check all maps have been release */
	struct vcodec_drm_buffer *drm_buffer;

	print_enter_func(dev);
	mutex_lock(&session_info->list_mutex);
	drm_buffer = vcodec_drm_get_buffer_no_lock(session_info, idx);

	if (!drm_buffer) {
		dev_err(dev, "can not find %d buffer in list\n", idx);
		mutex_unlock(&session_info->list_mutex);

		return -EINVAL;
	}

	if (refcount_read(&drm_buffer->ref.refcount) == 0) {
		dma_buf_put(drm_buffer->dma_buf);
		list_del_init(&drm_buffer->list);
		kfree(drm_buffer);
		session_info->buffer_nums--;
		vpu_iommu_debug(session_info->debug_level, DEBUG_IOMMU_NORMAL,
				"buffer nums %d\n", session_info->buffer_nums);
	}
	mutex_unlock(&session_info->list_mutex);

	print_exit_func(dev);
	return 0;
}

/* How many unmap and free functions does this thing needs.
 * Nothing to do with DRM anyway.
 */
static int
vcodec_drm_unmap_iommu(struct vcodec_iommu_session_info *session_info,
		       int idx)
{
	struct device *dev = session_info->dev;
	struct vcodec_drm_buffer *drm_buffer;

	print_enter_func(dev);
	/* Force to flush iommu table */
	/* No public Rockchip IOMMU function provides this functionnality
	 * it seems...
	 * TODO Make the "zap" functions of the Rockchip IOMMU code public ?
	 * -- Myy
	 */
	/*if (of_machine_is_compatible("rockchip,rk3288"))
		rockchip_iovmm_invalidate_tlb(session_info->mmu_dev);*/

	mutex_lock(&session_info->list_mutex);
	drm_buffer = vcodec_drm_get_buffer_no_lock(session_info, idx);
	mutex_unlock(&session_info->list_mutex);

	if (!drm_buffer) {
		dev_err(dev, "can not find %d buffer in list\n", idx);
		return -EINVAL;
	}

	kref_put(&drm_buffer->ref, vcodec_drm_clear_map);

	print_exit_func(dev);
	return 0;
}

/* Is this thing reimplementing everything by itself ? */
static int vcodec_drm_map_iommu(struct vcodec_iommu_session_info *session_info,
				int idx,
				unsigned long *iova,
				unsigned long *size)
{
	struct device *dev = session_info->dev;
	struct vcodec_drm_buffer *drm_buffer;

	print_enter_func(dev);
	/* Force to flush iommu table */
	/* No public Rockchip IOMMU function provides this functionnality
	 * it seems...
	 * TODO Make the "zap" functions of the Rockchip IOMMU code public ?
	 * -- Myy
	 */
	/*if (of_machine_is_compatible("rockchip,rk3288"))
		rockchip_iovmm_invalidate_tlb(session_info->mmu_dev);*/

	mutex_lock(&session_info->list_mutex);
	drm_buffer = vcodec_drm_get_buffer_no_lock(session_info, idx);
	dev_info(dev,
		"( Myy ) vcodec_drm_get_buffer_no_lock(%p, %d) → %p",
		session_info, idx, drm_buffer);
	mutex_unlock(&session_info->list_mutex);

	if (!drm_buffer) {
		dev_err(dev, "can not find %d buffer in list\n", idx);
		return -EINVAL;
	}

	kref_get(&drm_buffer->ref);
	if (iova)
		*iova = drm_buffer->iova;
	if (size)
		*size = drm_buffer->size;

	print_exit_func(dev);
	return 0;
}

static int
vcodec_drm_unmap_kernel(struct vcodec_iommu_session_info *session_info, int idx)
{
	struct device *dev = session_info->dev;
	struct vcodec_drm_buffer *drm_buffer;

	print_enter_func(dev);
	mutex_lock(&session_info->list_mutex);
	drm_buffer = vcodec_drm_get_buffer_no_lock(session_info, idx);
	mutex_unlock(&session_info->list_mutex);

	if (!drm_buffer) {
		dev_err(dev, "can not find %d buffer in list\n", idx);

		return -EINVAL;
	}

	if (drm_buffer->cpu_addr) {
		vcodec_drm_sgt_unmap_kernel(drm_buffer);
		drm_buffer->cpu_addr = NULL;
	}

	kref_put(&drm_buffer->ref, vcodec_drm_clear_map);

	print_exit_func(dev);
	return 0;
}

/* ?? Free FD ? Who asks for that ? The user ? Or the VPU itself ? */
static int
vcodec_drm_free_fd(struct vcodec_iommu_session_info *session_info, int fd)
{
	struct device *dev = session_info->dev;
	/* please double-check all maps have been release */
	struct vcodec_drm_buffer *drm_buffer = NULL;

	print_enter_func(dev);
	mutex_lock(&session_info->list_mutex);
	drm_buffer = vcodec_drm_get_buffer_fd_no_lock(session_info, fd);

	if (!drm_buffer) {
		dev_err(dev, "can not find %d buffer in list\n", fd);
		mutex_unlock(&session_info->list_mutex);

		return -EINVAL;
	}
	mutex_unlock(&session_info->list_mutex);

	vcodec_drm_unmap_iommu(session_info, drm_buffer->index);

	mutex_lock(&session_info->list_mutex);
	if (refcount_read(&drm_buffer->ref.refcount) == 0) {
		dma_buf_put(drm_buffer->dma_buf);
		list_del_init(&drm_buffer->list);
		kfree(drm_buffer);
		session_info->buffer_nums--;
		vpu_iommu_debug(session_info->debug_level, DEBUG_IOMMU_NORMAL,
				"buffer nums %d\n", session_info->buffer_nums);
	}
	mutex_unlock(&session_info->list_mutex);

	print_exit_func(dev);
	return 0;
}

static void
vcodec_drm_clear_session(struct vcodec_iommu_session_info *session_info)
{
	struct vcodec_drm_buffer *drm_buffer = NULL, *n;

	print_enter_func(session_info->dev);
	list_for_each_entry_safe(drm_buffer, n, &session_info->buffer_list,
				 list) {
		kref_put(&drm_buffer->ref, vcodec_drm_clear_map);
		vcodec_drm_free(session_info, drm_buffer->index);
	}
	print_exit_func(session_info->dev);
}

static void *
vcodec_drm_map_kernel(struct vcodec_iommu_session_info *session_info, int idx)
{
	struct device *dev = session_info->dev;
	struct vcodec_drm_buffer *drm_buffer;

	print_enter_func(dev);
	mutex_lock(&session_info->list_mutex);
	drm_buffer = vcodec_drm_get_buffer_no_lock(session_info, idx);
	mutex_unlock(&session_info->list_mutex);

	if (!drm_buffer) {
		dev_err(dev, "can not find %d buffer in list\n", idx);
		return NULL;
	}

	if (!drm_buffer->cpu_addr)
		drm_buffer->cpu_addr =
			vcodec_drm_sgt_map_kernel(drm_buffer);

	kref_get(&drm_buffer->ref);

	print_exit_func(dev);
	return drm_buffer->cpu_addr;
}

/* I still have no idea what this part wants to do.
 * Seriously, this is named DRM import but remember that we're inside
 * the VPU driver !
 * So who imports WHAT and WHY ? Is the VPU importing the DRM buffer ?
 * Or does this code tries to make the DRM driver imports its buffers ?
 */
static int vcodec_drm_import(struct vcodec_iommu_session_info *session_info,
			     int fd)
{
	struct vcodec_drm_buffer *drm_buffer = NULL, *n;
	struct vcodec_drm_buffer *oldest_buffer = NULL, *loop_buffer = NULL;
	struct vcodec_iommu_info *iommu_info = session_info->iommu_info;
	struct vcodec_iommu_drm_info *drm_info = iommu_info->private;
	struct device *dev = session_info->dev;
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
	struct dma_buf *dma_buf;
	ktime_t oldest_time = ktime_set(0, 0);
	int ret = 0;

	print_enter_func(dev);

	/* Gets the buffer attached to the FD. The user is using PRIME
	 * so we're sure that the FD represents a DMA Buffer.
	 * Still, why not use PRIME functions directly ?
	 * This is old code though...
	 */
	dma_buf = dma_buf_get(fd);
	if (IS_ERR(dma_buf)) {
		ret = PTR_ERR(dma_buf);
		return ret;
	}

	/* So it tries to find its DMA Buffer back !? And if it finds it,
	 * the code puts the second reference it got previously and return
	 * the index of the found buffer ??
	 */
	list_for_each_entry_safe(drm_buffer, n,
				 &session_info->buffer_list, list) {
		if (drm_buffer->dma_buf == dma_buf) {
			dma_buf_put(dma_buf);
			drm_buffer->last_used = ktime_get();
			return drm_buffer->index;
		}
	}

	/* If we're here, he didn't find the DMA buffer in its buffer list
	 * So it allocates a new "DRM Buffer" that has nothing to do with
	 * DRM besides the name...
	 * Remember that we're always in the VPU code !
	 */
	drm_buffer = kzalloc(sizeof(*drm_buffer), GFP_KERNEL);
	dev_info(dev, "( Myy ) kzalloc(%d, GFP_KERNEL) → %p\n",
		sizeof(*drm_buffer), drm_buffer);
	if (!drm_buffer) {
		ret = -ENOMEM;
		return ret;
	}

	/* Store the address of the DMA buffer in the DRM Buffer structure */
	drm_buffer->dma_buf = dma_buf;
	drm_buffer->session_info = session_info;
	drm_buffer->last_used = ktime_get();

	/* Initialize a kernel reference structure... ??? Why... */
	kref_init(&drm_buffer->ref);

	/* Hold and Lock a mutex. Careful IOMMU Info is some hand-made
	 * structure that has barefly anything to do with IOMMU. Don't
	 * get started.
	 */
	mutex_lock(&iommu_info->iommu_mutex);

	/* Told you ! */
	drm_info = session_info->iommu_info->private;

	/* Attach the exported DMA Buffer to the VPU device */
	attach = dma_buf_attach(drm_buffer->dma_buf, dev);
	if (IS_ERR(attach)) {
		ret = PTR_ERR(attach);
		goto fail_out;
	}

	/* And then get the buffer again... ??? */
	get_dma_buf(drm_buffer->dma_buf);

	/* Map the attachment to start using it. This will be provide the
	 * Scatter-Gather holding the content of the the DMA Buffer.
	 */
	sgt = dma_buf_map_attachment(attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(sgt)) {
		ret = PTR_ERR(sgt);
		goto fail_detach;
	}

	/* Let's see if you understand the next comment */
	/*
	 * Since we call dma_buf_map_attachment outside attach/detach, this
	 * will cause incorrectly map. we have to re-build map table native
	 * and for avoiding destroy their origin map table, we need use a
	 * copy one sg_table.
	 */
	
	/* Did you get it ? Because I don't ! What table is he talking about ?
	 * The IOMMU Translation table ??
	 * Note that the copy is INSANE ! We just allocated a DMA buffer,
	 * made sure that everything is attached correctly to the right
	 * devices... All of that and we copy data into a non DMA memory
	 * space !?
	 * Code dropped. See the Git history for details.
	 */

	/* ... */

	// The real problem
	// iommu_get_domain_for_dev NEVER works...
	/*if (iommu_get_domain_for_dev(iommu_info->dev) == NULL)
		dev_err(iommu_info->dev,
			"How about initializing the IOMMU domain, you idiot\n");*/

	// The crash
	// So we can't use iommu_dma_map_sg...

	/* Wasn't the DMA Buffer already mapped ? What is this thing trying
	 * to map again ? How many times must you map something to get it
	 * mapped correctly ? What is the IOMMU doing here anyway ?
	 * Who ate my sandwich ?
	 */
	/*ret = myy_iommu_dma_map_sg(drm_info->domain,
		iommu_info->dev, sgt->sgl, sgt->nents,
		IOMMU_READ | IOMMU_WRITE);

	if (!ret) {
		ret = -ENOMEM;
		goto fail_alloc;
	}*/
	/* What happen if I comment this ? */

	/* Set up the "drm_buffer" data structure with informations like the
	 * IO Virtual Address of the Scatter-Gather list, the size of the
	 * DMA Buffer, the attachment, ...
	 */
	drm_buffer->iova = sg_dma_address(sgt->sgl);
	drm_buffer->size = drm_buffer->dma_buf->size;

	drm_buffer->attach = attach;
	drm_buffer->sgt = sgt;

	/* Unlock our Mutex ! */
	mutex_unlock(&iommu_info->iommu_mutex);

	/* Initialize a list... */
	INIT_LIST_HEAD(&drm_buffer->list);

	/* Lock the session Mutex this time ... ? */
	mutex_lock(&session_info->list_mutex);

	/* Increment the number of buffers in the session !
	 * Did we store anything in it ? */
	session_info->buffer_nums++;

	vpu_iommu_debug(session_info->debug_level, DEBUG_IOMMU_NORMAL,
			"buffer nums %d\n", session_info->buffer_nums);

	/* This... remove buffers when there's too much buffers ? */
	if (session_info->buffer_nums > BUFFER_LIST_MAX_NUMS) {
		list_for_each_entry_safe(loop_buffer, n,
				 &session_info->buffer_list, list) {
			if (ktime_to_ns(oldest_time) == 0 ||
			    ktime_after(oldest_time,
					loop_buffer->last_used)) {
				oldest_time = loop_buffer->last_used;
				oldest_buffer = loop_buffer;
			}
		}
		kref_put(&oldest_buffer->ref, vcodec_drm_clear_map);
		dma_buf_put(oldest_buffer->dma_buf);
		list_del_init(&oldest_buffer->list);
		kfree(oldest_buffer);
		session_info->buffer_nums--;
	}

	/* Set the current index of this buffer */
	drm_buffer->index = session_info->max_idx;

	/* Add the "DRM" Buffer list to the session buffer list */
	list_add_tail(&drm_buffer->list, &session_info->buffer_list);

	/* Increment the next index */
	session_info->max_idx++;

	/* What the fuck... if max_idx = 0 then set max_idx to 0
	 * Of course...
	 * Is there a reason to make max_idx a "signed" int by the way ?
	 */
	if ((session_info->max_idx & 0xfffffff) == 0)
		session_info->max_idx = 0;

	/* Unlock our session mutex ! */
	mutex_unlock(&session_info->list_mutex);

	print_exit_func(dev);

	/* Return our buffer index ! */
	return drm_buffer->index;

	/* Error management. Nothing in this fucking function had anything
	 * to do with DRM... */
fail_alloc:
	dma_buf_unmap_attachment(attach, sgt,
				 DMA_BIDIRECTIONAL);
fail_detach:
	dma_buf_detach(drm_buffer->dma_buf, attach);
	dma_buf_put(drm_buffer->dma_buf);
fail_out:
	kfree(drm_buffer);
	mutex_unlock(&iommu_info->iommu_mutex);

	print_exit_func_with_issue(dev);
	return ret;
}

static int vcodec_drm_create(struct vcodec_iommu_info *iommu_info)
{
	struct vcodec_iommu_drm_info *drm_info;
	int ret;

	print_enter_func(iommu_info->dev);
	iommu_info->private = kzalloc(sizeof(*drm_info),
				      GFP_KERNEL);
	drm_info = iommu_info->private;
	if (!drm_info)
		return -ENOMEM;

	drm_info->domain = iommu_domain_alloc(&platform_bus_type);
	drm_info->attached = false;
	if (!drm_info->domain)
		return -ENOMEM;

	ret = iommu_get_dma_cookie(drm_info->domain);
	if (ret)
		goto err_free_domain;

	ret = iommu_dma_init_domain(drm_info->domain, 0x10000000, SZ_2G, iommu_info->dev);
	dev_info(iommu_info->dev, "iommu_dma_init_domain → %d\n", ret);

	print_exit_func(iommu_info->dev);
	return 0;

err_free_domain:
	iommu_domain_free(drm_info->domain);

	print_exit_func_with_issue(iommu_info->dev);
	return ret;
}

static int vcodec_drm_destroy(struct vcodec_iommu_info *iommu_info)
{
	struct vcodec_iommu_drm_info *drm_info = iommu_info->private;

	print_enter_func(iommu_info->dev);
	iommu_put_dma_cookie(drm_info->domain);

	iommu_domain_free(drm_info->domain);

	kfree(drm_info);
	iommu_info->private = NULL;

	print_exit_func(iommu_info->dev);
	return 0;
}

static struct vcodec_iommu_ops drm_ops = {
	.create = vcodec_drm_create,
	.import = vcodec_drm_import,
	.free = vcodec_drm_free,
	.free_fd = vcodec_drm_free_fd,
	.map_kernel = vcodec_drm_map_kernel,
	.unmap_kernel = vcodec_drm_unmap_kernel,
	.map_iommu = vcodec_drm_map_iommu,
	.unmap_iommu = vcodec_drm_unmap_iommu,
	.destroy = vcodec_drm_destroy,
	.dump = vcodec_drm_dump_info,
	.attach = vcodec_drm_attach,
	.detach = vcodec_drm_detach,
	.clear = vcodec_drm_clear_session,
};

void vcodec_iommu_drm_set_ops(struct vcodec_iommu_info *iommu_info)
{
	if (!iommu_info)
		return;
	iommu_info->ops = &drm_ops;
}
