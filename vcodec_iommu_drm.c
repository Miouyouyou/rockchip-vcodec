/* Myy - Mimicking the ION driver architecture to create a dumb DRM
 *       driver.
 * This won't compile for the moment.
 * Even if it compiles, expect it to blow up in ways you can't expect.
 */

/* Functions that do not exist in the mainline kernel :
 * static int rk_ion_get_phys(struct ion_client *client,
 * 			   unsigned long arg)
 * {
 * 	struct ion_phys_data data;
 * 	struct ion_handle *handle;
 * 	int ret;
 * 
 * 	if (copy_from_user(&data, (void __user *)arg,
 * 				sizeof(struct ion_phys_data)))
 * 		return -EFAULT;
 * 
 * 	handle = ion_handle_get_by_id(client, data.handle);
 * 	if (IS_ERR(handle))
 * 		return PTR_ERR(handle);
 * 
 * 	ret = ion_phys(client, handle, &data.phys,
 * 					(size_t *)&data.size);
 * 	ion_handle_put(handle);
 * 	if (ret < 0)
 * 		return ret;
 * 	if (copy_to_user((void __user *)arg, &data,
 * 			sizeof(struct ion_phys_data)))
 * 		return -EFAULT;
 * 
 * 	return 0;
 * }
 *
 * static long rk_custom_ioctl(struct ion_client *client,
 * 			    unsigned int cmd,
 * 			    unsigned long arg)
 * {
 * 	int ret = 0;
 * 
 * 	switch (cmd) {
 * 	case ION_IOC_GET_PHYS:
 * 		ret = rk_ion_get_phys(client, arg);
 * 		break;
 * 	default:
 * 		return -ENOTTY;
 * 	}
 * 
 * 	return ret;
 * }
 * 
 * ion_device -> ion_create_device(rk_custom_ioctl);
 * rockchip_ion_client_create(name) -> ion_client_create(ion_device, name);
 */
#include <linux/rockchip-iovmm.h>
#include <linux/slab.h>
#include <linux/pm_runtime.h>
#include <linux/memblock.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_graph.h>
#include <linux/component.h>
#include <linux/fence.h>
#include <linux/console.h>
#include <linux/kref.h>
#include <linux/fdtable.h>

#include "vcodec_iommu_ops.h"

struct vcodec_drm_buffer {
	struct list_head list;
	uint32_t handle;
	int index;
};

struct vcodec_iommu_drm_info {
	struct drm_client *drm_client;
	bool attached;
};

/* Just driver specific. Nothing to do with DRM per-se. */
static struct vcodec_drm_buffer *
vcodec_standard_get_buffer_no_lock
(struct vcodec_iommu_sessdrm_info * sessdrm_info, int idx)
{
	struct vcodec_drm_buffer *drm_buffer = NULL, *n;

	/* Can't we just use GEM naming facilities to get the right buffer
	 * each time ? */
	list_for_each_entry_safe(drm_buffer, n,
				 &sessdrm_info->buffer_list, list) {
		if (drm_buffer->index == idx)
			return drm_buffer;
	}

	return NULL;
}

/* Not DRM specific */
static void vcodec_standard_clear_session
(struct vcodec_iommu_sessdrm_info *sessdrm_info)
{
	/* do nothing */
}

/* Not ION specific ? */
static int vcodec_standard_attach(struct vcodec_iommu_info *iommu_info)
{
	struct vcodec_iommu_drm_info *drm_info = iommu_info->private;
	int ret;

	mutex_lock(&iommu_info->iommu_mutex);

	if (drm_info->attached) {
		mutex_unlock(&iommu_info->iommu_mutex);
		return 0;
	}

	/* Get and store the iommu domain somehow */
	iommu_attach_device(iommu_domain, iommu_info->dev);

	drm_info->attached = true;

	mutex_unlock(&iommu_info->iommu_mutex);

	return ret;
}

static void vcodec_standard_detach(struct vcodec_iommu_info *iommu_info)
{
	struct vcodec_iommu_drm_info *drm_info = iommu_info->private;

	mutex_lock(&iommu_info->iommu_mutex);

	if (!drm_info->attached) {
		mutex_unlock(&iommu_info->iommu_mutex);
		return;
	}

	/* Get and store the iommu domain somehow */
	iommu_detach_device(iommu_domain, iommu_info->dev);
	drm_info->attached = false;

	mutex_unlock(&iommu_info->iommu_mutex);
}

static int vcodec_standard_destroy(struct vcodec_iommu_info *iommu_info)
{
	struct vcodec_iommu_drm_info *drm_info = iommu_info->private;

	vcodec_standard_detach(iommu_info);
	kfree(drm_info);
	iommu_info->private = NULL;

	return 0;
}

static int vcodec_standard_free
(struct vcodec_iommu_sessdrm_info *sessdrm_info, int idx)
{
	struct vcodec_drm_buffer *drm_buffer;

	mutex_lock(&sessdrm_info->list_mutex);
	drm_buffer = vcodec_drm_get_buffer_no_lock(sessdrm_info, idx);

	if (!drm_buffer) {
		mutex_unlock(&sessdrm_info->list_mutex);
		pr_err("%s can not find %d buffer in list\n", __func__, idx);

		return -EINVAL;
	}

	list_del_init(&drm_buffer->list);
	mutex_unlock(&sessdrm_info->list_mutex);
	kfree(drm_buffer);

	return 0;
}

/* ION speficic : drm_free(drm_client, drm_handle) */
static int
vcodec_drm_unmap_iommu(struct vcodec_iommu_sessdrm_info *sessdrm_info, int idx)
{
	struct vcodec_drm_buffer *drm_buffer;
	struct vcodec_iommu_info *iommu_info = sessdrm_info->iommu_info;
	struct vcodec_iommu_drm_info *drm_info = iommu_info->private;

	mutex_lock(&sessdrm_info->list_mutex);
	drm_buffer = vcodec_drm_get_buffer_no_lock(sessdrm_info, idx);
	mutex_unlock(&sessdrm_info->list_mutex);

	if (!drm_buffer) {
		pr_err("%s can not find %d buffer in list\n", __func__, idx);

		return -EINVAL;
	}

	/* Was ion_free of course. */
	drm_prime_throw_that_away(drm_info->drm_client, drm_buffer->handle);

	return 0;
}

static int
vcodec_drm_map_iommu(struct vcodec_iommu_sessdrm_info *sessdrm_info, int idx,
		     unsigned long *iova, unsigned long *size)
{
	struct vcodec_drm_buffer *drm_buffer;
	struct device *dev = sessdrm_info->dev;
	struct vcodec_iommu_info *iommu_info = sessdrm_info->iommu_info;
	struct vcodec_iommu_drm_info *drm_info = iommu_info->private;
	int ret = 0;

	/* Force to flush iommu table
	 * Was :
	 * rockchip_iovmm_invalidate_tlb(sessdrm_info->dev);
	 * Which roughly equates to :
	 * rk_iommu_base_command(iommu->bases[i], RK_MMU_CMD_ZAP_CACHE);
	 * Solution :
	 * ???
	 */
  
	mutex_lock(&sessdrm_info->list_mutex);
	drm_buffer = vcodec_drm_get_buffer_no_lock(sessdrm_info, idx);
	mutex_unlock(&sessdrm_info->list_mutex);

	if (!drm_buffer) {
		pr_err("%s can not find %d buffer in list\n", __func__, idx);

		return -EINVAL;
	}

	/* Turns out that the previous function ion_map_iommu was added
	 * by Rockchip themselves...
	 * It's not a standard function. That said, in the end, the point is
	 * Call iommu_map on the ION device.
	 */
	ret = iommu_map(drm_dev, iova, size); // very roughly...

	return ret;
}

/* Not ION specific */
static int
vcodec_drm_unmap_kernel(struct vcodec_iommu_sessdrm_info *sessdrm_info,
			int idx)
{
	struct vcodec_drm_buffer *drm_buffer;

	mutex_lock(&sessdrm_info->list_mutex);
	drm_buffer = vcodec_drm_get_buffer_no_lock(sessdrm_info, idx);
	mutex_unlock(&sessdrm_info->list_mutex);

	if (!drm_buffer) {
		pr_err("%s can not find %d buffer in list\n", __func__, idx);

		return -EINVAL;
	}

	return 0;
}

/* ION Specific :
 * - drm_map_kernel(drm_client, drm_handle);
 */
static void *
vcodec_drm_map_kernel(struct vcodec_iommu_sessdrm_info *sessdrm_info, int idx)
{
	struct vcodec_drm_buffer *drm_buffer;
	struct vcodec_iommu_info *iommu_info = sessdrm_info->iommu_info;
	struct vcodec_iommu_drm_info *drm_info = iommu_info->private;

	rockchip_iovmm_invalidate_tlb(sessdrm_info->dev);

	mutex_lock(&sessdrm_info->list_mutex);
	drm_buffer = get_buffer_no_lock(sessdrm_info, idx);
	mutex_unlock(&sessdrm_info->list_mutex);

	if (!drm_buffer) {
		pr_err("%s can not find %d buffer in list\n", __func__, idx);

		return NULL;
	}

	return drm_map_kernel(drm_info->drm_client, drm_buffer->handle);
}

/* ION Specific :
 * - drm_import_dma_buf(drm_client, fd);
 */
static int
vcodec_drm_import(struct vcodec_iommu_sessdrm_info *sessdrm_info, int fd)
{
	struct vcodec_drm_buffer *drm_buffer = NULL;
	struct vcodec_iommu_info *iommu_info = sessdrm_info->iommu_info;
	struct vcodec_iommu_drm_info *drm_info = iommu_info->private;
	struct dma_buf * buf_buf = dma_buf_from(fd);

	drm_buffer = kzalloc(sizeof(*drm_buffer), GFP_KERNEL);
	if (!drm_buffer)
		return -ENOMEM;

	/* It's not the right function but it's similar. */
	drm_buffer->handle = 
		drm_gem_import_dma_buf(drm_info->drm_client, buf_buf);

	INIT_LIST_HEAD(&drm_buffer->list);
	mutex_lock(&sessdrm_info->list_mutex);
	drm_buffer->index = sessdrm_info->max_idx;
	list_add_tail(&drm_buffer->list, &sessdrm_info->buffer_list);
	sessdrm_info->max_idx++;
	mutex_unlock(&sessdrm_info->list_mutex);

	return drm_buffer->index;
}

static int vcodec_drm_create(struct vcodec_iommu_info *iommu_info)
{
	struct vcodec_iommu_drm_info *drm_info;

	iommu_info->private = kmalloc(sizeof(*drm_info), GFP_KERNEL);

	drm_info = iommu_info->private;
	if (!drm_info)
		return -ENOMEM;

	drm_info->drm_client = drm_prime_create_a_client_please();
	drm_info->attached = false;

	vcodec_drm_attach(iommu_info);

	return IS_ERR(drm_info->drm_client) ? -1 : 0;
}

static struct vcodec_iommu_ops drm_ops = {
	.create = vcodec_drm_create,
	.destroy = vcodec_drm_destroy,
	.import = vcodec_drm_import,
	.free = vcodec_drm_free,
	.free_fd = NULL,
	.map_kernel = vcodec_drm_map_kernel,
	.unmap_kernel = vcodec_drm_unmap_kernel,
	.map_iommu = vcodec_drm_map_iommu,
	.unmap_iommu = vcodec_drm_unmap_iommu,
	.dump = NULL,
	.attach = vcodec_drm_attach,
	.detach = vcodec_drm_detach,
	.clear = vcodec_drm_clear_session,
};

/*
 * we do not manage the ref number ourselves,
 * since ion will help us to do that. what we
 * need to do is just map/unmap and import/free
 * every time
 */
void vcodec_iommu_drm_set_ops(struct vcodec_iommu_info *iommu_info)
{
	if (!iommu_info)
		return;
	iommu_info->ops = &drm_ops;
}
