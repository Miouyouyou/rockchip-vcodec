/**
 * Copyright (C) 2016 - 2017 Fuzhou Rockchip Electronics Co., Ltd
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

#ifndef _ROCKCHIP_MPP_DEV_COMMON_H_
#define _ROCKCHIP_MPP_DEV_COMMON_H_

#include <linux/cdev.h>
#include <linux/dma-buf.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/reset.h>

#define MPP_DEVICE_NAME				"mpp_device"

#define MPP_IOC_CUSTOM_BASE			0x1000

#define EXTRA_INFO_MAGIC			0x4C4A46

struct mpp_trans_info {
	const int count;
	const char * const table;
};

struct extra_info_elem {
	u32 index;
	u32 offset;
};

struct extra_info_for_iommu {
	u32 magic;
	u32 cnt;
	struct extra_info_elem elem[20];
};

struct mpp_dev_variant {
	u32 reg_len;
	struct mpp_trans_info *trans_info;
	const char *node_name;
};

struct mpp_mem_region {
	struct list_head srv_lnk;
	struct list_head reg_lnk;
	struct list_head session_lnk;
	/* virtual address for iommu */
	dma_addr_t iova;
	unsigned long len;
	u32 reg_idx;
	void *hdl;
};

/* Definition in dma file */
struct mpp_dma_session;
/* Definition in mpp service file */
struct mpp_service;

struct rockchip_mpp_dev {
	struct device *dev;

	const struct mpp_dev_variant *variant;
	struct mpp_dev_ops *ops;

	void __iomem *reg_base;
	int irq;
	struct workqueue_struct *irq_workq;

	struct mpp_iommu_info *iommu_info;
	rwlock_t resource_rwlock;
	atomic_t reset_request;

	struct cdev mpp_cdev;
	dev_t dev_id;

	/* MPP Service */
	struct mpp_service *srv;
	struct list_head lnk_service;
};

struct mpp_session {
	/* the session related device private data */
	struct rockchip_mpp_dev *mpp;
	/* a linked list of data so we can access them for debugging */
	struct list_head list_session;
	struct mpp_dma_session *dma;

	struct list_head pending;
	struct list_head done;
	wait_queue_head_t wait;
	pid_t pid;
	atomic_t task_running;
};

/* The context for the a task */
struct mpp_task {
	/* context belong to */
	struct mpp_session *session;

	/* link to service session */
	struct list_head session_link;
	/* link to service list */
	struct list_head status_link;
	/* The DMA buffer used in this task */
	struct list_head mem_region_list;
	struct work_struct work;

	/* record context running start time */
	struct timeval start;
};

/*
 * struct mpp_dev_ops - context specific operations for a device
 * The task part
 * @alloc_task
 * @prepare	Check HW status for determining run next task or not.
 * @run		Start a single {en,de}coding run. Set registers to hardware.
 * @finish	Read back processing results and additional data from hardware.
 * @result	Read status to userspace.
 * @free_task	Release the resource allocate during init.
 * The device part
 * @reset
 */
struct mpp_dev_ops {
	/* size: in bytes, data sent from userspace, length in bytes */
	void *(*alloc_task)(struct mpp_session *session,
			    void __user *src, u32 size);
	int (*prepare)(struct rockchip_mpp_dev *mpp_dev, struct mpp_task *task);
	int (*run)(struct rockchip_mpp_dev *mpp_dev, struct mpp_task *task);
	int (*finish)(struct rockchip_mpp_dev *mpp_dev, struct mpp_task *task);
	int (*result)(struct rockchip_mpp_dev *mpp_dev, struct mpp_task *task,
		      u32 __user *dst, u32 size);
	int (*free_task)(struct mpp_session *session,
			    struct mpp_task *task);
	/* Hardware only operations */
	int (*reset)(struct rockchip_mpp_dev *mpp_dev);
};

struct mpp_mem_region *mpp_dev_task_attach_fd(struct mpp_task *task, int fd);
int mpp_reg_address_translate(struct rockchip_mpp_dev *data,
			      struct mpp_task *task, int fmt, u32 *reg);
void mpp_translate_extra_info(struct mpp_task *task,
			      struct extra_info_for_iommu *ext_inf,
			      u32 *reg);

int mpp_dev_task_init(struct mpp_session *session, struct mpp_task *task);
void mpp_dev_task_finish(struct mpp_session *session, struct mpp_task *task);
void mpp_dev_task_finalize(struct mpp_session *session, struct mpp_task *task);

void mpp_dev_power_on(struct rockchip_mpp_dev *mpp);
void mpp_dev_power_off(struct rockchip_mpp_dev *mpp);
bool mpp_dev_is_power_on(struct rockchip_mpp_dev *mpp);

void mpp_dump_reg(void __iomem *regs, int count);
void mpp_dump_reg_mem(u32 *regs, int count);

/* It can handle the default ioctl */
long mpp_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
long mpp_dev_compat_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg);
#endif

int mpp_dev_common_probe(struct rockchip_mpp_dev *mpp_dev,
			 struct platform_device *pdev,
			 struct mpp_dev_ops *ops);
int mpp_dev_register_node(struct rockchip_mpp_dev *mpp_dev,
			  const char *node_name, const void *fops);
int mpp_dev_common_remove(struct rockchip_mpp_dev *mpp_dev);

static inline void safe_reset(struct reset_control *rst)
{
	if (rst)
		reset_control_assert(rst);
}

static inline void safe_unreset(struct reset_control *rst)
{
	if (rst)
		reset_control_deassert(rst);
}

void mpp_dev_write_seq(struct rockchip_mpp_dev *mpp_dev,
			      unsigned long offset, void *buffer,
			      unsigned long count);

void mpp_dev_write(struct rockchip_mpp_dev *mpp, u32 val, u32 reg);

void mpp_dev_read_seq(struct rockchip_mpp_dev *mpp_dev,
			     unsigned long offset, void *buffer,
			     unsigned long count);

u32 mpp_dev_read(struct rockchip_mpp_dev *mpp, u32 reg);

void mpp_debug_time_record(struct mpp_task *task);
void mpp_debug_time_diff(struct mpp_task *task);

void mpp_debug_dump_reg(void __iomem *regs, int count);
void mpp_debug_dump_reg_mem(u32 *regs, int count);

/* Added there as a temporary measure - Myy */
int rockchip_pmu_idle_request(struct device *dev, bool idle);

#endif
