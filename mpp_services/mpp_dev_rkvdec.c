/*
 * Copyright (C) 2017 Fuzhou Rockchip Electronics Co., Ltd
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

#include <asm/cacheflush.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/of_platform.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/dma-buf.h>

#include "mpp_debug.h"
#include "mpp_dev_common.h"

#define RKVDEC_DRIVER_NAME		"mpp_rkvdec"

#define RKVDEC_NODE_NAME		"rkvdec"
#define RK_HEVCDEC_NODE_NAME		"hevc-service"

/* The maximum registers number of all the version */
#define ROCKCHIP_RKVDEC_REG_NUM			(109)

#define RKVDEC_REG_DEC_INT_EN			0x004
#define RKVDEC_REG_DEC_INT_EN_INDEX		(1)
#define		RKVDEC_WR_DDR_ALIGN_EN		BIT(23)
#define		RKVDEC_FORCE_SOFT_RESET_VALID	BIT(21)
#define		RKVDEC_SOFTWARE_RESET_EN	BIT(20)
#define		RKVDEC_INT_COLMV_REF_ERROR	BIT(17)
#define		RKVDEC_INT_BUF_EMPTY		BIT(16)
#define		RKVDEC_INT_TIMEOUT		BIT(15)
#define		RKVDEC_INT_STRM_ERROR		BIT(14)
#define		RKVDEC_INT_BUS_ERROR		BIT(13)
#define		RKVDEC_DEC_INT_RAW		BIT(9)
#define		RKVDEC_DEC_INT			BIT(8)
#define		RKVDEC_DEC_TIMEOUT_EN		BIT(5)
#define		RKVDEC_DEC_IRQ_DIS		BIT(4)
#define		RKVDEC_CLOCK_GATE_EN		BIT(1)
#define		RKVDEC_DEC_START		BIT(0)

#define RKVDEC_REG_SYS_CTRL			0x008
#define RKVDEC_REG_SYS_CTRL_INDEX		(2)
#define		RKVDEC_GET_FORMAT(x)		(((x) >> 20) & 0x3)
#define		RKVDEC_FMT_H265D		(0)
#define		RKVDEC_FMT_H264D		(1)
#define		RKVDEC_FMT_VP9D			(2)

#define RKVDEC_REG_STREAM_RLC_BASE		0x010
#define RKVDEC_REG_STREAM_RLC_BASE_INDEX	(4)

#define RKVDEC_REG_PPS_BASE			0x0a0
#define RKVDEC_REG_PPS_BASE_INDEX		(42)

#define RKVDEC_REG_VP9_REFCOLMV_BASE		0x0d0
#define RKVDEC_REG_VP9_REFCOLMV_BASE_INDEX	(52)

#define RKVDEC_REG_CACHE_ENABLE(i)		(0x41c + ((i) * 0x40))
#define		RKVDEC_CACHE_PERMIT_CACHEABLE_ACCESS	BIT(0)
#define		RKVDEC_CACHE_PERMIT_READ_ALLOCATE	BIT(1)
#define		RKVDEC_CACHE_LINE_SIZE_64_BYTES		BIT(4)

#define MPP_ALIGN_SIZE	0x1000

#define MHZ		(1000 * 1000)
#define DEF_ACLK	400
#define DEF_CORE	250
#define DEF_CABAC	300

#define to_rkvdec_task(ctx)		\
		container_of(ctx, struct rkvdec_task, mpp_task)
#define to_rkvdec_dev(dev)		\
		container_of(dev, struct rockchip_rkvdec_dev, mpp_dev)

static int debug;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "bit switch for rkvdec debug information");

enum RKVDEC_STATE {
	RKVDEC_STATE_NORMAL,
	RKVDEC_STATE_LT_START,
	RKVDEC_STATE_LT_RUN,
};

struct rockchip_rkvdec_dev {
	struct rockchip_mpp_dev mpp_dev;

	struct reset_control *rst_a;
	struct reset_control *rst_h;
	struct reset_control *rst_niu_a;
	struct reset_control *rst_niu_h;
	struct reset_control *rst_core;
	struct reset_control *rst_cabac;

	enum RKVDEC_STATE state;

	void *current_task;
};

struct rkvdec_task {
	struct mpp_task mpp_task;

	u32 reg[ROCKCHIP_RKVDEC_REG_NUM];
	u32 idx;

	u32 strm_base;
	u32 irq_status;
};

/*
 * file handle translate information
 */
static const char trans_tbl_h264d[] = {
	4, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
	23, 24, 41, 42, 43, 48, 75
};

static const char trans_tbl_h265d[] = {
	4, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
	23, 24, 42, 43
};

static const char trans_tbl_vp9d[] = {
	4, 6, 7, 11, 12, 13, 14, 15, 16
};

static struct mpp_trans_info trans_rk_hevcdec[] = {
	[RKVDEC_FMT_H265D] = {
		.count = sizeof(trans_tbl_h265d),
		.table = trans_tbl_h265d,
	},
};

static struct mpp_trans_info trans_rkvdec[] = {
	[RKVDEC_FMT_H265D] = {
		.count = sizeof(trans_tbl_h265d),
		.table = trans_tbl_h265d,
	},
	[RKVDEC_FMT_H264D] = {
		.count = sizeof(trans_tbl_h264d),
		.table = trans_tbl_h264d,
	},
	[RKVDEC_FMT_VP9D] = {
		.count = sizeof(trans_tbl_vp9d),
		.table = trans_tbl_vp9d,
	},
};

static const struct mpp_dev_variant rkvdec_v1_data = {
	.reg_len = 76,
	.trans_info = trans_rkvdec,
	.node_name = RKVDEC_NODE_NAME,
};

static const struct mpp_dev_variant rk_hevcdec_data = {
	.reg_len = 48,
	.trans_info = trans_rk_hevcdec,
	.node_name = RK_HEVCDEC_NODE_NAME,
};

static void *rockchip_rkvdec_get_drv_data(struct platform_device *pdev);

/*
 * NOTE: rkvdec/rkhevc put scaling list address in pps buffer hardware will read
 * it by pps id in video stream data.
 *
 * So we need to translate the address in iommu case. The address data is also
 * 10bit fd + 22bit offset mode.
 * Because userspace decoder do not give the pps id in the register file sets
 * kernel driver need to translate each scaling list address in pps buffer which
 * means 256 pps for H.264, 64 pps for H.265.
 *
 * In order to optimize the performance kernel driver ask userspace decoder to
 * set all scaling list address in pps buffer to the same one which will be used
 * on current decoding task. Then kernel driver can only translate the first
 * address then copy it all pps buffer.
 */
static int fill_scaling_list_pps(struct rkvdec_task *task, int fd, int offset,
				 int count, int pps_info_size,
				 int sub_addr_offset)
{
	struct device *dev = NULL;
	struct dma_buf *dmabuf = NULL;
	void *vaddr = NULL;
	u8 *pps = NULL;
	u32 base = sub_addr_offset;
	u32 scaling_fd = 0;
	u32 scaling_offset;
	int ret = 0;

	/* FIXME: find a better way, it only be used for debugging purpose */
	dev = task->mpp_task.session->mpp->dev;
	if (!dev)
		return -EINVAL;

	dmabuf = dma_buf_get(fd);
	if (IS_ERR_OR_NULL(dmabuf)) {
		dev_err(dev, "invliad pps buffer\n");
		return -ENOENT;
	}

	/* The new dma_buf_begin_cpu_access copy everything - Myy */
	ret = dma_buf_begin_cpu_access(dmabuf, DMA_FROM_DEVICE);
	if (ret) {
		dev_err(dev, "can't access the pps buffer\n");
		return ret;
	}

	vaddr = dma_buf_vmap(dmabuf);
	if (!vaddr) {
		dev_err(dev, "can't access the pps buffer\n");
		return -EIO;
	}
	pps = vaddr + offset;

	memcpy(&scaling_offset, pps + base, sizeof(scaling_offset));
	scaling_offset = le32_to_cpu(scaling_offset);

	scaling_fd = scaling_offset & 0x3ff;
	scaling_offset = scaling_offset >> 10;

	if (scaling_fd > 0) {
		struct mpp_mem_region *mem_region = NULL;
		dma_addr_t tmp = 0;
		int i = 0;

		mem_region = mpp_dev_task_attach_fd(&task->mpp_task,
						    scaling_fd);
		if (IS_ERR(mem_region)) {
			ret = PTR_ERR(mem_region);
			goto done;
		}

		tmp = mem_region->iova;
		tmp += scaling_offset;
		tmp = cpu_to_le32(tmp);
		mpp_debug(DEBUG_PPS_FILL,
			  "pps at %p, scaling fd: %3d => %pad + offset %10d\n",
			  pps, scaling_fd, &mem_region->iova, offset);

		/* Fill the scaling list address in each pps entries */
		for (i = 0; i < count; i++, base += pps_info_size)
			memcpy(pps + base, &tmp, sizeof(tmp));
	}

done:
	dma_buf_vunmap(dmabuf, vaddr);
	/* Recheck - Myy */
	dma_buf_end_cpu_access(dmabuf, DMA_FROM_DEVICE);
	dma_buf_put(dmabuf);

	return 0;
}

static void *rockchip_mpp_rkvdec_alloc_task(struct mpp_session *session,
					    void __user *src, u32 size)
{
	struct rkvdec_task *task = NULL;
	u32 reg_len;
	u32 fmt = 0;
	u32 dwsize = size / sizeof(u32);
	int pps_fd;
	u32 pps_offset;
	int err = -EFAULT;

	mpp_debug_enter();

	task = kzalloc(sizeof(*task), GFP_KERNEL);
	if (!task)
		return NULL;

	mpp_dev_task_init(session, &task->mpp_task);

	reg_len = dwsize > ROCKCHIP_RKVDEC_REG_NUM ?
		ROCKCHIP_RKVDEC_REG_NUM : dwsize;

	if (copy_from_user(task->reg, src, reg_len * 4)) {
		mpp_err("error: copy_from_user failed in reg_init\n");
		err = -EFAULT;
		goto fail;
	}

	fmt = RKVDEC_GET_FORMAT(task->reg[RKVDEC_REG_SYS_CTRL_INDEX]);
	/*
	 * special offset scale case
	 *
	 * This translation is for fd + offset translation.
	 * One register has 32bits. We need to transfer both buffer file
	 * handle and the start address offset so we packet file handle
	 * and offset together using below format.
	 *
	 *  0~9  bit for buffer file handle range 0 ~ 1023
	 * 10~31 bit for offset range 0 ~ 4M
	 *
	 * But on 4K case the offset can be larger the 4M
	 * So on VP9 4K decoder colmv base we scale the offset by 16
	 */
	if (fmt == RKVDEC_FMT_VP9D) {
		struct mpp_mem_region *mem_region = NULL;
		dma_addr_t iova = 0;
		u32 offset = task->reg[RKVDEC_REG_VP9_REFCOLMV_BASE_INDEX];
		int fd = task->reg[RKVDEC_REG_VP9_REFCOLMV_BASE_INDEX] & 0x3ff;

		offset = offset >> 10 << 4;
		mem_region = mpp_dev_task_attach_fd(&task->mpp_task, fd);
		if (IS_ERR(mem_region)) {
			err = PTR_ERR(mem_region);
			goto fail;
		}

		iova = mem_region->iova;
		task->reg[RKVDEC_REG_VP9_REFCOLMV_BASE_INDEX] = iova + offset;
	}

	pps_fd = task->reg[RKVDEC_REG_PPS_BASE_INDEX] & 0x3ff;
	pps_offset = task->reg[RKVDEC_REG_PPS_BASE_INDEX] >> 10;
	if (pps_fd > 0) {
		int pps_info_offset;
		int pps_info_count;
		int pps_info_size;
		int scaling_list_addr_offset;

		switch (fmt) {
		case RKVDEC_FMT_H264D:
			pps_info_offset = pps_offset;
			pps_info_count = 256;
			pps_info_size = 32;
			scaling_list_addr_offset = 23;
			break;
		case RKVDEC_FMT_H265D:
			pps_info_offset = pps_offset;
			pps_info_count = 64;
			pps_info_size = 80;
			scaling_list_addr_offset = 74;
			break;
		default:
			pps_info_offset = 0;
			pps_info_count = 0;
			pps_info_size = 0;
			scaling_list_addr_offset = 0;
			break;
		}

		mpp_debug(DEBUG_PPS_FILL,
			  "scaling list filling parameter:\n");
		mpp_debug(DEBUG_PPS_FILL,
			  "pps_info_offset %d\n", pps_info_offset);
		mpp_debug(DEBUG_PPS_FILL,
			  "pps_info_count  %d\n", pps_info_count);
		mpp_debug(DEBUG_PPS_FILL,
			  "pps_info_size   %d\n", pps_info_size);
		mpp_debug(DEBUG_PPS_FILL,
			  "scaling_list_addr_offset %d\n",
			  scaling_list_addr_offset);

		if (pps_info_count) {
			err = fill_scaling_list_pps(task, pps_fd,
						    pps_info_offset,
						    pps_info_count,
						    pps_info_size,
						    scaling_list_addr_offset);
			if (err) {
				mpp_err("fill pps failed\n");
				goto fail;
			}
		}
	}

	err = mpp_reg_address_translate(session->mpp, &task->mpp_task, fmt,
					task->reg);
	if (err) {
		mpp_err("error: translate reg address failed.\n");

		if (unlikely(debug & DEBUG_DUMP_ERR_REG))
			mpp_debug_dump_reg_mem(task->reg,
					       ROCKCHIP_RKVDEC_REG_NUM);
		goto fail;
	}

	task->strm_base = task->reg[RKVDEC_REG_STREAM_RLC_BASE_INDEX];

	mpp_debug_leave();

	return &task->mpp_task;

fail:
	mpp_dev_task_finalize(session, &task->mpp_task);
	kfree(task);
	return ERR_PTR(err);
}

static int rockchip_mpp_rkvdec_prepare(struct rockchip_mpp_dev *mpp_dev,
				       struct mpp_task *task)
{
	struct rockchip_rkvdec_dev *dec_dev = to_rkvdec_dev(mpp_dev);

	if (dec_dev->state == RKVDEC_STATE_NORMAL)
		return -EINVAL;
	/*
	 * Don't do soft reset before running or you will meet 0x00408322
	 * if you will decode a HEVC stream. Different error for the AVC.
	 */

	return 0;
}

static int rockchip_mpp_rkvdec_run(struct rockchip_mpp_dev *mpp_dev,
				   struct mpp_task *mpp_task)
{
	struct rockchip_rkvdec_dev *dec_dev = NULL;
	struct rkvdec_task *task = NULL;
	u32 reg = 0;

	mpp_debug_enter();

	dec_dev = to_rkvdec_dev(mpp_dev);
	task = to_rkvdec_task(mpp_task);
#if 0
	/*
	 * hardware bug workaround, because the write ddr align optimize need
	 * aclk and core clock using the same parent clock. so when optimization
	 * enable, we need to reset the clocks.
	 */
	if (ctx->reg[RKVDEC_REG_DEC_INT_EN / 4] & RKVDEC_WR_DDR_ALIGN_EN) {
		if (atomic_read(&dec->cur_core) != 250) {
			atomic_set(&dec->cur_core, 250);
			mpp_debug(DEBUG_CLOCK, "set core clock to 250 MHz\n");
			clk_set_rate(dec->core, 250 * MHZ);
		}
	} else {
		if (atomic_read(&dec->cur_core) != 200) {
			atomic_set(&dec->cur_core, 200);
			mpp_debug(DEBUG_CLOCK, "set core clock to 200 MHz\n");
			clk_set_rate(dec->core, 200 * MHZ);
		}
		if (atomic_read(&dec->cur_aclk) != 300) {
			atomic_set(&dec->cur_aclk, 300);
			mpp_debug(DEBUG_CLOCK, "set core clock to 300 MHz\n");
			clk_set_rate(dec->aclk, 300 * MHZ);
		}
		if (atomic_read(&dec->cur_caback) != 200) {
			atomic_set(&dec->cur_caback, 200);
			mpp_debug(DEBUG_CLOCK, "set core clock to 200 MHz\n");
			clk_set_rate(dec->cabac, 200 * MHZ);
		}
	}
#endif
	switch (dec_dev->state) {
	case RKVDEC_STATE_NORMAL:
		/* FIXME: spin lock here */
		dec_dev->current_task = task;

		reg = RKVDEC_CACHE_PERMIT_CACHEABLE_ACCESS
			| RKVDEC_CACHE_PERMIT_READ_ALLOCATE;
		if (!(debug & DEBUG_CACHE_32B))
			reg |= RKVDEC_CACHE_LINE_SIZE_64_BYTES;

		mpp_dev_write(mpp_dev, RKVDEC_REG_CACHE_ENABLE(0), reg);
		mpp_dev_write(mpp_dev, RKVDEC_REG_CACHE_ENABLE(1), reg);

		mpp_dev_write_seq(mpp_dev, RKVDEC_REG_SYS_CTRL,
				  &task->reg[RKVDEC_REG_SYS_CTRL_INDEX],
				  mpp_dev->variant->reg_len
				  - RKVDEC_REG_SYS_CTRL_INDEX);

		/* Flush the register before the start the device */
		wmb();
		mpp_dev_write(mpp_dev, RKVDEC_REG_DEC_INT_EN,
			      task->reg[RKVDEC_REG_DEC_INT_EN_INDEX]
			      | RKVDEC_DEC_START);
		break;
	default:
		break;
	}

	mpp_debug_leave();

	return 0;
}

static int rockchip_mpp_rkvdec_finish(struct rockchip_mpp_dev *mpp_dev,
				      struct mpp_task *mpp_task)
{
	struct rockchip_rkvdec_dev *dec_dev = to_rkvdec_dev(mpp_dev);
	struct rkvdec_task *task = to_rkvdec_task(mpp_task);

	mpp_debug_enter();

	switch (dec_dev->state) {
	case RKVDEC_STATE_NORMAL: {
		mpp_dev_read_seq(mpp_dev, RKVDEC_REG_SYS_CTRL,
				 &task->reg[RKVDEC_REG_SYS_CTRL_INDEX],
				 mpp_dev->variant->reg_len
				 - RKVDEC_REG_SYS_CTRL_INDEX);
		task->reg[RKVDEC_REG_DEC_INT_EN_INDEX] = task->irq_status;
	} break;
	default:
		break;
	}

	mpp_debug_leave();

	return 0;
}

static int rockchip_mpp_rkvdec_result(struct rockchip_mpp_dev *mpp_dev,
				      struct mpp_task *mpp_task,
				      u32 __user *dst, u32 size)
{
	struct rkvdec_task *task = to_rkvdec_task(mpp_task);

	/* FIXME may overflow the kernel */
	if (copy_to_user(dst, task->reg, size)) {
		mpp_err("copy_to_user failed\n");
		return -EIO;
	}

	return 0;
}

static int rockchip_mpp_rkvdec_free_task(struct mpp_session *session,
					 struct mpp_task *mpp_task)
{
	struct rkvdec_task *task = to_rkvdec_task(mpp_task);

	mpp_dev_task_finalize(session, mpp_task);
	kfree(task);

	return 0;
}

static irqreturn_t mpp_rkvdec_isr(int irq, void *dev_id)
{
	struct rockchip_rkvdec_dev *dec_dev = dev_id;
	struct rockchip_mpp_dev *mpp_dev = &dec_dev->mpp_dev;
	struct rkvdec_task *task = NULL;
	struct mpp_task *mpp_task = NULL;
	u32 irq_status;
	u32 err_mask;

	irq_status = mpp_dev_read(mpp_dev, RKVDEC_REG_DEC_INT_EN);
	if (!(irq_status & RKVDEC_DEC_INT_RAW))
		return IRQ_NONE;

	mpp_dev_write(mpp_dev, RKVDEC_REG_DEC_INT_EN, RKVDEC_CLOCK_GATE_EN);
	/* FIXME use a spin lock here */
	task = (struct rkvdec_task *)dec_dev->current_task;
	if (!task) {
		dev_err(dec_dev->mpp_dev.dev, "no current task\n");
		return IRQ_HANDLED;
	}
	mpp_debug_time_diff(&task->mpp_task);

	task->irq_status = irq_status;
	switch (dec_dev->state) {
	case RKVDEC_STATE_NORMAL:
		mpp_debug(DEBUG_IRQ_STATUS, "irq_status: %08x\n",
			  task->irq_status);

		err_mask = RKVDEC_INT_BUF_EMPTY
			| RKVDEC_INT_BUS_ERROR
			| RKVDEC_INT_COLMV_REF_ERROR
			| RKVDEC_INT_STRM_ERROR
			| RKVDEC_INT_TIMEOUT;

		if (err_mask & task->irq_status)
			atomic_set(&mpp_dev->reset_request, 1);

		mpp_task = &task->mpp_task;
		mpp_dev_task_finish(mpp_task->session, mpp_task);

		mpp_debug_leave();
		return IRQ_HANDLED;
	default:
		goto fail;
	}
fail:
	return IRQ_HANDLED;
}

static int rockchip_mpp_rkvdec_assign_reset(struct rockchip_rkvdec_dev *dec_dev)
{
	struct rockchip_mpp_dev *mpp_dev = &dec_dev->mpp_dev;

	/* TODO: use devm_reset_control_get_share() instead */
	dec_dev->rst_a = devm_reset_control_get(mpp_dev->dev, "video_a");
	dec_dev->rst_h = devm_reset_control_get(mpp_dev->dev, "video_h");
	dec_dev->rst_core = devm_reset_control_get(mpp_dev->dev, "video_core");
	/* The reset controller below are not shared with VPU */
	dec_dev->rst_niu_a = devm_reset_control_get(mpp_dev->dev, "niu_a");
	dec_dev->rst_niu_h = devm_reset_control_get(mpp_dev->dev, "niu_h");
	dec_dev->rst_cabac = devm_reset_control_get(mpp_dev->dev,
						    "video_cabac");

	if (IS_ERR_OR_NULL(dec_dev->rst_a)) {
		mpp_err("No aclk reset resource define\n");
		dec_dev->rst_a = NULL;
	}

	if (IS_ERR_OR_NULL(dec_dev->rst_h)) {
		mpp_err("No hclk reset resource define\n");
		dec_dev->rst_h = NULL;
	}

	if (IS_ERR_OR_NULL(dec_dev->rst_niu_a)) {
		mpp_err("No axi niu reset resource define\n");
		dec_dev->rst_niu_a = NULL;
	}

	if (IS_ERR_OR_NULL(dec_dev->rst_niu_h)) {
		mpp_err("No ahb niu reset resource define\n");
		dec_dev->rst_niu_h = NULL;
	}

	if (IS_ERR_OR_NULL(dec_dev->rst_core)) {
		mpp_err("No core reset resource define\n");
		dec_dev->rst_core = NULL;
	}

	if (IS_ERR_OR_NULL(dec_dev->rst_cabac)) {
		mpp_err("No cabac reset resource define\n");
		dec_dev->rst_cabac = NULL;
	}

	return 0;
}

static int rockchip_mpp_rkvdec_reset(struct rockchip_mpp_dev *mpp_dev)
{
	struct rockchip_rkvdec_dev *dec = to_rkvdec_dev(mpp_dev);

	if (dec->rst_a && dec->rst_h) {
		mpp_debug(DEBUG_RESET, "reset in\n");
		rockchip_pmu_idle_request(mpp_dev->dev, true);

		safe_reset(dec->rst_niu_a);
		safe_reset(dec->rst_niu_h);
		safe_reset(dec->rst_a);
		safe_reset(dec->rst_h);
		safe_reset(dec->rst_core);
		safe_reset(dec->rst_cabac);
		udelay(5);
		safe_unreset(dec->rst_niu_h);
		safe_unreset(dec->rst_niu_a);
		safe_unreset(dec->rst_a);
		safe_unreset(dec->rst_h);
		safe_unreset(dec->rst_core);
		safe_unreset(dec->rst_cabac);

		rockchip_pmu_idle_request(mpp_dev->dev, false);

		mpp_dev_write(mpp_dev, RKVDEC_REG_DEC_INT_EN, 0);
		dec->current_task = NULL;
		mpp_debug(DEBUG_RESET, "reset out\n");
	}

	return 0;
}

static struct mpp_dev_ops rkvdec_ops = {
	.alloc_task = rockchip_mpp_rkvdec_alloc_task,
	.prepare = rockchip_mpp_rkvdec_prepare,
	.run = rockchip_mpp_rkvdec_run,
	.finish = rockchip_mpp_rkvdec_finish,
	.result = rockchip_mpp_rkvdec_result,
	.free_task = rockchip_mpp_rkvdec_free_task,
	.reset = rockchip_mpp_rkvdec_reset,
};

static int rockchip_mpp_rkvdec_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rockchip_rkvdec_dev *dec_dev = NULL;
	struct rockchip_mpp_dev *mpp_dev = NULL;
	int ret = 0;

	dec_dev = devm_kzalloc(dev, sizeof(struct rockchip_rkvdec_dev),
			       GFP_KERNEL);
	if (!dec_dev)
		return -ENOMEM;

	mpp_dev = &dec_dev->mpp_dev;
	mpp_dev->variant = rockchip_rkvdec_get_drv_data(pdev);
	ret = mpp_dev_common_probe(mpp_dev, pdev, &rkvdec_ops);
	if (ret)
		return ret;

	ret = devm_request_threaded_irq(dev, mpp_dev->irq, NULL, mpp_rkvdec_isr,
					IRQF_SHARED | IRQF_ONESHOT,
					dev_name(dev), dec_dev);
	if (ret) {
		dev_err(dev, "register interrupter runtime failed\n");
		return ret;
	}

	rockchip_mpp_rkvdec_assign_reset(dec_dev);
	dec_dev->state = RKVDEC_STATE_NORMAL;

	ret = mpp_dev_register_node(mpp_dev, mpp_dev->variant->node_name, NULL);
	if (ret)
		dev_err(dev, "register char device failed: %d\n", ret);

	dev_info(dev, "probing finish\n");

	platform_set_drvdata(pdev, dec_dev);

	return 0;
}

static int rockchip_mpp_rkvdec_remove(struct platform_device *pdev)
{
	struct rockchip_rkvdec_dev *dec_dev = platform_get_drvdata(pdev);

	mpp_dev_common_remove(&dec_dev->mpp_dev);

	return 0;
}

static const struct of_device_id mpp_rkvdec_dt_match[] = {
	{ .compatible = "rockchip,video-decoder-v1", .data = &rkvdec_v1_data},
	{ .compatible = "rockchip,hevc-decoder-v1", .data = &rk_hevcdec_data},
	{},
};

static void *rockchip_rkvdec_get_drv_data(struct platform_device *pdev)
{
	struct mpp_dev_variant *driver_data = NULL;

	if (pdev->dev.of_node) {
		const struct of_device_id *match;

		match = of_match_node(mpp_rkvdec_dt_match,
				      pdev->dev.of_node);
		if (match)
			driver_data = (struct mpp_dev_variant *)match->data;
	}
	return driver_data;
}

static struct platform_driver rockchip_rkvdec_driver = {
	.probe = rockchip_mpp_rkvdec_probe,
	.remove = rockchip_mpp_rkvdec_remove,
	.driver = {
		.name = RKVDEC_DRIVER_NAME,
		.of_match_table = of_match_ptr(mpp_rkvdec_dt_match),
	},
};

static int __init mpp_dev_rkvdec_init(void)
{
	int ret = platform_driver_register(&rockchip_rkvdec_driver);

	if (ret) {
		mpp_err("Platform device register failed (%d).\n", ret);
		return ret;
	}

	return ret;
}

static void __exit mpp_dev_rkvdec_exit(void)
{
	platform_driver_unregister(&rockchip_rkvdec_driver);
}

module_init(mpp_dev_rkvdec_init);
module_exit(mpp_dev_rkvdec_exit);

MODULE_DEVICE_TABLE(of, mpp_rkvdec_dt_match);
MODULE_LICENSE("GPL v2");
