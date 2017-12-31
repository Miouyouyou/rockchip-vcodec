/*
 * Copyright (C) 2017 Fuzhou Rockchip Electronics Co., Ltd
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

#include <asm/cacheflush.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/of_platform.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "mpp_debug.h"
#include "mpp_dev_common.h"

#define RKVDPU1_DRIVER_NAME		"mpp_vdpu1"
#define RKVDPU1_NODE_NAME		"vpu-service"

/* The maximum registers number of all the version */
#define ROCKCHIP_VDPU1_REG_NUM			108

#define RKVDPU1_REG_DEC_INT_EN			0x004
#define RKVDPU1_REG_DEC_INT_EN_INDEX		(1)
/* B slice detected, used in 8190 decoder and later */
#define		RKVDPU1_INT_PIC_INF		BIT(24)
#define		RKVDPU1_INT_TIMEOUT		BIT(18)
#define		RKVDPU1_INT_SLICE		BIT(17)
#define		RKVDPU1_INT_STRM_ERROR		BIT(16)
#define		RKVDPU1_INT_ASO_ERROR		BIT(15)
#define		RKVDPU1_INT_BUF_EMPTY		BIT(14)
#define		RKVDPU1_INT_BUS_ERROR		BIT(13)
#define		RKVDPU1_DEC_INT			BIT(12)
#define		RKVDPU1_DEC_INT_RAW		BIT(8)
#define		RKVDPU1_DEC_IRQ_DIS		BIT(4)
#define		RKVDPU1_DEC_START		BIT(0)

#define RKVDPU1_REG_DEC_DEV_CTRL		0x008
#define RKVDPU1_REG_DEC_DEV_CTRL_INDEX		(2)
/* NOTE: Don't enable it or decoding AVC would meet problem at rk3288 */
#define		RKVDPU1_CLOCK_GATE_EN		BIT(10)

#define RKVDPU1_REG_SYS_CTRL			0x00c
#define RKVDPU1_REG_SYS_CTRL_INDEX		(3)
#define		RKVDPU1_GET_FORMAT(x)		(((x) >> 28) & 0xf)
#define		RKVDPU1_FMT_H264D		0
#define		RKVDPU1_FMT_MPEG4D		1
#define		RKVDPU1_FMT_H263D		2
#define		RKVDPU1_FMT_JPEGD		3
#define		RKVDPU1_FMT_VC1D		4
#define		RKVDPU1_FMT_MPEG2D		5
#define		RKVDPU1_FMT_MPEG1D		6
#define		RKVDPU1_FMT_VP6D		7
#define		RKVDPU1_FMT_RESERVED		8
#define		RKVDPU1_FMT_VP7D		9
#define		RKVDPU1_FMT_VP8D		10
#define		RKVDPU1_FMT_AVSD		11

#define RKVDPU1_REG_STREAM_RLC_BASE		0x030
#define RKVDPU1_REG_STREAM_RLC_BASE_INDEX	(12)

#define RKVDPU1_REG_DIR_MV_BASE			0x0a4
#define RKVDPU1_REG_DIR_MV_BASE_INDEX		(41)

#define to_rkvdpu_task(ctx)		\
		container_of(ctx, struct rkvdpu_task, mpp_task)
#define to_rkvdpu_dev(dev)		\
		container_of(dev, struct rockchip_rkvdpu_dev, mpp_dev)

static int debug;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "bit switch for vdpu1 debug information");

struct vdpu1_dev_data {
	struct mpp_dev_variant dec_data;
	bool pp_support;
};

struct rockchip_rkvdpu_dev {
	struct rockchip_mpp_dev mpp_dev;
	struct vdpu1_dev_data *data;

	struct reset_control *rst_a;
	struct reset_control *rst_h;

	void *current_task;
};

struct rkvdpu_task {
	struct mpp_task mpp_task;

	u32 reg[ROCKCHIP_VDPU1_REG_NUM];
	u32 idx;
	struct extra_info_for_iommu ext_inf;

	u32 strm_base;
	u32 irq_status;
};

/*
 * file handle translate information
 */
static const char trans_tbl_avsd[] = {
	12, 13, 14, 15, 16, 17, 40, 41, 45
};

static const char trans_tbl_default[] = {
	12, 13, 14, 15, 16, 17, 40, 41
};

static const char trans_tbl_jpegd[] = {
	12, 13, 14, 40, 66, 67
};

static const char trans_tbl_h264d[] = {
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
	28, 29, 40
};

static const char trans_tbl_vc1d[] = {
	12, 13, 14, 15, 16, 17, 27, 41
};

static const char trans_tbl_vp6d[] = {
	12, 13, 14, 18, 27, 40
};

static const char trans_tbl_vp8d[] = {
	10, 12, 13, 14, 18, 19, 22, 23, 24, 25, 26, 27, 28, 29, 40
};

static struct mpp_trans_info trans_rk_vdpu1[] = {
	[RKVDPU1_FMT_H264D] = {
		.count = sizeof(trans_tbl_h264d),
		.table = trans_tbl_h264d,
	},
	[RKVDPU1_FMT_MPEG4D] = {
		.count = sizeof(trans_tbl_default),
		.table = trans_tbl_default,
	},
	[RKVDPU1_FMT_H263D] = {
		.count = sizeof(trans_tbl_default),
		.table = trans_tbl_default,
	},
	[RKVDPU1_FMT_JPEGD] = {
		.count = sizeof(trans_tbl_jpegd),
		.table = trans_tbl_jpegd,
	},
	[RKVDPU1_FMT_VC1D] = {
		.count = sizeof(trans_tbl_vc1d),
		.table = trans_tbl_vc1d,
	},
	[RKVDPU1_FMT_MPEG2D] = {
		.count = sizeof(trans_tbl_default),
		.table = trans_tbl_default,
	},
	[RKVDPU1_FMT_MPEG1D] = {
		.count = sizeof(trans_tbl_default),
		.table = trans_tbl_default,
	},
	[RKVDPU1_FMT_VP6D] = {
		.count = sizeof(trans_tbl_vp6d),
		.table = trans_tbl_vp6d,
	},
	[RKVDPU1_FMT_RESERVED] = {
		.count = 0,
		.table = NULL,
	},
	[RKVDPU1_FMT_VP7D] = {
		.count = sizeof(trans_tbl_default),
		.table = trans_tbl_default,
	},
	[RKVDPU1_FMT_VP8D] = {
		.count = sizeof(trans_tbl_vp8d),
		.table = trans_tbl_vp8d,
	},
	[RKVDPU1_FMT_AVSD] = {
		.count = sizeof(trans_tbl_avsd),
		.table = trans_tbl_avsd,
	},
};

static const struct vdpu1_dev_data vdpu_v1_data = {
	.dec_data = {
		/* Exclude the register of the Post Processor */
		.reg_len = 60,
		.trans_info = trans_rk_vdpu1,
		.node_name = RKVDPU1_NODE_NAME,
	},
	.pp_support = false,
};

static const struct vdpu1_dev_data vdpu_pp_v1_data = {
	.dec_data = {
		/* Exclude the register of the Performance monitor */
		.reg_len = 101,
		.trans_info = trans_rk_vdpu1,
		.node_name = RKVDPU1_NODE_NAME,
	},
	.pp_support = true,
};

static void *rockchip_rkvdpu1_get_drv_data(struct platform_device *pdev);

static void *rockchip_mpp_rkvdpu_alloc_task(struct mpp_session *session,
					    void __user *src, u32 size)
{
	struct rkvdpu_task *task = NULL;
	u32 reg_len;
	u32 extinf_len;
	u32 fmt = 0;
	u32 dwsize = size / sizeof(u32);
	int err = -EFAULT;

	mpp_debug_enter();

	task = kzalloc(sizeof(*task), GFP_KERNEL);
	if (!task)
		return NULL;

	mpp_dev_task_init(session, &task->mpp_task);

	reg_len = dwsize > ROCKCHIP_VDPU1_REG_NUM ?
		ROCKCHIP_VDPU1_REG_NUM : dwsize;
	extinf_len = dwsize > reg_len ? (dwsize - reg_len) * 4 : 0;

	if (copy_from_user(task->reg, src, reg_len * 4)) {
		mpp_err("error: copy_from_user failed in reg_init\n");
		err = -EFAULT;
		goto fail;
	}
	if (extinf_len > 0) {
		u32 ext_cpy = min_t(size_t, extinf_len, sizeof(task->ext_inf));

		if (copy_from_user(&task->ext_inf, (u8 *)src + reg_len,
				   ext_cpy)) {
			mpp_err("copy_from_user failed when extra info\n");
			err = -EFAULT;
			goto fail;
		}
	}

	fmt = RKVDPU1_GET_FORMAT(task->reg[RKVDPU1_REG_SYS_CTRL_INDEX]);
	err = mpp_reg_address_translate(session->mpp, &task->mpp_task, fmt,
					task->reg);
	if (err) {
		mpp_err("error: translate reg address failed.\n");

		if (unlikely(debug & DEBUG_DUMP_ERR_REG))
			mpp_debug_dump_reg_mem(task->reg,
					       ROCKCHIP_VDPU1_REG_NUM);
		goto fail;
	}
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
	 */
	if (likely(fmt == RKVDPU1_FMT_H264D)) {
		struct mpp_mem_region *mem_region = NULL;
		dma_addr_t iova = 0;
		u32 offset = task->reg[RKVDPU1_REG_DIR_MV_BASE_INDEX];
		int fd = task->reg[RKVDPU1_REG_DIR_MV_BASE_INDEX] & 0x3ff;

		offset = offset >> 10 << 4;
		mem_region = mpp_dev_task_attach_fd(&task->mpp_task, fd);
		if (IS_ERR(mem_region)) {
			err = PTR_ERR(mem_region);
			goto fail;
		}

		iova = mem_region->iova;
		mpp_debug(DEBUG_IOMMU, "DMV[%3d]: %3d => %pad + offset %10d\n",
			  RKVDPU1_REG_DIR_MV_BASE_INDEX, fd, &iova, offset);
		task->reg[RKVDPU1_REG_DIR_MV_BASE_INDEX] = iova + offset;
	}

	task->strm_base = task->reg[RKVDPU1_REG_STREAM_RLC_BASE_INDEX];

	mpp_debug(DEBUG_SET_REG, "extra info cnt %u, magic %08x",
		  task->ext_inf.cnt, task->ext_inf.magic);
	mpp_translate_extra_info(&task->mpp_task, &task->ext_inf, task->reg);

	mpp_debug_leave();

	return &task->mpp_task;

fail:
	mpp_dev_task_finalize(session, &task->mpp_task);
	kfree(task);
	return ERR_PTR(err);
}

static int rockchip_mpp_rkvdpu_prepare(struct rockchip_mpp_dev *mpp_dev,
				       struct mpp_task *task)
{
	return -EINVAL;
}

static int rockchip_mpp_rkvdpu_run(struct rockchip_mpp_dev *mpp_dev,
				   struct mpp_task *mpp_task)
{
	struct rkvdpu_task *task = NULL;
	struct rockchip_rkvdpu_dev *dec_dev = NULL;

	mpp_debug_enter();

	task = to_rkvdpu_task(mpp_task);
	dec_dev = to_rkvdpu_dev(mpp_dev);

	/* FIXME: spin lock here */
	dec_dev->current_task = task;

	mpp_dev_write_seq(mpp_dev, RKVDPU1_REG_DEC_DEV_CTRL,
			  &task->reg[RKVDPU1_REG_DEC_DEV_CTRL_INDEX],
			  mpp_dev->variant->reg_len
			  - RKVDPU1_REG_DEC_DEV_CTRL_INDEX);
	/* Flush the registers */
	wmb();
	mpp_dev_write(mpp_dev, RKVDPU1_REG_DEC_INT_EN,
		      task->reg[RKVDPU1_REG_DEC_INT_EN_INDEX]
		      | RKVDPU1_DEC_START);

	mpp_debug_leave();

	return 0;
}

static int rockchip_mpp_rkvdpu_finish(struct rockchip_mpp_dev *mpp_dev,
				      struct mpp_task *mpp_task)
{
	struct rkvdpu_task *task = to_rkvdpu_task(mpp_task);

	mpp_debug_enter();

	mpp_dev_read_seq(mpp_dev, RKVDPU1_REG_DEC_DEV_CTRL,
			 &task->reg[RKVDPU1_REG_DEC_DEV_CTRL_INDEX],
			 mpp_dev->variant->reg_len
			 - RKVDPU1_REG_DEC_DEV_CTRL);
	task->reg[RKVDPU1_REG_DEC_INT_EN_INDEX] = task->irq_status;

	mpp_debug_leave();

	return 0;
}

static int rockchip_mpp_rkvdpu_result(struct rockchip_mpp_dev *mpp_dev,
				      struct mpp_task *mpp_task,
				      u32 __user *dst, u32 size)
{
	struct rkvdpu_task *task = to_rkvdpu_task(mpp_task);

	/* FIXME may overflow the kernel */
	if (copy_to_user(dst, task->reg, size)) {
		mpp_err("copy_to_user failed\n");
		return -EIO;
	}

	return 0;
}

static int rockchip_mpp_rkvdpu_free_task(struct mpp_session *session,
					 struct mpp_task *mpp_task)
{
	struct rkvdpu_task *task = to_rkvdpu_task(mpp_task);

	mpp_dev_task_finalize(session, mpp_task);
	kfree(task);

	return 0;
}

static irqreturn_t mpp_rkvdpu_isr(int irq, void *dev_id)
{
	struct rockchip_rkvdpu_dev *dec_dev = dev_id;
	struct rockchip_mpp_dev *mpp_dev = &dec_dev->mpp_dev;
	struct rkvdpu_task *task = NULL;
	struct mpp_task *mpp_task = NULL;
	u32 irq_status;
	u32 err_mask;

	irq_status = mpp_dev_read(mpp_dev, RKVDPU1_REG_DEC_INT_EN);
	if (!(irq_status & RKVDPU1_DEC_INT_RAW))
		return IRQ_NONE;

	mpp_dev_write(mpp_dev, RKVDPU1_REG_DEC_INT_EN, 0);
	/* FIXME use a spin lock here */
	task = (struct rkvdpu_task *)dec_dev->current_task;
	if (!task) {
		dev_err(dec_dev->mpp_dev.dev, "no current task\n");
		return IRQ_HANDLED;
	}

	mpp_task = &task->mpp_task;
	mpp_debug_time_diff(mpp_task);

	task->irq_status = irq_status;
	mpp_debug(DEBUG_IRQ_STATUS, "irq_status: %08x\n",
		  task->irq_status);

	err_mask = RKVDPU1_INT_TIMEOUT
		| RKVDPU1_INT_STRM_ERROR
		| RKVDPU1_INT_ASO_ERROR
		| RKVDPU1_INT_BUF_EMPTY
		| RKVDPU1_INT_BUS_ERROR;

	if (err_mask & task->irq_status)
		atomic_set(&mpp_dev->reset_request, 1);

	mpp_dev_task_finish(mpp_task->session, mpp_task);

	mpp_debug_leave();
	return IRQ_HANDLED;

	return IRQ_NONE;
}

static int rockchip_mpp_rkvdpu_assign_reset(struct rockchip_rkvdpu_dev *dec_dev)
{
	struct rockchip_mpp_dev *mpp_dev = &dec_dev->mpp_dev;

	/* TODO: use devm_reset_control_get_share() instead */
	dec_dev->rst_a = devm_reset_control_get(mpp_dev->dev, "video_a");
	dec_dev->rst_h = devm_reset_control_get(mpp_dev->dev, "video_h");

	if (IS_ERR_OR_NULL(dec_dev->rst_a)) {
		mpp_err("No aclk reset resource define\n");
		dec_dev->rst_a = NULL;
	}

	if (IS_ERR_OR_NULL(dec_dev->rst_h)) {
		mpp_err("No hclk reset resource define\n");
		dec_dev->rst_h = NULL;
	}

	return 0;
}

static int rockchip_mpp_rkvdpu_reset(struct rockchip_mpp_dev *mpp_dev)
{
	struct rockchip_rkvdpu_dev *dec = to_rkvdpu_dev(mpp_dev);

	if (dec->rst_a && dec->rst_h) {
		mpp_debug(DEBUG_RESET, "reset in\n");

		/* Don't skip this or iommu won't work after reset */
		rockchip_pmu_idle_request(mpp_dev->dev, true);
		safe_reset(dec->rst_a);
		safe_reset(dec->rst_h);
		udelay(5);
		safe_unreset(dec->rst_h);
		safe_unreset(dec->rst_a);
		rockchip_pmu_idle_request(mpp_dev->dev, false);

		mpp_dev_write(mpp_dev, RKVDPU1_REG_DEC_INT_EN, 0);
		dec->current_task = NULL;
		mpp_debug(DEBUG_RESET, "reset out\n");
	}

	return 0;
}

static struct mpp_dev_ops rkvdpu_ops = {
	.alloc_task = rockchip_mpp_rkvdpu_alloc_task,
	.prepare = rockchip_mpp_rkvdpu_prepare,
	.run = rockchip_mpp_rkvdpu_run,
	.finish = rockchip_mpp_rkvdpu_finish,
	.result = rockchip_mpp_rkvdpu_result,
	.free_task = rockchip_mpp_rkvdpu_free_task,
	.reset = rockchip_mpp_rkvdpu_reset,
};

static int rockchip_mpp_rkvdpu_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rockchip_rkvdpu_dev *dec_dev = NULL;
	struct rockchip_mpp_dev *mpp_dev = NULL;
	int ret = 0;

	dec_dev = devm_kzalloc(dev, sizeof(struct rockchip_rkvdpu_dev),
			       GFP_KERNEL);
	if (!dec_dev)
		return -ENOMEM;

	dec_dev->data = rockchip_rkvdpu1_get_drv_data(pdev);
	mpp_dev = &dec_dev->mpp_dev;
	mpp_dev->variant = &dec_dev->data->dec_data;
	ret = mpp_dev_common_probe(mpp_dev, pdev, &rkvdpu_ops);
	if (ret)
		return ret;

	ret = devm_request_threaded_irq(dev, mpp_dev->irq, NULL, mpp_rkvdpu_isr,
					IRQF_SHARED | IRQF_ONESHOT,
					dev_name(dev), dec_dev);
	if (ret) {
		dev_err(dev, "register interrupter runtime failed\n");
		return ret;
	}

	rockchip_mpp_rkvdpu_assign_reset(dec_dev);

	ret = mpp_dev_register_node(mpp_dev, mpp_dev->variant->node_name, NULL);
	if (ret)
		dev_err(dev, "register char device failed: %d\n", ret);

	dev_info(dev, "probing finish\n");

	platform_set_drvdata(pdev, dec_dev);

	return 0;
}

static int rockchip_mpp_rkvdpu_remove(struct platform_device *pdev)
{
	struct rockchip_rkvdpu_dev *dec_dev = platform_get_drvdata(pdev);

	mpp_dev_common_remove(&dec_dev->mpp_dev);

	return 0;
}

static const struct of_device_id mpp_rkvdpu1_dt_match[] = {
	{ .compatible = "rockchip,vpu-decoder-v1", .data = &vdpu_v1_data},
	{ .compatible = "rockchip,vpu-decoder-pp-v1", .data = &vdpu_pp_v1_data},
	{},
};

static void *rockchip_rkvdpu1_get_drv_data(struct platform_device *pdev)
{
	struct vdpu1_dev_data *driver_data = NULL;

	if (pdev->dev.of_node) {
		const struct of_device_id *match;

		match = of_match_node(mpp_rkvdpu1_dt_match,
				      pdev->dev.of_node);
		if (match)
			driver_data = (struct vdpu1_dev_data *)match->data;
	}
	return driver_data;
}

static struct platform_driver rockchip_rkvdpu1_driver = {
	.probe = rockchip_mpp_rkvdpu_probe,
	.remove = rockchip_mpp_rkvdpu_remove,
	.driver = {
		.name = RKVDPU1_DRIVER_NAME,
		.of_match_table = of_match_ptr(mpp_rkvdpu1_dt_match),
	},
};

static int __init mpp_dev_rkvdpu1_init(void)
{
	int ret = platform_driver_register(&rockchip_rkvdpu1_driver);

	if (ret) {
		mpp_err("Platform device register failed (%d).\n", ret);
		return ret;
	}

	return ret;
}

static void __exit mpp_dev_rkvdpu1_exit(void)
{
	platform_driver_unregister(&rockchip_rkvdpu1_driver);
}

module_init(mpp_dev_rkvdpu1_init);
module_exit(mpp_dev_rkvdpu1_exit);

MODULE_DEVICE_TABLE(of, mpp_rkvdpu1_dt_match);
MODULE_LICENSE("GPL v2");
