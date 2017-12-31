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

#define RKVEPU2_DRIVER_NAME		"mpp_vepu2"
#define RKVEPU2_NODE_NAME		"vepu"

/* The maximum registers number of all the version */
#define ROCKCHIP_VEPU2_REG_NUM			(184)

#define RKVEPU2_REG_ENC_CTRL			0x19c
#define RKVEPU2_REG_ENC_CTRL_INDEX		(103)
#define		RKVEPU2_GET_FORMAT(x)		(((x) >> 4) & 0x3)
#define		RKVEPU2_FMT_RESERVED		(0)
#define		RKVEPU2_FMT_VP8E		(1)
#define		RKVEPU2_FMT_JPEGE		(2)
#define		RKVEPU2_FMT_H264E		(3)
#define		RKVEPU2_ENC_START		BIT(0)


#define RKVEPU2_REG_INT				0x1b4
#define RKVEPU2_REG_INT_INDEX			(109)
#define		RKVEPU2_MV_SAD_WR_EN		BIT(24)
#define		RKVEPU2_ROCON_WRITE_DIS		BIT(20)
#define		RKVEPU1_INT_SLICE_EN		BIT(16)
#define		RKVEPU2_CLOCK_GATE_EN		BIT(12)
#define 	RKVEPU2_INT_TIMEOUT_EN		BIT(10)
#define		RKVEPU2_INT_CLEAR		BIT(9)
#define		RKVEPU2_IRQ_DIS			BIT(8)
#define		RKVEPU2_INT_TIMEOUT		BIT(6)
#define		RKVEPU2_INT_BUF_FULL		BIT(5)
#define		RKVEPU2_INT_BUS_ERROR		BIT(4)
#define		RKVEPU2_INT_SLICE		BIT(2)
#define		RKVEPU2_INT_RDY			BIT(1)
#define		RKVEPU2_INT_RAW			BIT(0)

#define RKVPUE2_REG_DMV_4P_1P(i)		(0x1e0 + ((i) << 4))
#define RKVPUE2_REG_DMV_4P_1P_INDEX(i)		(120 + (i))

#define to_rkvepu_task(ctx)		\
		container_of(ctx, struct rkvepu_task, mpp_task)
#define to_rkvepu_dev(dev)		\
		container_of(dev, struct rockchip_rkvepu_dev, mpp_dev)

static int debug;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "bit switch for vepu1 debug information");

struct rockchip_rkvepu_dev {
	struct rockchip_mpp_dev mpp_dev;

	struct reset_control *rst_a;
	struct reset_control *rst_h;

	void *current_task;
};

struct rkvepu_task {
	struct mpp_task mpp_task;

	u32 reg[ROCKCHIP_VEPU2_REG_NUM];
	u32 idx;
	struct extra_info_for_iommu ext_inf;

	u32 strm_base;
	u32 irq_status;
};

/*
 * file handle translate information
 */
static const char trans_tbl_default[] = {
	77, 78, 56, 57, 63, 64, 48, 49, 50, 81
};

static const char trans_tbl_vp8e[] = {
	27, 44, 45, 48, 49, 50, 56, 57, 63, 64, 76, 77, 78, 80, 81, 106, 108
};

static struct mpp_trans_info trans_rk_vepu2[] = {
	[RKVEPU2_FMT_RESERVED] = {
		.count = 0,
		.table = NULL,
	},
	[RKVEPU2_FMT_VP8E] = {
		.count = sizeof(trans_tbl_vp8e),
		.table = trans_tbl_vp8e,
	},
	[RKVEPU2_FMT_JPEGE] = {
		.count = sizeof(trans_tbl_default),
		.table = trans_tbl_default,
	},
	[RKVEPU2_FMT_H264E] = {
		.count = sizeof(trans_tbl_default),
		.table = trans_tbl_default,
	},
};

static const struct mpp_dev_variant rkvepu_v2_data = {
	.reg_len = ROCKCHIP_VEPU2_REG_NUM,
	.trans_info = trans_rk_vepu2,
	.node_name = RKVEPU2_NODE_NAME,
};

static void *rockchip_rkvepu2_get_drv_data(struct platform_device *pdev);

static void *rockchip_mpp_rkvepu_alloc_task(struct mpp_session *session,
					    void __user *src, u32 size)
{
	struct rkvepu_task *task = NULL;
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

	reg_len = dwsize > ROCKCHIP_VEPU2_REG_NUM ?
		ROCKCHIP_VEPU2_REG_NUM : dwsize;
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

	fmt = RKVEPU2_GET_FORMAT(task->reg[RKVEPU2_REG_ENC_CTRL_INDEX]);
	err = mpp_reg_address_translate(session->mpp, &task->mpp_task, fmt,
					task->reg);
	if (err) {
		mpp_err("error: translate reg address failed.\n");

		if (unlikely(debug & DEBUG_DUMP_ERR_REG))
			mpp_debug_dump_reg_mem(task->reg,
					       ROCKCHIP_VEPU2_REG_NUM);
		goto fail;
	}

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

static int rockchip_mpp_rkvepu_prepare(struct rockchip_mpp_dev *mpp_dev,
				       struct mpp_task *task)
{
	return -EINVAL;
}

static int rockchip_mpp_rkvepu_run(struct rockchip_mpp_dev *mpp_dev,
				   struct mpp_task *mpp_task)
{
	struct rkvepu_task *task = NULL;
	struct rockchip_rkvepu_dev *enc_dev = NULL;

	mpp_debug_enter();

	task = to_rkvepu_task(mpp_task);
	enc_dev = to_rkvepu_dev(mpp_dev);

	/* FIXME: spin lock here */
	enc_dev->current_task = task;

	mpp_dev_write_seq(mpp_dev, 0,
			  &task->reg[0],
			  RKVEPU2_REG_ENC_CTRL_INDEX);

	mpp_dev_write_seq(mpp_dev, RKVPUE2_REG_DMV_4P_1P(0),
			  &task->reg[RKVPUE2_REG_DMV_4P_1P_INDEX(1)],
			  ROCKCHIP_VEPU2_REG_NUM
			  - RKVPUE2_REG_DMV_4P_1P_INDEX(0));

	/* Flush the registers */
	wmb();
	mpp_dev_write(mpp_dev, RKVEPU2_REG_ENC_CTRL,
		      task->reg[RKVEPU2_REG_ENC_CTRL_INDEX]
		      | RKVEPU2_ENC_START);

	mpp_debug_leave();

	return 0;
}

static int rockchip_mpp_rkvepu_finish(struct rockchip_mpp_dev *mpp_dev,
				      struct mpp_task *mpp_task)
{
	struct rkvepu_task *task = to_rkvepu_task(mpp_task);

	mpp_debug_enter();

	task->reg[RKVEPU2_REG_INT_INDEX] = task->irq_status;

	mpp_debug_leave();

	return 0;
}

static int rockchip_mpp_rkvepu_result(struct rockchip_mpp_dev *mpp_dev,
				      struct mpp_task *mpp_task,
				      u32 __user *dst, u32 size)
{
	struct rkvepu_task *task = to_rkvepu_task(mpp_task);

	/* FIXME may overflow the kernel */
	if (copy_to_user(dst, task->reg, size)) {
		mpp_err("copy_to_user failed\n");
		return -EIO;
	}

	return 0;
}

static int rockchip_mpp_rkvepu_free_task(struct mpp_session *session,
					 struct mpp_task *mpp_task)
{
	struct rkvepu_task *task = to_rkvepu_task(mpp_task);

	mpp_dev_task_finalize(session, mpp_task);
	kfree(task);

	return 0;
}

static irqreturn_t mpp_rkvepu_isr(int irq, void *dev_id)
{
	struct rockchip_rkvepu_dev *enc_dev = dev_id;
	struct rockchip_mpp_dev *mpp_dev = &enc_dev->mpp_dev;
	struct rkvepu_task *task = NULL;
	struct mpp_task *mpp_task = NULL;
	u32 irq_status;
	u32 err_mask;

	irq_status = mpp_dev_read(mpp_dev, RKVEPU2_REG_INT);
	if (!(irq_status & RKVEPU2_INT_RAW))
		return IRQ_NONE;

	mpp_dev_write(mpp_dev, RKVEPU2_REG_INT, RKVEPU2_INT_CLEAR);
	/* FIXME use a spin lock here */
	task = (struct rkvepu_task *)enc_dev->current_task;
	if (!task) {
		dev_err(enc_dev->mpp_dev.dev, "no current task\n");
		return IRQ_HANDLED;
	}

	mpp_task = &task->mpp_task;
	mpp_debug_time_diff(mpp_task);

	task->irq_status = irq_status;
	mpp_debug(DEBUG_IRQ_STATUS, "irq_status: %08x\n",
		  task->irq_status);

	err_mask = RKVEPU2_INT_TIMEOUT_EN
		| RKVEPU2_INT_BUF_FULL
		| RKVEPU2_INT_BUS_ERROR;

	if (err_mask & task->irq_status)
		atomic_set(&mpp_dev->reset_request, 1);

	mpp_dev_task_finish(mpp_task->session, mpp_task);

	mpp_debug_leave();
	return IRQ_HANDLED;

	return IRQ_NONE;
}

static int rockchip_mpp_rkvepu_assign_reset(struct rockchip_rkvepu_dev *enc_dev)
{
	struct rockchip_mpp_dev *mpp_dev = &enc_dev->mpp_dev;

	/* TODO: use devm_reset_control_get_share() instead */
	enc_dev->rst_a = devm_reset_control_get(mpp_dev->dev, "video_a");
	enc_dev->rst_h = devm_reset_control_get(mpp_dev->dev, "video_h");

	if (IS_ERR_OR_NULL(enc_dev->rst_a)) {
		mpp_err("No aclk reset resource define\n");
		enc_dev->rst_a = NULL;
	}

	if (IS_ERR_OR_NULL(enc_dev->rst_h)) {
		mpp_err("No hclk reset resource define\n");
		enc_dev->rst_h = NULL;
	}

	return 0;
}

static int rockchip_mpp_rkvepu_reset(struct rockchip_mpp_dev *mpp_dev)
{
	struct rockchip_rkvepu_dev *enc = to_rkvepu_dev(mpp_dev);

	if (enc->rst_a && enc->rst_h) {
		mpp_debug(DEBUG_RESET, "reset in\n");

		/* Don't skip this or iommu won't work after reset */
		rockchip_pmu_idle_request(mpp_dev->dev, true);
		safe_reset(enc->rst_a);
		safe_reset(enc->rst_h);
		udelay(5);
		safe_unreset(enc->rst_h);
		safe_unreset(enc->rst_a);
		rockchip_pmu_idle_request(mpp_dev->dev, false);

		mpp_dev_write(mpp_dev, RKVEPU2_REG_INT, RKVEPU2_INT_CLEAR);
		enc->current_task = NULL;
		mpp_debug(DEBUG_RESET, "reset out\n");
	}

	return 0;
}

static struct mpp_dev_ops rkvepu_ops = {
	.alloc_task = rockchip_mpp_rkvepu_alloc_task,
	.prepare = rockchip_mpp_rkvepu_prepare,
	.run = rockchip_mpp_rkvepu_run,
	.finish = rockchip_mpp_rkvepu_finish,
	.result = rockchip_mpp_rkvepu_result,
	.free_task = rockchip_mpp_rkvepu_free_task,
	.reset = rockchip_mpp_rkvepu_reset,
};

static int rockchip_mpp_rkvepu_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rockchip_rkvepu_dev *enc_dev = NULL;
	struct rockchip_mpp_dev *mpp_dev = NULL;
	int ret = 0;

	enc_dev = devm_kzalloc(dev, sizeof(struct rockchip_rkvepu_dev),
			       GFP_KERNEL);
	if (!enc_dev)
		return -ENOMEM;

	mpp_dev = &enc_dev->mpp_dev;
	mpp_dev->variant = rockchip_rkvepu2_get_drv_data(pdev);
	ret = mpp_dev_common_probe(mpp_dev, pdev, &rkvepu_ops);
	if (ret)
		return ret;

	ret = devm_request_threaded_irq(dev, mpp_dev->irq, NULL, mpp_rkvepu_isr,
					IRQF_SHARED | IRQF_ONESHOT,
					dev_name(dev), enc_dev);
	if (ret) {
		dev_err(dev, "register interrupter runtime failed\n");
		return ret;
	}

	rockchip_mpp_rkvepu_assign_reset(enc_dev);

	ret = mpp_dev_register_node(mpp_dev, mpp_dev->variant->node_name, NULL);
	if (ret)
		dev_err(dev, "register char device failed: %d\n", ret);

	dev_info(dev, "probing finish\n");

	platform_set_drvdata(pdev, enc_dev);

	return 0;
}

static int rockchip_mpp_rkvepu_remove(struct platform_device *pdev)
{
	struct rockchip_rkvepu_dev *enc_dev = platform_get_drvdata(pdev);

	mpp_dev_common_remove(&enc_dev->mpp_dev);

	return 0;
}

static const struct of_device_id mpp_rkvepu2_dt_match[] = {
	{ .compatible = "rockchip,vpu-encoder-v2", .data = &rkvepu_v2_data},
	{},
};

static void *rockchip_rkvepu2_get_drv_data(struct platform_device *pdev)
{
	struct mpp_dev_variant *driver_data = NULL;

	if (pdev->dev.of_node) {
		const struct of_device_id *match;

		match = of_match_node(mpp_rkvepu2_dt_match, pdev->dev.of_node);
		if (match)
			driver_data = (struct mpp_dev_variant *)match->data;
	}
	return driver_data;
}

static struct platform_driver rockchip_rkvepu2_driver = {
	.probe = rockchip_mpp_rkvepu_probe,
	.remove = rockchip_mpp_rkvepu_remove,
	.driver = {
		.name = RKVEPU2_DRIVER_NAME,
		.of_match_table = of_match_ptr(mpp_rkvepu2_dt_match),
	},
};

static int __init mpp_dev_rkvepu2_init(void)
{
	int ret = platform_driver_register(&rockchip_rkvepu2_driver);

	if (ret) {
		mpp_err("Platform device register failed (%d).\n", ret);
		return ret;
	}

	return ret;
}

static void __exit mpp_dev_rkvepu2_exit(void)
{
	platform_driver_unregister(&rockchip_rkvepu2_driver);
}

module_init(mpp_dev_rkvepu2_init);
module_exit(mpp_dev_rkvepu2_exit);

MODULE_DEVICE_TABLE(of, mpp_rkvepu2_dt_match);
MODULE_LICENSE("GPL v2");
