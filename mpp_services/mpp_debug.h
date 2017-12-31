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

#ifndef _ROCKCHIP_MPP_DEBUG_H_
#define _ROCKCHIP_MPP_DEBUG_H_

#include <linux/types.h>

/*
 * debug flag usage:
 * +------+-------------------+
 * | 8bit |      24bit        |
 * +------+-------------------+
 *  0~23 bit is for different information type
 * 24~31 bit is for information print format
 */

#define DEBUG_POWER				0x00000001
#define DEBUG_CLOCK				0x00000002
#define DEBUG_IRQ_STATUS			0x00000004
#define DEBUG_IOMMU				0x00000008
#define DEBUG_IOCTL				0x00000010
#define DEBUG_FUNCTION				0x00000020
#define DEBUG_REGISTER				0x00000040
#define DEBUG_EXTRA_INFO			0x00000080
#define DEBUG_TIMING				0x00000100
#define DEBUG_TASK_INFO				0x00000200
#define DEBUG_DUMP_ERR_REG			0x00000400
#define DEBUG_LINK_TABLE			0x00000800

#define DEBUG_SET_REG				0x00001000
#define DEBUG_GET_REG				0x00002000
#define DEBUG_PPS_FILL				0x00004000
#define DEBUG_IRQ_CHECK				0x00008000
#define DEBUG_CACHE_32B				0x00010000

#define DEBUG_RESET				0x00020000

#define PRINT_FUNCTION				0x80000000
#define PRINT_LINE				0x40000000

#define mpp_debug_func(type, fmt, args...)			\
	do {							\
		if (unlikely(debug & type)) {			\
			pr_info("%s:%d: " fmt,			\
				 __func__, __LINE__, ##args);	\
		}						\
	} while (0)
#define mpp_debug(type, fmt, args...)				\
	do {							\
		if (unlikely(debug & type)) {			\
			pr_info(fmt, ##args);			\
		}						\
	} while (0)

#define mpp_debug_enter()					\
	do {							\
		if (unlikely(debug & DEBUG_FUNCTION)) {		\
			pr_info("%s:%d: enter\n",		\
				 __func__, __LINE__);		\
		}						\
	} while (0)

#define mpp_debug_leave()					\
	do {							\
		if (unlikely(debug & DEBUG_FUNCTION)) {		\
			pr_info("%s:%d: leave\n",		\
				 __func__, __LINE__);		\
		}						\
	} while (0)

#define mpp_err(fmt, args...)					\
		pr_err("%s:%d: " fmt, __func__, __LINE__, ##args)

#endif
