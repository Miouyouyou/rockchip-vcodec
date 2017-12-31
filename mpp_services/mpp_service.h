/*
 * Copyright (C) 2016 Fuzhou Rockchip Electronics Co., Ltd
 * author: chenhengming chm@rock-chips.com
 *	   Alpha Lin, alpha.lin@rock-chips.com
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

#ifndef __ROCKCHIP_MPP_SERVICE_H
#define __ROCKCHIP_MPP_SERVICE_H

#include "mpp_dev_common.h"

enum mpp_srv_state {
	HW_RUNNING	= BIT(1)
};

struct mpp_service {
	/* service structure global lock */
	struct mutex lock;
	struct list_head pending;
	struct list_head done;
	/* serivce critical time lock */
	struct mutex running_lock;
	struct list_head running;
	/* link to list_session in struct mpp_session */
	struct list_head session;

	struct device *dev;

	u32 dev_cnt;
	struct list_head subdev_list;
};

void mpp_srv_lock(struct mpp_service *pservice);
void mpp_srv_unlock(struct mpp_service *pservice);
void mpp_srv_pending_locked(struct mpp_service *pservice,
			    struct mpp_task *task);
void mpp_srv_run(struct mpp_service *pservice, struct mpp_task *task);
void mpp_srv_done(struct mpp_service *pservice, struct mpp_task *task);
int mpp_srv_abort(struct mpp_service *pservice, struct mpp_task *task);
void mpp_srv_attach(struct mpp_service *pservice, struct list_head *elem);
void mpp_srv_detach(struct mpp_service *pservice, struct list_head *elem);
struct mpp_task *mpp_srv_get_pending_task(struct mpp_service *pservice);
struct mpp_task *mpp_srv_get_current_task(struct mpp_service *pservice);
void mpp_srv_wait_to_run(struct mpp_service *pservice);

struct mpp_task *mpp_srv_get_done_task(struct mpp_session *session);
bool mpp_srv_is_power_on(struct mpp_service *pservice);
int mpp_srv_is_running(struct mpp_service *pservice);

#endif
