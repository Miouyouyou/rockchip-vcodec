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

#ifndef __VCODEC_IOMMU_DMA_H__
#define __VCODEC_IOMMU_DMA_H__

#include <linux/dma-mapping.h>

struct mpp_iommu_info;
struct mpp_dma_session;

struct mpp_dma_session *mpp_dma_session_create(struct device *dev);
void mpp_dma_destroy_session(struct mpp_dma_session *session);

dma_addr_t mpp_dma_import_fd(struct mpp_dma_session *session, int fd);
int mpp_dma_release_fd(struct mpp_dma_session *session, int fd);

struct mpp_iommu_info *mpp_iommu_probe(struct device *dev);
int mpp_iommu_remove(struct mpp_iommu_info *info);

int mpp_iommu_attach(struct mpp_iommu_info *info);
void mpp_iommu_detach(struct mpp_iommu_info *info);

#endif
