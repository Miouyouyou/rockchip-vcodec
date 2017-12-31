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

#ifndef __VCODEC_IOMMU_DMA_H__
#define __VCODEC_IOMMU_DMA_H__

#include <linux/dma-mapping.h>

struct vcodec_iommu_info;
struct vcodec_dma_session;

struct vcodec_dma_session *vcodec_dma_session_create(struct device *dev);
void vcodec_dma_destroy_session(struct vcodec_dma_session *session);

dma_addr_t vcodec_dma_import_fd(struct vcodec_dma_session *session, int fd);
int vcodec_dma_release_fd(struct vcodec_dma_session *session, int fd);

struct vcodec_iommu_info *vcodec_iommu_probe(struct device *dev);
int vcodec_iommu_remove(struct vcodec_iommu_info *info);

int vcodec_iommu_attach(struct vcodec_iommu_info *info);
void vcodec_iommu_detach(struct vcodec_iommu_info *info);

#endif
