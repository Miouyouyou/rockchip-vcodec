ccflags-y += -I${src}/include

rk-vcodec-objs := vcodec_service.o vcodec_iommu_ops.o

rk-vcodec-objs += vcodec_iommu_drm.o

obj-$(CONFIG_RK_VCODEC) += rk-vcodec.o

