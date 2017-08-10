ccflags-y += -I${src}/include -DCONFIG_DRM=1

rk-vcodec-objs := vcodec_service.o vcodec_iommu_ops.o

rk-vcodec-objs += vcodec_iommu_drm.o

obj-m += rk-vcodec.o

