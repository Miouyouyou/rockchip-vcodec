# Set this variable with the path to your kernel.
# Don't use /usr/src/linux if you're cross-compiling...
MYY_KERNEL_DIR ?= ../linux

# If you're compiling for ARM64, this will be arm64
ARCH ?= arm

# This is the prefix attached to your cross-compiling gcc/ld/... tools
# In my case, gcc is armv7a-hardfloat-linux-gnueabi-gcc
# If you've installed cross-compiling tools and don't know your 
# prefix, just type "arm" in a shell, hit <TAB> twice
#
# If you're compiling from ARM system with the same architecture
# (arm on arm or arm64 on arm64) delete the characters after "?="
CROSS_COMPILE ?= armv7a-hardfloat-linux-gnueabi-

# The modules will be installed in $(INSTALL_MOD_PATH)/lib/...
# That might not be needed at all, if you're replacing the "install"
# command, see below.
INSTALL_MOD_PATH ?= /tmp/RockMyy-Build
INSTALL_PATH     ?= $(INSTALL_MOD_PATH)/boot
INSTALL_HDR_PATH ?= $(INSTALL_MOD_PATH)/usr

# Determine the CFLAGS specific to this compilation unit.
ccflags-y += -I${src}/include -DCONFIG_DRM=1

# Determine what's needed to compile rk-vcodec.o
# Every '.o' file corresponds to a '.c' file.
rk-vcodec-objs := vcodec_service.o vcodec_iommu_ops.o
rk-vcodec-objs += vcodec_iommu_drm.o

# Replace m by y if you want to integrate it or
# replace it by a configuration option that should be enabled when
# configuring the kernel like obj-$(CONFIG_CRASHY_THE_VPU)
obj-m += rk-vcodec.o

all:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) M=$(PWD) -C $(MYY_KERNEL_DIR) modules

clean:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) M=$(PWD) -C $(MYY_KERNEL_DIR) clean

# This does a normal installation...
# You could replace this by a scp command that sends the module to
# your ARM system.
install:
	make INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) INSTALL_PATH=$(INSTALL_PATH) INSTALL_HDR_PATH=$(INSTALL_HDR_PATH) M=$(PWD) -C $(MYY_KERNEL_DIR) modules_install
#	scp *.ko 10.100.0.55:/tmp
