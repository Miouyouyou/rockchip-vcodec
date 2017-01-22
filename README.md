# About

The rockchip VPU service driver itself that can be built as an 
Out-Of-Tree module.

You'll still need a [patched kernel](https://github.com/Miouyouyou/MyyQi/blob/master/patches/kernel/v4.10-rc4/0013-Export-rockchip_pmu_set_idle_request-for-out-of-tree.patch) 
to compile these drivers, as some Rockchip Power domains symbols are 
required to compile this module successfully, and therefore need to be
exported.

You'll also need [several modifications to your DTS files](https://github.com/Miouyouyou/MyyQi/blob/master/patches/kernel/v4.10-rc4/0012-arm-dts-Adding-and-enabling-VPU-services-addresses-f.patch) if 
you're using a mainline kernel.

# Compilation

## If you're cross-compiling

If you're cross-compiling this module, first set the `ARCH` and 
`CROSS_COMPILE` variables. If you're compiling from the Rockchip board
itself, skip this example.

Example :

``bash
export ARCH=arm 
export CROSS_COMPILE=armv7a-hardfloat-linux-gnueabi-
``

## Anyway

To compile this module, type the following :

    make M=$PWD -C /path/to/linux/sources CONFIG_RK_VCODEC=m

The command will generate a 'rk-vcodec.ko' file that you can `insmod`
on the Rockchip board executing the kernel generated from the sources
you specified.

# Installation

## If you're cross-compiling

Type the following command as **root**

    make INSTALL_PATH=/install_root M=$PWD -C /path/to/linux/sources CONFIG_RK_VCODEC=m

Note that this will install `extra/rk-vcodec.ko`, along with the others
kernel modules, in `/install_root/lib/modules/kernel_version/kernel`. 
Once you copy the modules directory in the board's `/lib` directory, 
you'll be able to modprobe the module directly from the board.

The kernel will also try to auto-load the module when possible.

## If you're compiling directly

    make M=$PWD -C /path/to/linux/sources CONFIG_RK_VCODEC=m modules_install

The module will then be loaded at boot. You can still load it directly through
`modprobe rk-vcodec`.

# Todo

Find a way to use the Makefile to build the module directly, with 
parameters setup with some kind of configuration system
(Cmake, autotools)...

