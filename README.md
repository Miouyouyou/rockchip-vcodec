If you appreciate this project, support me on Patreon !

[![Patreon !](https://raw.githubusercontent.com/Miouyouyou/RockMyy/master/.img/button-patreon.png)](https://www.patreon.com/Miouyouyou)

# About

This repository goal is to focus on this Rockchip VPU driver code in
order to use it with 4.13 kernels and onward.

Most of the code is written by the Rockchip engineers, in the
[rockchip_forwardports](https://github.com/rockchip-linux/rockchip_forwardports)
repository initiated by [phh](https://github.com/phhusson), and updated
by [wzyy2](https://github.com/wzyy2), and in the 
[kernel 4.4 patched and maintained by Rockchip](https://github.com/rockchip-linux/kernel).

[phh](https://github.com/phhusson) took care of making it compilable in
an Out-Of-Tree fashion.

Currently being tested against
[RockMyy-Build](https://github.com/Miouyouyou/RockMyy-Build) kernels.
Note that this might generate crashes and/or freezes in its current
state.

The kernel patches required to use this driver will be integrated in
RockMyy and RockMyy-Build this week-end.
If you're in a hurry, for whatever reason,
[the patch is here](https://raw.githubusercontent.com/Miouyouyou/MyyQi/master/patches/kernel/v4.11/0012-Export-rockchip_pmu_set_idle_request-for-out-of-tree.patch).

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
