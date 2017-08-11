If you appreciate this project, support me on Patreon !

[![Patreon !](https://raw.githubusercontent.com/Miouyouyou/RockMyy/master/.img/button-patreon.png)](https://www.patreon.com/Miouyouyou)

# State

Unusable at the moment, a good part, if not the entire driver needs to
be rewritten using up to date APIs, as some parts of the current driver
are in an unmaintainable state, it seems.

Take a look at the Wiki for more info.

The rewrite takes place in the
[DRM_rewrite](https://github.com/Miouyouyou/rockchip-vcodec/tree/DRM_rewrite)
branch.

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

You'll need a patched kernel anyway if you want to test this VPU code.
The patches required are in the [kernel_patches](./kernel_patches)
directory.

# Build

You'll need to edit the Makefile and check the following variables :
```make
MYY_KERNEL_DIR
ARCH
CROSS_COMPILE
```
or export these variables before :
```bash
export MYY_KERNEL_DIR=/path/to/my/arm/linux
export ARCH=arm
export CROSS_COMPILE=armv7a-hardfloat-linux-gnueabi-
```

## Clean up

`make clean`

## Compilation

`make`

## Installation

Copy all the module files to your ARM system and load them from there.

Something like :

```bash
scp rk-vcodec.ko my_rk3288_board:/tmp
```

# Loading the module

Following the previous SCP example :

```bash
ssh my_rk3288_board
# Once connected to the board through SSH
sudo insmod /tmp/rk-vcodec.ko
```

If you have a direct access to the board, just type the last command.
