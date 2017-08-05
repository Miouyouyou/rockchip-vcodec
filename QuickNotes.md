# VPU registers

Registers are numbered starting from 0.

Informations obtained through the vcoded_service.c file.

## Register 0
### VPU hardware type ?
VPU Hardward type : the first register, it seems.
```c
hw_id = readl_relaxed(data->regs);
```

## Register 3
### Frame format
Frame format : 28th to 32th bits of Register 3
```c
frame_format = ((reg[3] >> 28) & 0xf);
```
> 0xf is only useful when using more than 32 bits to encode the
  register.

### Interlacing
Interlacing : 23th bits of Register 3.
```c
is_interlaced = (reg[3] >> 23);
```

## Register 4
### Width
Width (in MB ??) : Starting from the 23th of Register 4 (Max bits unknown...)
```c
width_in_mb = (reg[4] >> 23) * 16;
```
> The `* 16` comes from the provided code... Why is that necessary though ?

## Register 8
### HEVC Y Stride
HEVC Y Stride : The 8th register content define the HEVC Y Stride.
```c
hevc_stride = reg[8];
```

# Call order

```
(file_operations)
open
	
unlocked_ioctl
	vpu_service_ioctl
		reg_init
			vcodec_reg_address_translate
				vcodec_bufid_to_iova
```

# Global workflow

## open

Allocate kernel memory to store one session data.
Initialize a session structure at the allocated memory address.
Set it to the private_data field of the provided file structure.
(See Linux kernels file_operations for details about the ways struct
 file is passed.)

# To determine

**Which system is used in the end ? VPU ? VPU2 ? RKVENC ?**

There's no need to maintain 3 systems at once. This driver aim to be
used with mainline Linux kernels, starting from versio 4.12.

