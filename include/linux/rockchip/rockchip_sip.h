/* Copyright (c) 2016, Fuzhou Rockchip Electronics Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef __ROCKCHIP_SIP_H
#define __ROCKCHIP_SIP_H

#include <linux/arm-smccc.h>
#include <linux/io.h>

/* SMC function IDs for SiP Service queries, compatible with kernel-3.10 */
#define SIP_ATF_VERSION			0x82000001
#define SIP_ACCESS_REG			0x82000002
#define SIP_SUSPEND_MODE		0x82000003
#define SIP_PENDING_CPUS		0x82000004
#define SIP_UARTDBG_CFG			0x82000005
#define SIP_UARTDBG_CFG64		0xc2000005
#define SIP_MCU_EL3FIQ_CFG		0x82000006
#define SIP_ACCESS_CHIP_STATE64		0xc2000006
#define SIP_SECURE_MEM_CONFIG		0x82000007
#define SIP_ACCESS_CHIP_EXTRA_STATE64	0xc2000007
#define SIP_DRAM_CONFIG			0x82000008
#define SIP_SHARE_MEM			0x82000009
#define SIP_SIP_VERSION			0x8200000a
#define SIP_REMOTECTL_CFG		0x8200000b

/* Rockchip Sip version */
#define SIP_IMPLEMENT_V1                (1)
#define SIP_IMPLEMENT_V2                (2)

/* Trust firmware version */
#define ATF_VER_MAJOR(ver)		(((ver) >> 16) & 0xffff)
#define ATF_VER_MINOR(ver)		(((ver) >> 0) & 0xffff)

/* SIP_ACCESS_REG: read or write */
#define SECURE_REG_RD			0x0
#define SECURE_REG_WR			0x1

/* Fiq debugger share memory: 8KB enough */
#define FIQ_UARTDBG_PAGE_NUMS		2
#define FIQ_UARTDBG_SHARE_MEM_SIZE	((FIQ_UARTDBG_PAGE_NUMS) * 4096)

/* Error return code */
#define IS_SIP_ERROR(x)			(!!(x))

#define SIP_RET_SUCCESS			0
#define SIP_RET_SMC_UNKNOWN		-1
#define SIP_RET_NOT_SUPPORTED		-2
#define SIP_RET_INVALID_PARAMS		-3
#define SIP_RET_INVALID_ADDRESS		-4
#define SIP_RET_DENIED			-5

/* SIP_UARTDBG_CFG64 call types */
#define UARTDBG_CFG_INIT		0xf0
#define UARTDBG_CFG_OSHDL_TO_OS		0xf1
#define UARTDBG_CFG_OSHDL_CPUSW		0xf3
#define UARTDBG_CFG_OSHDL_DEBUG_ENABLE	0xf4
#define UARTDBG_CFG_OSHDL_DEBUG_DISABLE	0xf5
#define UARTDBG_CFG_PRINT_PORT		0xf7
#define UARTDBG_CFG_FIQ_ENABEL		0xf8
#define UARTDBG_CFG_FIQ_DISABEL		0xf9

/* SIP_SUSPEND_MODE32 call types */
#define SUSPEND_MODE_CONFIG		0x01
#define WKUP_SOURCE_CONFIG		0x02
#define PWM_REGULATOR_CONFIG		0x03
#define GPIO_POWER_CONFIG		0x04
#define SUSPEND_DEBUG_ENABLE		0x05
#define APIOS_SUSPEND_CONFIG		0x06
#define VIRTUAL_POWEROFF		0x07

/* SIP_REMOTECTL_CFG call types */
#define	REMOTECTL_SET_IRQ		0xf0
#define REMOTECTL_SET_PWM_CH		0xf1
#define REMOTECTL_SET_PWRKEY		0xf2
#define REMOTECTL_GET_WAKEUP_STATE	0xf3
#define REMOTECTL_ENABLE		0xf4
/* wakeup state */
#define REMOTECTL_PWRKEY_WAKEUP		0xdeadbeaf

/* Share mem page types */
typedef enum {
	SHARE_PAGE_TYPE_INVALID = 0,
	SHARE_PAGE_TYPE_UARTDBG,
	SHARE_PAGE_TYPE_DDR,
	SHARE_PAGE_TYPE_MAX,
} share_page_type_t;

/*
 * Rules: struct arm_smccc_res contains result and data, details:
 *
 * a0: error code(0: success, !0: error);
 * a1~a3: data
 */
#ifdef CONFIG_ROCKCHIP_SIP
struct arm_smccc_res sip_smc_get_atf_version(void);
struct arm_smccc_res sip_smc_get_sip_version(void);
struct arm_smccc_res sip_smc_dram(u32 arg0, u32 arg1, u32 arg2);
struct arm_smccc_res sip_smc_request_share_mem(u32 page_num,
					       share_page_type_t page_type);
struct arm_smccc_res sip_smc_mcu_el3fiq(u32 arg0, u32 arg1, u32 arg2);

int sip_smc_set_suspend_mode(u32 ctrl, u32 config1, u32 config2);
int sip_smc_virtual_poweroff(void);

int sip_smc_secure_reg_write(u32 addr_phy, u32 val);
u32 sip_smc_secure_reg_read(u32 addr_phy);

/***************************fiq debugger **************************************/
void sip_fiq_debugger_enable_fiq(bool enable, uint32_t tgt_cpu);
void sip_fiq_debugger_enable_debug(bool enable);
int sip_fiq_debugger_uart_irq_tf_init(u32 irq_id, void *callback_fn);
int sip_fiq_debugger_set_print_port(u32 port_phyaddr, u32 baudrate);
int sip_fiq_debugger_request_share_memory(void);
int sip_fiq_debugger_get_target_cpu(void);
int sip_fiq_debugger_switch_cpu(u32 cpu);
int sip_fiq_debugger_is_enabled(void);
#else
static inline struct arm_smccc_res sip_smc_get_atf_version(void)
{
	struct arm_smccc_res tmp = {0};
	return tmp;
}

static inline struct arm_smccc_res sip_smc_get_sip_version(void)
{
	struct arm_smccc_res tmp = {0};
	return tmp;
}

static inline struct arm_smccc_res sip_smc_dram(u32 arg0, u32 arg1, u32 arg2)
{
	struct arm_smccc_res tmp = {0};
	return tmp;
}

static inline struct arm_smccc_res sip_smc_request_share_mem
			(u32 page_num, share_page_type_t page_type)
{
	struct arm_smccc_res tmp = {0};
	return tmp;
}

static inline struct arm_smccc_res sip_smc_mcu_el3fiq
			(u32 arg0, u32 arg1, u32 arg2)
{
	struct arm_smccc_res tmp = {0};
	return tmp;
}

static inline int sip_smc_set_suspend_mode(u32 ctrl, u32 config1, u32 config2)
{
	return 0;
}

static inline int sip_smc_virtual_poweroff(void) { return 0; }
static inline u32 sip_smc_secure_reg_read(u32 addr_phy) { return 0; }
static inline int sip_smc_secure_reg_write(u32 addr_phy, u32 val) { return 0; }

/***************************fiq debugger **************************************/
static inline void sip_fiq_debugger_enable_fiq
			(bool enable, uint32_t tgt_cpu) { return; }

static inline void sip_fiq_debugger_enable_debug(bool enable) { return; }
static inline int sip_fiq_debugger_uart_irq_tf_init(u32 irq_id,
						    void *callback_fn)
{
	return 0;
}

static inline int sip_fiq_debugger_set_print_port(u32 port_phyaddr,
						  u32 baudrate)
{
	return 0;
}

static inline int sip_fiq_debugger_request_share_memory(void) { return 0; }
static inline int sip_fiq_debugger_get_target_cpu(void) { return 0; }
static inline int sip_fiq_debugger_switch_cpu(u32 cpu) { return 0; }
static inline int sip_fiq_debugger_is_enabled(void) { return 0; }
#endif

/* optee cpu_context */
struct sm_nsec_ctx {
	u32 usr_sp;
	u32 usr_lr;
	u32 irq_spsr;
	u32 irq_sp;
	u32 irq_lr;
	u32 svc_spsr;
	u32 svc_sp;
	u32 svc_lr;
	u32 abt_spsr;
	u32 abt_sp;
	u32 abt_lr;
	u32 und_spsr;
	u32 und_sp;
	u32 und_lr;
	u32 mon_lr;
	u32 mon_spsr;
	u32 r4;
	u32 r5;
	u32 r6;
	u32 r7;
	u32 r8;
	u32 r9;
	u32 r10;
	u32 r11;
	u32 r12;
	u32 r0;
	u32 r1;
	u32 r2;
	u32 r3;
};

#endif
