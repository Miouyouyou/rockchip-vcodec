#ifndef __MACH_ROCKCHIP_CRU_H
#define __MACH_ROCKCHIP_CRU_H

#include <dt-bindings/clock/rockchip,rk3188.h>
#include <dt-bindings/clock/rockchip,rk3288.h>
#include <linux/rockchip/iomap.h>


/*******************CRU BITS*******************************/

#define CRU_W_MSK(bits_shift, msk)	((msk) << ((bits_shift) + 16))

#define CRU_SET_BITS(val, bits_shift, msk)	(((val)&(msk)) << (bits_shift))

#define CRU_W_MSK_SETBITS(val, bits_shift,msk) \
	(CRU_W_MSK(bits_shift, msk) | CRU_SET_BITS(val, bits_shift, msk))

/*******************RK3188********************************/
/*******************CRU OFFSET*********************/
#define RK3188_CRU_MODE_CON		0x40
#define RK3188_CRU_CLKSEL_CON		0x44
#define RK3188_CRU_CLKGATE_CON		0xd0
#define RK3188_CRU_GLB_SRST_FST		0x100
#define RK3188_CRU_GLB_SRST_SND		0x104
#define RK3188_CRU_SOFTRST_CON		0x110

#define RK3188_PLL_CONS(id, i)		((id) * 0x10 + ((i) * 4))

#define RK3188_CRU_CLKSELS_CON_CNT	(35)
#define RK3188_CRU_CLKSELS_CON(i)	(RK3188_CRU_CLKSEL_CON + ((i) * 4))

#define RK3188_CRU_CLKGATES_CON_CNT	(10)
#define RK3188_CRU_CLKGATES_CON(i)	(RK3188_CRU_CLKGATE_CON + ((i) * 4))

#define RK3188_CRU_SOFTRSTS_CON_CNT	(9)
#define RK3188_CRU_SOFTRSTS_CON(i)	(RK3188_CRU_SOFTRST_CON + ((i) * 4))

#define RK3188_CRU_MISC_CON		(0x134)
#define RK3188_CRU_GLB_CNT_TH		(0x140)

/******************PLL MODE BITS*******************/
#define RK3188_PLL_MODE_MSK(id)		(0x3 << ((id) * 4))
#define RK3188_PLL_MODE_SLOW(id)	((0x0<<((id)*4))|(0x3<<(16+(id)*4)))
#define RK3188_PLL_MODE_NORM(id)	((0x1<<((id)*4))|(0x3<<(16+(id)*4)))
#define RK3188_PLL_MODE_DEEP(id)	((0x2<<((id)*4))|(0x3<<(16+(id)*4)))

/******************CRU GATINGS**********************************/
#define RK3188_CRU_GATEID_CONS(ID) (RK3188_CRU_CLKGATE_CON+(ID/16)*4)

/*************************RK3288********************************/

/*******************CRU OFFSET*********************/
#define RK3288_CRU_MODE_CON		0x50
#define RK3288_CRU_CLKSEL_CON		0x60
#define RK3288_CRU_CLKGATE_CON		0x160

#define RK3288_PLL_CONS(id, i)		((id) * 0x10 + ((i) * 4))
#define RK3288_CRU_CLKSELS_CON(i)	(RK3288_CRU_CLKSEL_CON + ((i) * 4))
#define RK3288_CRU_CLKGATES_CON(i)	(RK3288_CRU_CLKGATE_CON + ((i) * 4))

/******************PLL MODE BITS*******************/
/*************apll dpll,cpll,gpll,npll 0~4************/
#define RK3288_PLLS_MODE_OFFSET(id) ((id)<=3 ? (id*4) : 14)
#define RK3288_PLL_MODE_MSK(id)		(0x3 << RK3288_PLLS_MODE_OFFSET(id))
#define RK3288_PLL_MODE_SLOW(id)	((0x0<<RK3288_PLLS_MODE_OFFSET(id))|(0x3<<(16+RK3288_PLLS_MODE_OFFSET(id))))
#define RK3288_PLL_MODE_NORM(id)	((0x1<<RK3288_PLLS_MODE_OFFSET(id))|(0x3<<(16+RK3288_PLLS_MODE_OFFSET(id))))
#define RK3288_PLL_MODE_DEEP(id)	((0x2<<RK3288_PLLS_MODE_OFFSET(id))|(0x3<<(16+RK3288_PLLS_MODE_OFFSET(id))))

/*******************CRU GATING*********************/
#define RK3288_CRU_CLKGATES_CON_CNT (19)
#define RK3288_CRU_CONS_GATEID(i)	(16 * (i))
#define RK3288_CRU_GATEID_CONS(ID)	(RK3288_CRU_CLKGATE_CON+(ID/16)*4)

enum rk3288_cru_clk_gate {
	/* SCU CLK GATE 0 CON */
	RK3288_CLKGATE_UART0_SRC    =   (RK3288_CRU_CONS_GATEID(1)+8),   
	
	RK3288_CLKGATE_UART4_SRC    =   (RK3288_CRU_CONS_GATEID(2)+12),   
	
        RK3288_CLKGATE_PCLK_UART0= (RK3288_CRU_CONS_GATEID(6)+8),   
        RK3288_CLKGATE_PCLK_UART1,
        RK3288_CLKGATE6_DUMP1,
        RK3288_CLKGATE_PCLK_UART3,
        RK3288_CLKGATE_PCLK_I2C2,
        RK3288_CLKGATE_PCLK_I2C3,
        RK3288_CLKGATE_PCLK_I2C4,

    	RK3288_CLKGATE_PCLK_I2C0    =   (RK3288_CRU_CONS_GATEID(10)+2),	
	RK3288_CLKGATE_PCLK_I2C1,
	
        RK3288_CLKGATE_PCLK_UART2    =   (RK3288_CRU_CONS_GATEID(11)+9), 

    
	RK3288_CLKGATE_PCLK_GPIO1   =   (RK3288_CRU_CONS_GATEID(14)+1),
	
	RK3288_CLKGATE_PCLK_GPIO0   =   (RK3288_CRU_CONS_GATEID(17)+4),
        //gate6
};

#define RK3288_CRU_GLB_SRST_FST_VALUE   0x1b0
#define RK3288_CRU_GLB_SRST_SND_VALUE   0x1b4
#define RK3288_CRU_SOFTRST_CON          0x1b8
#define RK3288_CRU_MISC_CON             0x1e8
#define RK3288_CRU_GLB_CNT_TH           0x1ec
#define RK3288_CRU_GLB_RST_CON          0x1f0
#define RK3288_CRU_GLB_RST_ST           0x1f8
#define RK3288_CRU_SDMMC_CON0           0x200
#define RK3288_CRU_SDMMC_CON1           0x204
#define RK3288_CRU_SDIO0_CON0           0x208
#define RK3288_CRU_SDIO0_CON1           0x20c
#define RK3288_CRU_SDIO1_CON0           0x210
#define RK3288_CRU_SDIO1_CON1           0x214
#define RK3288_CRU_EMMC_CON0            0x218
#define RK3288_CRU_EMMC_CON1            0x21c

#define RK3288_CRU_SOFTRSTS_CON_CNT	(12)
#define RK3288_CRU_SOFTRSTS_CON(i)	(RK3288_CRU_SOFTRST_CON + ((i) * 4))

static inline void rk3288_cru_set_soft_reset(u32 idx, bool on)
{
	void __iomem *reg = RK_CRU_VIRT + RK3288_CRU_SOFTRSTS_CON(idx >> 4);
	u32 val = on ? 0x10001U << (idx & 0xf) : 0x10000U << (idx & 0xf);
	writel_relaxed(val, reg);
	dsb(sy);
}

#define RK3036_CRU_MODE_CON 0x0040

/******************PLL MODE BITS*******************/
/****************apll dpll,gpll 0~2******************/
#define RK3036_PLLS_MODE_OFFSET(id) ((id) < 2 ? (id*4) : 12)

#define RK3036_PLL_MODE_SLOW(id)	((0x0 << RK3036_PLLS_MODE_OFFSET(id)) \
	| (((id) < 2 ? 0x1 : 0x3) << (16 + RK3036_PLLS_MODE_OFFSET(id))))

#define RK3036_PLL_MODE_MSK(id)	(0x1 << RK3036_PLLS_MODE_OFFSET(id))

#define RK3036_APLL_MODE_SLOW	((0x0<<0x00)|(0x1<<(16+0x00)))
#define RK3036_DPLL_MODE_SLOW	((0x0<<0x04)|(0x1<<(16+0x04)))
#define RK3036_GPLL_MODE_SLOW	((0x0<<0x12)|(0x3<<(16+0x12)))

#define RK3036_APLL_MODE_NORM	((0x1<<0x00)|(0x1<<(16+0x00)))
#define RK3036_DPLL_MODE_NORM	((0x1<<0x04)|(0x1<<(16+0x04)))
#define RK3036_GPLL_MODE_NORM	((0x1<<0x12)|(0x3<<(16+0x12)))

#define RK3036_GPLL_MODE_DEEP	((0x10<<0x12)|(0x3<<(16+0x12)))

#define RK3036_PLL_CONS(id, i)	(((id) < 2 ? id : (id + 1)) * 0x10 + ((i) * 4))

#define RK3036_CRU_GLB_SRST_FST_VALUE 0x00100
#define RK3036_CRU_GLB_SRST_SND_VALUE 0x00104
#define RK3036_CRU_SOFTRST0_CON 0x00110
#define RK3036_CRU_SOFTRST1_CON 0x00114
#define RK3036_CRU_SOFTRST2_CON 0x00118
#define RK3036_CRU_SOFTRST3_CON 0x0011c
#define RK3036_CRU_SOFTRST4_CON 0x00120
#define RK3036_CRU_SOFTRST5_CON 0x00124
#define RK3036_CRU_SOFTRST6_CON 0x00128
#define RK3036_CRU_SOFTRST7_CON 0x0012c
#define RK3036_CRU_SOFTRST8_CON 0x00130
#define RK3036_CRU_MISC_CON 0x00134
#define RK3036_CRU_GLB_CNT_TH 0x00140
#define RK3036_CRU_SDMMC_CON0 0x00144
#define RK3036_CRU_SDMMC_CON1 0x00148
#define RK3036_CRU_SDIO_CON0 0x0014c
#define RK3036_CRU_SDIO_CON1 0x00150
#define RK3036_CRU_EMMC_CON0 0x00154
#define RK3036_CRU_EMMC_CON1 0x00158
#define RK3036_CRU_RST_ST 0x00160
#define RK3036_CRU_PLL_MASK_CON 0x001f0

#define RK3036_CRU_CLKSEL_CON		0x44
#define RK3036_CRU_CLKGATE_CON		0xd0

#define RK3036_CRU_CLKSELS_CON_CNT	(35)
#define RK3036_CRU_CLKSELS_CON(i)	(RK3036_CRU_CLKSEL_CON + ((i) * 4))

#define RK3036_CRU_CLKGATES_CON_CNT	(11)
#define RK3036_CRU_CLKGATES_CON(i)	(RK3036_CRU_CLKGATE_CON + ((i) * 4))

#define RK3036_CRU_SOFTRSTS_CON_CNT	(9)
#define RK3036_CRU_SOFTRSTS_CON(i)	(RK3036_CRU_SOFTRST_CON + ((i) * 4))

/*******************CRU GATING*********************/
#define RK3036_CRU_UART_GATE                0xd4
#define RK3036_CLKGATE_UART0_SRC        8
#define RK3036_CLKGATE_UART0_PCLK      9

#define RK312X_PLL_CONS(id, i)		((id) * 0x10 + ((i) * 4))

#define RK312X_CRU_GLB_SRST_FST_VALUE 0x00100
#define RK312X_CRU_GLB_SRST_SND_VALUE 0x00104
#define RK312X_CRU_MISC_CON 0x00134
#define RK312X_CRU_GLB_CNT_TH 0x00140
#define RK312X_CRU_GLB_RST_ST 0x00150
#define RK312X_CRU_SDMMC_CON0	0x01c0
#define RK312X_CRU_SDMMC_CON1	0x01c4
#define RK312X_CRU_SDIO_CON0	0x01c8
#define RK312X_CRU_SDIO_CON1	0x01cc
#define RK312X_CRU_EMMC_CON0	0x01d8
#define RK312X_CRU_EMMC_CON1	0x01dc
#define RK312X_CRU_PLL_PRG_EN	0x01f0
#define RK312X_CRU_MODE_CON		0x40
#define RK312X_CRU_RST_ST 0x00160
#define RK312X_CRU_PLL_MASK_CON 0x001f0

#define RK312X_CRU_CLKSEL_CON		0x44
#define RK312X_CRU_CLKGATE_CON		0xd0

#define RK312X_PLL_CONS(id, i)		((id) * 0x10 + ((i) * 4))

/******************PLL MODE BITS*******************/
#define RK312X_PLLS_MODE_OFFSET(id) ((id) <= 3 ? (id * 4) : 14)
#define RK312X_PLL_MODE_MSK(id)		(0x1 << RK312X_PLLS_MODE_OFFSET(id))
#define RK312X_PLL_MODE_SLOW(id)	((0x0 << RK312X_PLLS_MODE_OFFSET(id))\
| (0x1 << (16 + RK312X_PLLS_MODE_OFFSET(id))))
#define RK312X_PLL_MODE_NORM(id)	((0x1 << RK312X_PLLS_MODE_OFFSET(id))\
| (0x1 << (16 + RK312X_PLLS_MODE_OFFSET(id))))


#define RK312X_CRU_SOFTRST_CON		0x110

#define RK312X_CRU_CLKSELS_CON_CNT	(35)
#define RK312X_CRU_CLKSELS_CON(i)	(RK3036_CRU_CLKSEL_CON + ((i) * 4))

#define RK312X_CRU_CLKGATES_CON_CNT	(11)
#define RK312X_CRU_CLKGATES_CON(i)	(RK3036_CRU_CLKGATE_CON + ((i) * 4))

#define RK312X_CRU_SOFTRSTS_CON_CNT	(9)
#define RK312X_CRU_SOFTRSTS_CON(i)	(RK312X_CRU_SOFTRST_CON + ((i) * 4))

/*******************CRU GATING*********************/
#define RK312X_CRU_CONS_GATEID(i)	(16 * (i))
#define RK312X_CRU_GATEID_CONS(ID)	(RK312X_CRU_CLKGATE_CON\
	+ ((ID) / 16) * 4)

enum rk312x_cru_clk_gate {
	/* SCU CLK GATE 0 CON */
	RK312X_CLKGATE_UART0_SRC = (RK312X_CRU_CONS_GATEID(1) + 8),
	RK312X_CLKGATE_PCLK_UART0 = (RK312X_CRU_CONS_GATEID(8) + 0),
	RK312X_CLKGATE_PCLK_UART1,
	RK312X_CLKGATE_PCLK_UART2,
};

#define RK3228_PLL_CONS(id, i)		RK312X_PLL_CONS(id, i)
#define RK3228_CRU_MODE_CON			RK312X_CRU_MODE_CON
#define RK3228_CRU_CLKSELS_CON_CNT	RK312X_CRU_CLKSELS_CON_CNT
#define RK3228_CRU_CLKSELS_CON(i)	RK312X_CRU_CLKSELS_CON(i)
#define RK3228_CRU_CLKGATES_CON_CNT	(16)
#define RK3228_CRU_CLKGATES_CON(i)	RK312X_CRU_CLKGATES_CON(i)
#define RK3228_CRU_SOFTRSTS_CON_CNT	RK312X_CRU_SOFTRSTS_CON_CNT
#define RK3228_CRU_SOFTRSTS_CON(i)	RK312X_CRU_SOFTRSTS_CON(i)
#define RK3228_CRU_MISC_CON		RK312X_CRU_MISC_CON
#define RK3228_CRU_GLB_CNT_TH		RK312X_CRU_GLB_CNT_TH
#define RK3228_CRU_GLB_RST_ST		RK312X_CRU_GLB_RST_ST
#define RK3228_CRU_SDMMC_CON0		RK312X_CRU_SDMMC_CON0
#define RK3228_CRU_SDMMC_CON1		RK312X_CRU_SDMMC_CON1
#define RK3228_CRU_SDIO_CON0		RK312X_CRU_SDIO_CON0
#define RK3228_CRU_SDIO_CON1		RK312X_CRU_SDIO_CON1
#define RK3228_CRU_EMMC_CON0		RK312X_CRU_EMMC_CON0
#define RK3228_CRU_EMMC_CON1		RK312X_CRU_EMMC_CON1
#define RK3228_CRU_GLB_SRST_FST_VALUE	0x001f0
#define RK3228_CRU_GLB_SRST_SND_VALUE	0x001f4
#define RK3228_CRU_PLL_MASK_CON		0x001f8

/*************************RK3368********************************/

/*******************CRU OFFSET*********************/
#define RK3368_CRU_CLKSEL_CON		0x100
#define RK3368_CRU_CLKGATE_CON		0x200
#define RK3368_CRU_CLKGATES_CON_CNT     25

#define RK3368_PLL_CONS(id, i)		((id) * 0x10 + ((i) * 4))
#define RK3368_CRU_CLKSELS_CON(i)	(RK3368_CRU_CLKSEL_CON + ((i) * 4))
#define RK3368_CRU_CLKGATES_CON(i)	(RK3368_CRU_CLKGATE_CON + ((i) * 4))

#define RK3368_CRU_SOFTRSTS_CON_CNT	(15)
#define RK3368_CRU_SOFTRST_CON          0x300
#define RK3368_CRU_SOFTRSTS_CON(i)	(RK3368_CRU_SOFTRST_CON + ((i) * 4))

#endif
