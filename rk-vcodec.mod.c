#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

MODULE_ALIAS("of:N*T*Crockchip,vpu_service");
MODULE_ALIAS("of:N*T*Crockchip,vpu_serviceC*");
MODULE_ALIAS("of:N*T*Crockchip,hevc_service");
MODULE_ALIAS("of:N*T*Crockchip,hevc_serviceC*");
MODULE_ALIAS("of:N*T*Crockchip,vpu_combo");
MODULE_ALIAS("of:N*T*Crockchip,vpu_comboC*");
MODULE_ALIAS("of:N*T*Crockchip,rkvdec");
MODULE_ALIAS("of:N*T*Crockchip,rkvdecC*");
