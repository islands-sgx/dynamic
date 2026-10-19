#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x155e60e3, "misc_deregister" },
	{ 0x092a35a2, "_copy_from_user" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0xb3353fc6, "apic" },
	{ 0xf20237ee, "unpin_user_pages" },
	{ 0xfbe7861b, "memcpy" },
	{ 0xf296206e, "pgdir_shift" },
	{ 0xf1de9e85, "vunmap" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0x448a179e, "lookup_address" },
	{ 0xd272d446, "__fentry__" },
	{ 0x5a844b26, "__x86_indirect_thunk_rax" },
	{ 0xe8213e80, "_printk" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0xbd03ed67, "page_offset_base" },
	{ 0x095159b2, "physical_mask" },
	{ 0x5a844b26, "__x86_indirect_thunk_r14" },
	{ 0x9aa6980d, "mutex_lock" },
	{ 0xe0038666, "unregister_kretprobe" },
	{ 0xc5c2a6a3, "const_current_task" },
	{ 0xbd03ed67, "phys_base" },
	{ 0x0a708f4e, "vmap" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0x5fc55113, "__default_kernel_pte_mask" },
	{ 0xf296206e, "ptrs_per_p4d" },
	{ 0xe98a2697, "misc_register" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x092a35a2, "_copy_to_user" },
	{ 0xe3f5f05b, "pv_ops" },
	{ 0xbd03ed67, "vmemmap_base" },
	{ 0x82fd7238, "__ubsan_handle_shift_out_of_bounds" },
	{ 0x9aa6980d, "mutex_unlock" },
	{ 0x5cb46e6d, "validate_usercopy_range" },
	{ 0xab4fa532, "register_kretprobe" },
	{ 0x048fdb82, "boot_cpu_data" },
	{ 0xd272d446, "BUG_func" },
	{ 0x1bdf2bc8, "sme_me_mask" },
	{ 0x67c78da2, "pin_user_pages_fast" },
	{ 0xa61fd7aa, "__check_object_size" },
	{ 0xe9196a28, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0x155e60e3,
	0x092a35a2,
	0xd710adbf,
	0xb3353fc6,
	0xf20237ee,
	0xfbe7861b,
	0xf296206e,
	0xf1de9e85,
	0xcb8b6ec6,
	0x448a179e,
	0xd272d446,
	0x5a844b26,
	0xe8213e80,
	0xbd03ed67,
	0xd272d446,
	0xbd03ed67,
	0x095159b2,
	0x5a844b26,
	0x9aa6980d,
	0xe0038666,
	0xc5c2a6a3,
	0xbd03ed67,
	0x0a708f4e,
	0xe54e0a6b,
	0x5fc55113,
	0xf296206e,
	0xe98a2697,
	0xd272d446,
	0x092a35a2,
	0xe3f5f05b,
	0xbd03ed67,
	0x82fd7238,
	0x9aa6980d,
	0x5cb46e6d,
	0xab4fa532,
	0x048fdb82,
	0xd272d446,
	0x1bdf2bc8,
	0x67c78da2,
	0xa61fd7aa,
	0xe9196a28,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"misc_deregister\0"
	"_copy_from_user\0"
	"__kmalloc_noprof\0"
	"apic\0"
	"unpin_user_pages\0"
	"memcpy\0"
	"pgdir_shift\0"
	"vunmap\0"
	"kfree\0"
	"lookup_address\0"
	"__fentry__\0"
	"__x86_indirect_thunk_rax\0"
	"_printk\0"
	"__ref_stack_chk_guard\0"
	"__stack_chk_fail\0"
	"page_offset_base\0"
	"physical_mask\0"
	"__x86_indirect_thunk_r14\0"
	"mutex_lock\0"
	"unregister_kretprobe\0"
	"const_current_task\0"
	"phys_base\0"
	"vmap\0"
	"__fortify_panic\0"
	"__default_kernel_pte_mask\0"
	"ptrs_per_p4d\0"
	"misc_register\0"
	"__x86_return_thunk\0"
	"_copy_to_user\0"
	"pv_ops\0"
	"vmemmap_base\0"
	"__ubsan_handle_shift_out_of_bounds\0"
	"mutex_unlock\0"
	"validate_usercopy_range\0"
	"register_kretprobe\0"
	"boot_cpu_data\0"
	"BUG_func\0"
	"sme_me_mask\0"
	"pin_user_pages_fast\0"
	"__check_object_size\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "9AF317D1914B7D8078FB031");
