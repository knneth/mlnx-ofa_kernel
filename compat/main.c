#include <linux/module.h>

#include "config.h"

#ifndef HAVE_XARRAY
#include <linux/xarray.h>
#endif

#ifdef CONFIG_COMPAT_CLS_FLOWER_4_18_MOD
#include <net/netfilter/nf_flow_table.h>
#endif
MODULE_AUTHOR("Luis R. Rodriguez");
MODULE_DESCRIPTION("Kernel backport module");
MODULE_LICENSE("GPL");
#ifdef RETPOLINE_MLNX
MODULE_INFO(retpoline, "Y");
#endif

#ifndef COMPAT_BASE
#error "You need a COMPAT_BASE"
#endif

#ifndef COMPAT_BASE_TREE
#error "You need a COMPAT_BASE_TREE"
#endif

#ifndef COMPAT_BASE_TREE_VERSION
#error "You need a COMPAT_BASE_TREE_VERSION"
#endif

#ifndef COMPAT_VERSION
#error "You need a COMPAT_VERSION"
#endif

static char *compat_base = COMPAT_BASE;
static char *compat_base_tree = COMPAT_BASE_TREE;
static char *compat_base_tree_version = COMPAT_BASE_TREE_VERSION;
static char *compat_version = COMPAT_VERSION;

module_param(compat_base, charp, 0400);
MODULE_PARM_DESC(compat_base_tree,
		 "The upstream verion of compat.git used");

module_param(compat_base_tree, charp, 0400);
MODULE_PARM_DESC(compat_base_tree,
		 "The upstream tree used as base for this backport");

module_param(compat_base_tree_version, charp, 0400);
MODULE_PARM_DESC(compat_base_tree_version,
		 "The git-describe of the upstream base tree");

module_param(compat_version, charp, 0400);
MODULE_PARM_DESC(compat_version,
		 "Version of the kernel compat backport work");

void mlx_backport_dependency_symbol(void)
{
}
EXPORT_SYMBOL_GPL(mlx_backport_dependency_symbol);


static int __init backport_init(void)
{
	printk(KERN_INFO
	       COMPAT_PROJECT " backport release: "
	       COMPAT_VERSION
	       "\n");
	printk(KERN_INFO "Backport based on "
	       COMPAT_BASE_TREE " " COMPAT_BASE_TREE_VERSION
	       "\n");
	printk(KERN_INFO "compat.git: "
	       COMPAT_BASE_TREE "\n");

#ifndef HAVE_XARRAY
	compat_radix_tree_init();
#endif
#ifdef CONFIG_COMPAT_CLS_FLOWER_4_18_MOD
	nf_flow_table_offload_init();
#endif
        return 0;
}
module_init(backport_init);

static void __exit backport_exit(void)
{
#ifndef HAVE_XARRAY
	compat_radix_tree_clean();
#endif	
#ifdef CONFIG_COMPAT_CLS_FLOWER_4_18_MOD
	nf_flow_table_offload_exit();
#endif

        return;
}
module_exit(backport_exit);

