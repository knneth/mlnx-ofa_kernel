#ifndef _COMPAT_LINUX_RADIX_TREE_H
#define _COMPAT_LINUX_RADIX_TREE_H

#include "../../compat/config.h"

#include_next <linux/radix-tree.h>

#ifndef HAVE_IDR_PRELOAD_EXPORTED
#define idr_preload LINUX_BACKPORT(idr_preload)
extern void idr_preload(gfp_t gfp_mask);
#endif

#ifndef HAVE_RADIX_TREE_IS_INTERNAL
#define RADIX_TREE_ENTRY_MASK           3UL
#define RADIX_TREE_INTERNAL_NODE        2UL
static inline bool radix_tree_is_internal_node(void *ptr)
{
	return ((unsigned long)ptr & RADIX_TREE_ENTRY_MASK) ==
		RADIX_TREE_INTERNAL_NODE;
}
#endif

#endif /* _COMPAT_LINUX_RADIX_TREE_H */
