#ifndef _COMPAT_LINUX_RADIX_TREE_H
#define _COMPAT_LINUX_RADIX_TREE_H

#include "../../compat/config.h"

#include_next <linux/radix-tree.h>

#ifndef HAVE_RADIX_TREE_NODE

#ifdef __KERNEL__
#define RADIX_TREE_MAP_SHIFT	(CONFIG_BASE_SMALL ? 4 : 6)
#else
#define RADIX_TREE_MAP_SHIFT	3	/* For more stressful testing */
#endif
#define RADIX_TREE_MAP_SIZE	(1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK	(RADIX_TREE_MAP_SIZE-1)

#define RADIX_TREE_TAG_LONGS	\
	((RADIX_TREE_MAP_SIZE + BITS_PER_LONG - 1) / BITS_PER_LONG)

struct radix_tree_node {
	unsigned int	path;	/* Offset in parent & height from the bottom */
	unsigned int	count;
	union {
		struct {
			/* Used when ascending tree */
			struct radix_tree_node *parent;
			/* For tree user */
			void *private_data;
		};
		/* Used when freeing node */
		struct rcu_head	rcu_head;
	};
	/* For tree user */
	struct list_head private_list;
	void __rcu	*slots[RADIX_TREE_MAP_SIZE];
	unsigned long	tags[RADIX_TREE_MAX_TAGS][RADIX_TREE_TAG_LONGS];
};

#endif /* HAVE_RADIX_TREE_NODE */
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
