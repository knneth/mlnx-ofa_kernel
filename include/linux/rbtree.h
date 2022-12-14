#ifndef _COMPAT_LINUX_RBTREE_H
#define _COMPAT_LINUX_RBTREE_H

#include "../../compat/config.h"

#include_next <linux/rbtree.h>

#if !defined(HAVE_RB_ROOT_CACHED) || defined(HAVE_INTERVAL_TREE_TAKES_RB_ROOT)
#if defined(HAVE_RB_ROOT_CACHED)
#undef HAVE_RB_ROOT_CACHED
#undef RB_ROOT_CACHED
#endif
#define rb_root_cached rb_root
#define RB_ROOT_CACHED RB_ROOT
#endif

#ifndef rb_entry_safe
#define rb_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? rb_entry(____ptr, type, member) : NULL; \
	})
#endif

#ifndef rbtree_postorder_for_each_entry_safe
#define rbtree_postorder_for_each_entry_safe(pos, n, root, field) \
	for (pos = rb_entry_safe(rb_first_postorder(root), typeof(*pos), field); \
	     pos && ({ n = rb_entry_safe(rb_next_postorder(&pos->field), \
			typeof(*pos), field); 1; }); \
	     pos = n)
#endif

#endif /* _COMPAT_LINUX_RBTREE_H */
