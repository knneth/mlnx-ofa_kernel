#ifndef _COMPAT_LINUX_RBTREE_H
#define _COMPAT_LINUX_RBTREE_H

#include "../../compat/config.h"

#include_next <linux/rbtree.h>

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
