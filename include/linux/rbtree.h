#ifndef _MLNX_LINUX_RBTREE_H
#define _MLNX_LINUX_RBTREE_H

#include "../../compat/config.h"

#include_next <linux/rbtree.h>

#ifndef HAVE_RB_ROOT_CACHED
#define rb_root_cached rb_root
#define RB_ROOT_CACHED RB_ROOT
#endif

#endif /* _MLNX_LINUX_RBTREE_H */
