#ifndef _COMPAT_LINUX_LLIST_H
#define _COMPAT_LINUX_LLIST_H

#include "../../compat/config.h"

#include_next <linux/llist.h>

#ifndef HAVE_INIT_LLIST_NODE
static inline void init_llist_node(struct llist_node *node)
{
	node->next = node;
}
#endif

#ifndef HAVE_LLIST_ON_LIST
static inline bool llist_on_list(struct llist_node *node)
{
	return node->next != node;
}
#endif

#endif /* _COMPAT_LINUX_LLIST_H */
