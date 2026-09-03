/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _COMPAT_LINUX_RBTREE_H
#define _COMPAT_LINUX_RBTREE_H

#include "../../compat/config.h"

#include_next <linux/rbtree.h>

#ifndef HAVE_RB_FIND
/* Older kernels (<5.12): provide rb_find / rb_find_add as static inlines.
 * Copied verbatim from upstream 2d24dd5798d0 "rbtree: Add generic add
 * and find helpers". Only depends on rb_link_node / rb_insert_color
 * which have been present since well before 5.4.
 */
static __always_inline struct rb_node *
rb_find(const void *key, const struct rb_root *tree,
	int (*cmp)(const void *key, const struct rb_node *))
{
	struct rb_node *node = tree->rb_node;

	while (node) {
		int c = cmp(key, node);

		if (c < 0)
			node = node->rb_left;
		else if (c > 0)
			node = node->rb_right;
		else
			return node;
	}
	return NULL;
}

static __always_inline struct rb_node *
rb_find_add(struct rb_node *node, struct rb_root *tree,
	    int (*cmp)(struct rb_node *, const struct rb_node *))
{
	struct rb_node **link = &tree->rb_node;
	struct rb_node *parent = NULL;
	int c;

	while (*link) {
		parent = *link;
		c = cmp(node, parent);

		if (c < 0)
			link = &parent->rb_left;
		else if (c > 0)
			link = &parent->rb_right;
		else
			return parent;
	}

	rb_link_node(node, parent, link);
	rb_insert_color(node, tree);
	return NULL;
}
#endif /* !HAVE_RB_FIND */

#endif /* _COMPAT_LINUX_RBTREE_H */
