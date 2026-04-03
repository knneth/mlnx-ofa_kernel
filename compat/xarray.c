// SPDX-License-Identifier: GPL-2.0+
/*
 * XArray implementation
 * Copyright (c) 2017 Microsoft Corporation
 * Author: Matthew Wilcox <willy@infradead.org>
 */


/* For RHEL 8.1/8.2 and kernels below 5.4 that has xarray
 * but suffering of lack of fixes for xarray */
#ifndef HAVE_XA_FOR_EACH_RANGE
static bool xas_sibling(struct xa_state *xas)
{
	struct xa_node *node = xas->xa_node;
	unsigned long mask;

	if (!IS_ENABLED(CONFIG_XARRAY_MULTI) || !node)
		return false;
	mask = (XA_CHUNK_SIZE << node->shift) - 1;
	return (xas->xa_index & mask) >
		((unsigned long)xas->xa_offset << node->shift);
}

static void *set_bounds(struct xa_state *xas)
{
	xas->xa_node = XAS_BOUNDS;
	return NULL;
}

void *xa_find_after(struct xarray *xa, unsigned long *indexp,
		unsigned long max, xa_mark_t filter)
{
	XA_STATE(xas, xa, *indexp + 1);
	void *entry;

	if (xas.xa_index == 0)
		return NULL;

	rcu_read_lock();
	for (;;) {
		if ((__force unsigned int)filter < XA_MAX_MARKS) {
			if (xas.xa_index > max) {
				xas.xa_node = XAS_RESTART;
				entry = NULL;
			}
			else
				entry = xas_find_marked(&xas, max, filter);
		}
		else {
			if (xas.xa_index > max)
				entry = set_bounds(&xas);
			else
				entry = xas_find(&xas, max);
		}

		if (xas_invalid(&xas))
			break;
		if (xas_sibling(&xas))
			continue;
		if (!xas_retry(&xas, entry))
			break;
	}
	rcu_read_unlock();

	if (entry)
		*indexp = xas.xa_index;
	return entry;
}
EXPORT_SYMBOL(xa_find_after);
#endif
