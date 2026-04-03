/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _COMPAT_LINUX_XARRAY_H
#define _COMPAT_LINUX_XARRAY_H
#include "../../compat/config.h"
#include_next <linux/xarray.h>

#ifndef HAVE_XA_FOR_EACH_RANGE
#define xa_find_after LINUX_BACKPORT(xa_find_after)
void *xa_find_after(struct xarray *xa, unsigned long *index,
		unsigned long max, xa_mark_t) __attribute__((nonnull(2)));

#define xa_for_each_range(xa, index, entry, start, last)		\
	for (index = start,						\
	     entry = xa_find(xa, &index, last, XA_PRESENT);		\
	     entry;							\
	     entry = xa_find_after(xa, &index, last, XA_PRESENT))
#endif /* HAVE_XA_FOR_EACH_RANGE */

#endif /* _COMPAT_LINUX_XARRAY_H */
