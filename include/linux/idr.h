#ifndef _COMPAT_LINUX_IDR_H
#define _COMPAT_LINUX_IDR_H

#include "../../compat/config.h"

#include_next <linux/idr.h>

#define compat_idr_for_each_entry(idr, entry, id)          \
		idr_for_each_entry(idr, entry, id)

/**
 * idr_for_each_entry_continue_ul() - Continue iteration over an IDR's elements of a given type
 * @idr: IDR handle.
 * @entry: The type * to use as a cursor.
 * @tmp: A temporary placeholder for ID.
 * @id: Entry ID.
 *
 * Continue to iterate over entries, continuing after the current position.
 * After normal termination @entry is left with the value NULL.  This
 * is convenient for a "not found" value.
 */
#ifndef HAVE_IDR_FOR_EACH_ENTRY_CONTINUE_UL
#define idr_for_each_entry_continue_ul(idr, entry, tmp, id)		\
	for (tmp = id;							\
	     ((entry) = tmp <= id ? idr_get_next_ul(idr, &(id)) : NULL) != NULL; \
	     tmp = id, ++id)
#endif

#endif /* _COMPAT_LINUX_IDR_H */
