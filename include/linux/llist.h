#ifndef _COMPAT_LINUX_LLIST_H
#define _COMPAT_LINUX_LLIST_H

#include "../../compat/config.h"

#include_next <linux/llist.h>

#ifndef member_address_is_nonnull
#define member_address_is_nonnull(ptr, member)  \
	((uintptr_t)(ptr) + offsetof(typeof(*(ptr)), member) != 0)
#endif


#ifndef llist_for_each_entry_safe
#define llist_for_each_entry_safe(pos, n, node, member)				\
	for (pos = llist_entry((node), typeof(*pos), member);			\
		member_address_is_nonnull(pos, member) &&			\
		(n = llist_entry(pos->member.next, typeof(*n), member), true);	\
		 pos = n)
#endif

#endif /* _COMPAT_LINUX_LLIST_H */
