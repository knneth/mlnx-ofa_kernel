#ifndef _COMPAT_LINUX_LLIST_H
#define _COMPAT_LINUX_LLIST_H

#include "../../compat/config.h"

#include_next <linux/llist.h>

#ifndef member_address_is_nonnull
#define member_address_is_nonnull(ptr, member)  \
	((uintptr_t)(ptr) + offsetof(typeof(*(ptr)), member) != 0)
#endif

#endif /* _COMPAT_LINUX_LLIST_H */
