#ifndef _COMPAT_LINUX_TYPES_H
#define _COMPAT_LINUX_TYPES_H 1

#include "../../compat/config.h"

#include_next <linux/types.h>

#ifdef __KERNEL__
#if !defined(HAVE_TYPE_CYCLE_T) && !defined(HAVE_CLOCKSOURCE_CYCLE_T)
/*  clocksource cycle base type */
typedef u64 cycle_t;
#endif
#endif /* __KERNEL__*/

#endif	/* _COMPAT_LINUX_TYPES_H */
