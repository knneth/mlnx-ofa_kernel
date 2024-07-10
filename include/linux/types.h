#ifndef _COMPAT_LINUX_TYPES_H
#define _COMPAT_LINUX_TYPES_H 1

#include "../../compat/config.h"

#include_next <linux/types.h>

#ifdef __KERNEL__
/*  clocksource cycle base type */
typedef u64 cycle_t;
#endif /* __KERNEL__*/

#ifndef __aligned_u64
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#endif

#endif	/* _COMPAT_LINUX_TYPES_H */
