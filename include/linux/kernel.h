#ifndef _COMPAT_LINUX_KERNEL_H
#define _COMPAT_LINUX_KERNEL_H

#include "../../compat/config.h"

#include_next <linux/kernel.h>

#ifndef HAVE_PANIC_H
#ifndef TAINT_FWCTL
#define TAINT_FWCTL                19
#undef  TAINT_FLAGS_COUNT
#define TAINT_FLAGS_COUNT          20
#endif
#endif /* HAVE_PANIC_H */

#ifndef PTR_IF
#define PTR_IF(cond, ptr)	((cond) ? (ptr) : NULL)
#endif

#endif /* _COMPAT_LINUX_KERNEL_H */
