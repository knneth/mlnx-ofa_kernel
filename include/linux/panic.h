#ifndef _COMPAT_LINUX_PANIC_H
#define _COMPAT_LINUX_PANIC_H

#include "../../compat/config.h"

#include_next <linux/panic.h>

#ifndef TAINT_FWCTL
#define TAINT_FWCTL                19
#undef 	TAINT_FLAGS_COUNT
#define TAINT_FLAGS_COUNT          20
#endif

#endif /* _COMPAT_LINUX_PANIC_H */
