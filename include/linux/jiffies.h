#ifndef _COMPAT_LINUX_JIFFIES_H
#define _COMPAT_LINUX_JIFFIES_H

#include "../../compat/config.h"

#include_next <linux/jiffies.h>

#ifndef HAVE_SECS_TO_JIFFIES
#define secs_to_jiffies(_secs) (((u64)(_secs)) * HZ)
#endif

#endif /* _COMPAT_LINUX_JIFFIES_H */
