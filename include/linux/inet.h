#ifndef _COMPAT_LINUX_INET_H
#define _COMPAT_LINUX_INET_H

#include "../../compat/config.h"
#include <linux/version.h>

#include_next <linux/inet.h>

#if (defined(RHEL_MAJOR) && RHEL_MAJOR -0 == 7 && RHEL_MINOR -0 >= 2) || \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0))
#endif

#endif /* _COMPAT_LINUX_INET_H */
