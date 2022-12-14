
#ifndef _COMPAT_LINUX_SYSFS_H_
#define _COMPAT_LINUX_SYSFS_H_

#include "../../compat/config.h"
#include_next <linux/sysfs.h>

#ifndef HAVE_SYSFS_EMIT
#ifdef CONFIG_SYSFS

#ifndef offset_in_page
#define offset_in_page(p)       ((unsigned long)(p) & ~PAGE_MASK)
#endif


#define sysfs_emit LINUX_BACKPORT(sysfs_emit)
__printf(2, 3)
int sysfs_emit(char *buf, const char *fmt, ...);

#else /* CONFIG_SYSFS */

__printf(2, 3)
static inline int sysfs_emit(char *buf, const char *fmt, ...)
{
	return 0;
}

#endif /* CONFIG_SYSFS */
#endif /* HAVE_SYSFS_EMIT */
#endif /* _COMPAT_LINUX_SYSFS_H_ */
