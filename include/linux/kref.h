#ifndef _COMPAT_LINUX_KREF_H
#define _COMPAT_LINUX_KREF_H

#include "../../compat/config.h"

#include_next <linux/kref.h>

#ifndef HAVE_KREF_READ

static inline int kref_read(struct kref *kref)
{
	return atomic_read(&kref->refcount);
}
#endif

#endif /* _COMPAT_LINUX_KREF_H */
