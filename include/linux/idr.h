#ifndef _COMPAT_LINUX_IDR_H
#define _COMPAT_LINUX_IDR_H

#include "../../compat/config.h"

#include_next <linux/idr.h>

#define compat_idr_for_each_entry(idr, entry, id)          \
		idr_for_each_entry(idr, entry, id)
#endif /* _COMPAT_LINUX_IDR_H */
