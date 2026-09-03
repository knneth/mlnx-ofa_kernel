#ifndef _COMPAT_LINUX_SORT_H
#define _COMPAT_LINUX_SORT_H

#include "../../compat/config.h"

#include_next <linux/sort.h>

#ifndef HAVE_CMP_INT
#define cmp_int(l, r) (((l) > (r)) - ((l) < (r)))
#endif

#endif /* _COMPAT_LINUX_SORT_H */
