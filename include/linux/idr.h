#ifndef _COMPAT_LINUX_IDR_H
#define _COMPAT_LINUX_IDR_H

#include "../../compat/config.h"

#include_next <linux/idr.h>

#ifndef HAVE_IDA_SIMPLE_GET
#define ida_simple_remove LINUX_BACKPORT(ida_simple_remove)
void ida_simple_remove(struct ida *ida, unsigned int id);

#define ida_simple_get LINUX_BACKPORT(ida_simple_get)
int ida_simple_get(struct ida *ida, unsigned int start, unsigned int end,
		   gfp_t gfp_mask);

#endif /* HAVE_IDA_SIMPLE_GET */

#endif /* _COMPAT_LINUX_IDR_H */
