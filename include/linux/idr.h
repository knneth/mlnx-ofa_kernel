#ifndef _COMPAT_LINUX_IDR_H
#define _COMPAT_LINUX_IDR_H

#include "../../compat/config.h"

#include_next <linux/idr.h>

#define compat_idr_for_each_entry(idr, entry, id)          \
		idr_for_each_entry(idr, entry, id)

#ifndef HAVE_IDR_GET_NEXT_UL_EXPORTED
#define idr_get_next_ul LINUX_BACKPORT(idr_get_next_ul)
void *idr_get_next_ul(struct idr *idr, unsigned long *nextid);


#define idr_alloc_u32 LINUX_BACKPORT(idr_alloc_u32)
int idr_alloc_u32(struct idr *idr, void *ptr, u32 *nextid,
		unsigned long max, gfp_t gfp);
#endif
#endif /* _COMPAT_LINUX_IDR_H */
