#ifndef _COMPAT_LINUX_MEMREMAP_H
#define _COMPAT_LINUX_MEMREMAP_H

#include "../../compat/config.h"

#include_next <linux/memremap.h>


#ifndef HAVE_MEMREMAP_COMPAT_ALIGN

#ifdef CONFIG_ZONE_DEVICE
#define SUBSECTION_SHIFT 21
#define SUBSECTION_SIZE (1UL << SUBSECTION_SHIFT)
static inline unsigned long memremap_compat_align(void)
{
        return SUBSECTION_SIZE;
}
#else
/* when memremap_pages() is disabled all archs can remap a single page */
static inline unsigned long memremap_compat_align(void)
{
        return PAGE_SIZE;
}
#endif /* CONFIG_ZONE_DEVICE */

#endif /* HAVE_MEMREMAP_COMPAT_ALIGN */

#endif /* _COMPAT_LINUX_MEMREMAP_H */
