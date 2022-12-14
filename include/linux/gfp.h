#ifndef _COMPAT_LINUX_GFP_H
#define _COMPAT_LINUX_GFP_H

#include "../../compat/config.h"
#include <linux/version.h>

#include_next <linux/gfp.h>

#ifndef __GFP_MEMALLOC
#define __GFP_MEMALLOC	0
#endif

#endif /* _COMPAT_LINUX_GFP_H */
