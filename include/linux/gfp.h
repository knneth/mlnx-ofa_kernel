#ifndef _COMPAT_LINUX_GFP_H
#define _COMPAT_LINUX_GFP_H

#include "../../compat/config.h"

#include_next <linux/gfp.h>
#ifndef __GFP_ACCOUNT
#define ___GFP_ACCOUNT          0x100000u
#define __GFP_ACCOUNT   ((__force gfp_t)___GFP_ACCOUNT)
#endif
#ifndef __GFP_MEMALLOC
#define __GFP_MEMALLOC	0
#endif

#endif /* _COMPAT_LINUX_GFP_H */
