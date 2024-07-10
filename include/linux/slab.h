#ifndef _COMPAT_LINUX_SLAB_H
#define _COMPAT_LINUX_SLAB_H

#include "../../compat/config.h"

#include_next <linux/slab.h>
#include <linux/overflow.h>

/*
 * W/A for old kernels that do not have this fix.
 *
 * commit 3942d29918522ba6a393c19388301ec04df429cd
 * Author: Sergey Senozhatsky <sergey.senozhatsky@gmail.com>
 * Date:   Tue Sep 8 15:00:50 2015 -0700
 *
 *     mm/slab_common: allow NULL cache pointer in kmem_cache_destroy()
 *
*/
static inline void compat_kmem_cache_destroy(struct kmem_cache *s)
{
	if (unlikely(!s))
		return;

	kmem_cache_destroy(s);
}
#define kmem_cache_destroy compat_kmem_cache_destroy

#endif /* _COMPAT_LINUX_SLAB_H */
