#ifndef COMPAT_LINUX_SLAB_H
#define COMPAT_LINUX_SLAB_H

#include "../../compat/config.h"

#include_next <linux/slab.h>

#ifndef HAVE_KMALLOC_ARRAY
/**
 * kmalloc_array - allocate memory for an array.
 * @n: number of elements.
 * @size: element size.
 * @flags: the type of memory to allocate (see kmalloc).
 */
static inline void *kmalloc_array(size_t n, size_t size, gfp_t flags)
{
        if (size != 0 && n > SIZE_MAX / size)
                return NULL;
        return __kmalloc(n * size, flags);
}
#endif


#endif /* COMPAT_LINUX_SLAB_H */
