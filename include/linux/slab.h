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

/*
 * Backport of the k{m,z,v,vz}alloc_obj()/_objs()/_flex() family from
 * upstream v7.0-rc1:
 *   2932ba8d9c99875b98c951d9d3fd6d651d35df3a "slab: Introduce kmalloc_obj() and family"
 *   e4c8b46b924e...                          "slab: Introduce kmalloc_flex() and family"
 *   e19e1b480ac7...                          "add default_gfp() helper macro and use it ..."
 *
 * On 7.0+ HAVE_KZALLOC_OBJ_AND_OBJS is defined; the whole block is skipped and the
 * real upstream macros (from #include_next <linux/slab.h> above) are used.
 *
 * On 6.x and earlier we expand the helpers ourselves. Behaviour is observably
 * identical for OFED callers: same byte size (array_size / struct_size_t),
 * same return type, same GFP defaulting. The upstream __set_flex_counter()
 * step (which auto-writes __counted_by()-annotated counters) becomes a no-op
 * here; the single kzalloc_flex() caller in OFED (rdma_alloc_hw_stats_struct
 * at drivers/infiniband/core/verbs.c) sets ->num_counters explicitly on the
 * next line, so the auto-set was already redundant.
 *
 * Each inner helper is individually #ifndef-guarded so the header is safe
 * against distro partial backports.
 */
#ifndef HAVE_KZALLOC_OBJ_AND_OBJS

#ifndef struct_size_t
#define struct_size_t(type, member, count) \
	struct_size((type *)NULL, member, (count))
#endif

#ifndef __default_gfp
#define __default_gfp(a, b, ...) b
#endif

#ifndef default_gfp
#define default_gfp(...) __default_gfp(, ##__VA_ARGS__, GFP_KERNEL)
#endif

#ifndef __alloc_objs
#define __alloc_objs(KMALLOC, GFP, TYPE, COUNT)				\
({									\
	const size_t __obj_size = array_size(sizeof(TYPE), (COUNT));	\
	(TYPE *)KMALLOC(__obj_size, GFP);				\
})
#endif

#ifndef __set_flex_counter
#define __set_flex_counter(FAM, COUNT)	do { (void)(COUNT); } while (0)
#endif

#ifndef __alloc_flex
#define __alloc_flex(KMALLOC, GFP, TYPE, FAM, COUNT)			\
({									\
	const size_t __count = (COUNT);					\
	const size_t __obj_size = struct_size_t(TYPE, FAM, __count);	\
	TYPE *__obj_ptr = KMALLOC(__obj_size, GFP);			\
	if (__obj_ptr)							\
		__set_flex_counter(__obj_ptr->FAM, __count);		\
	__obj_ptr;							\
})
#endif

#ifndef kmalloc_obj
#define kmalloc_obj(P, ...) \
	__alloc_objs(kmalloc,  default_gfp(__VA_ARGS__), typeof(P), 1)
#define kzalloc_obj(P, ...) \
	__alloc_objs(kzalloc,  default_gfp(__VA_ARGS__), typeof(P), 1)
#define kvmalloc_obj(P, ...) \
	__alloc_objs(kvmalloc, default_gfp(__VA_ARGS__), typeof(P), 1)
#define kvzalloc_obj(P, ...) \
	__alloc_objs(kvzalloc, default_gfp(__VA_ARGS__), typeof(P), 1)

#define kmalloc_objs(P, COUNT, ...) \
	__alloc_objs(kmalloc,  default_gfp(__VA_ARGS__), typeof(P), (COUNT))
#define kzalloc_objs(P, COUNT, ...) \
	__alloc_objs(kzalloc,  default_gfp(__VA_ARGS__), typeof(P), (COUNT))
#define kvmalloc_objs(P, COUNT, ...) \
	__alloc_objs(kvmalloc, default_gfp(__VA_ARGS__), typeof(P), (COUNT))
#define kvzalloc_objs(P, COUNT, ...) \
	__alloc_objs(kvzalloc, default_gfp(__VA_ARGS__), typeof(P), (COUNT))

#define kmalloc_flex(P, FAM, COUNT, ...) \
	__alloc_flex(kmalloc,  default_gfp(__VA_ARGS__), typeof(P), FAM, (COUNT))
#define kzalloc_flex(P, FAM, COUNT, ...) \
	__alloc_flex(kzalloc,  default_gfp(__VA_ARGS__), typeof(P), FAM, (COUNT))
#define kvmalloc_flex(P, FAM, COUNT, ...) \
	__alloc_flex(kvmalloc, default_gfp(__VA_ARGS__), typeof(P), FAM, (COUNT))
#define kvzalloc_flex(P, FAM, COUNT, ...) \
	__alloc_flex(kvzalloc, default_gfp(__VA_ARGS__), typeof(P), FAM, (COUNT))
#endif /* !kmalloc_obj */

#endif /* HAVE_KZALLOC_OBJ_AND_OBJS */

#endif /* _COMPAT_LINUX_SLAB_H */
