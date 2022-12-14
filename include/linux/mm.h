#ifndef _COMPAT_LINUX_MM_H
#define _COMPAT_LINUX_MM_H

#include "../../compat/config.h"

#include_next <linux/mm.h>

#ifndef HAVE_KVZALLOC
#include <linux/vmalloc.h>
#include <linux/slab.h>

static inline void *kvzalloc(unsigned long size,...) {
	void *rtn;

	rtn = kzalloc(size, GFP_KERNEL | __GFP_NOWARN);
	if (!rtn)
		rtn = vzalloc(size);
	return rtn;
}
#endif

#ifndef HAVE_KVMALLOC_ARRAY
#include <linux/vmalloc.h>
#include <linux/slab.h>

static inline void *kvmalloc_array(size_t n, size_t size,...) {
	void *rtn;

	rtn = kcalloc(n, size, GFP_KERNEL | __GFP_NOWARN);
	if (!rtn)
		rtn = vzalloc(n * size);
	return rtn;
}
#endif

#ifndef HAVE_KVMALLOC_NODE
#include <linux/vmalloc.h>
#include <linux/slab.h>

static inline void *kvmalloc_node(size_t size, gfp_t flags, int node) {
	void *rtn;

	rtn = kmalloc_node(size, GFP_KERNEL | __GFP_NOWARN, node);
	if (!rtn)
		rtn = vmalloc(size);
	return rtn;
}
#endif

#ifndef HAVE_KVZALLOC_NODE
#include <linux/vmalloc.h>
#include <linux/slab.h>

static inline void *kvzalloc_node(size_t size, gfp_t flags, int node)
{
	void *p = kvmalloc_node(size, flags, node);
	if (p)
		memset(p, 0, size);
	return p;
}
#endif

#endif /* _COMPAT_LINUX_MM_H */
