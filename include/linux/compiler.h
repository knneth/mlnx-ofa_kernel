#ifndef _COMPAT_LINUX_COMPILER_H
#define _COMPAT_LINUX_COMPILER_H

#include "../../compat/config.h"

#include_next <linux/compiler.h>
#include <linux/types.h>

#ifndef HAVE_3_UNDERSCORE_ADDRESSABLE
#undef __ADDRESSABLE

#define ___ADDRESSABLE(sym, __attrs)						\
	static void * __used __attrs						\
	__UNIQUE_ID(__PASTE(__addressable_,sym)) = (void *)(uintptr_t)&sym;

#define __ADDRESSABLE(sym) \
	___ADDRESSABLE(sym, __section(".discard.addressable"))
#endif

#ifndef HAVE_CONST_READ_ONCE_SIZE
#define __read_once_size LINUX_BACKPORT(__read_once_size)
static __always_inline void __read_once_size(const volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(__u8 *)res = *(volatile __u8 *)p; break;
	case 2: *(__u16 *)res = *(volatile __u16 *)p; break;
	case 4: *(__u32 *)res = *(volatile __u32 *)p; break;
#ifdef CONFIG_64BIT
	case 8: *(__u64 *)res = *(volatile __u64 *)p; break;
#endif
	default:
		barrier();
		__builtin_memcpy((void *)res, (const void *)p, size);
		barrier();
	}
}
#endif

#endif /* _COMPAT_LINUX_COMPILER_H */
