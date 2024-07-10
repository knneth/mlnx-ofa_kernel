#ifndef _COMPAT_LINUX_STRING_H
#define _COMPAT_LINUX_STRING_H

#include "../../compat/config.h"

#include_next <linux/string.h>

#ifndef HAVE_STRSCPY_PAD
#define strscpy strlcpy
#endif

#ifndef unsafe_memcpy
#define unsafe_memcpy(dst, src, bytes, justification)		\
		memcpy(dst, src, bytes)
#endif

#ifndef __HAVE_ARCH_STRNICMP
#define strnicmp strncasecmp
#endif
#endif /* HAVE_STRNICMP */

#ifndef memset_after
#define memset_after(obj, v, member)					\
({									\
	u8 *__ptr = (u8 *)(obj);					\
	typeof(v) __val = (v);						\
	memset(__ptr + offsetofend(typeof(*(obj)), member), __val,	\
	       sizeof(*(obj)) - offsetofend(typeof(*(obj)), member));	\
})

#endif /* _COMPAT_LINUX_STRING_H */
