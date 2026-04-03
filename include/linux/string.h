#ifndef _COMPAT_LINUX_STRING_H
#define _COMPAT_LINUX_STRING_H

#include "../../compat/config.h"

#include_next <linux/string.h>

#ifndef unsafe_memcpy
#define unsafe_memcpy(dst, src, bytes, justification)		\
		memcpy(dst, src, bytes)
#endif

#endif /* _COMPAT_LINUX_STRING_H */
