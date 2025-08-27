#ifndef _COMPAT_LINUX_COMPILER_GCC_H
#define _COMPAT_LINUX_COMPILER_GCC_H

#include "../../compat/config.h"

#include_next <linux/compiler-gcc.h>

#ifndef __has_attribute
# define __has_attribute(x) __GCC4_has_attribute_##x
# define __GCC4_has_attribute___copy__                0
#endif

#ifndef __copy
#if __has_attribute(__copy__)
# define __copy(symbol)                 __attribute__((__copy__(symbol)))
#else
# define __copy(symbol)
#endif
#endif /* __copy__ */

#ifndef fallthrough
# define fallthrough                    do {} while (0)  /* fallthrough */
#endif

#ifndef GCC_VERSION
#define GCC_VERSION (__GNUC__ * 10000		\
		     + __GNUC_MINOR__ * 100	\
		     + __GNUC_PATCHLEVEL__)
#endif

#endif /* _COMPAT_LINUX_COMPILER_GCC_H */
