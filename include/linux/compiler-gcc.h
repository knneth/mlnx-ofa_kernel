#ifndef _COMPAT_LINUX_COMPILER_GCC_H
#define _COMPAT_LINUX_COMPILER_GCC_H

#include "../../compat/config.h"

#include_next <linux/compiler-gcc.h>

#ifndef fallthrough
# define fallthrough                    do {} while (0)  /* fallthrough */
#endif

#ifndef GCC_VERSION
#define GCC_VERSION (__GNUC__ * 10000		\
		     + __GNUC_MINOR__ * 100	\
		     + __GNUC_PATCHLEVEL__)
#endif

#endif /* _COMPAT_LINUX_COMPILER_GCC_H */
