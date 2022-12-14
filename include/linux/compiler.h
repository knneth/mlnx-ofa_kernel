#ifndef _COMPAT_COMPILER_H
#define _COMPAT_COMPILER_H

#include_next <linux/compiler.h>

#ifndef __percpu
#define __percpu
#endif

#endif /* _COMPAT_COMPILER_H */
