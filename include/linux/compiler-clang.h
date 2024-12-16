#ifndef _COMPAT_LINUX_COMPILER_CLANG_H
#define _COMPAT_LINUX_COMPILER_CLANG_H

#include "../../compat/config.h"

#include_next <linux/compiler-clang.h>

#ifndef __cleanup
#define __cleanup(func) __maybe_unused __attribute__((__cleanup__(func)))
#endif

#endif /* _COMPAT_LINUX_COMPILER_CLANG_H */
