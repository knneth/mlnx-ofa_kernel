#ifndef _COMPAT_LINUX_COMPILER_TYPES_H
#define _COMPAT_LINUX_COMPILER_TYPES_H

#include "../../compat/config.h"

#include_next <linux/compiler_types.h>

/*
 * Optional: only supported since gcc >= 15
 * Optional: only supported since clang >= 18
 *
 *   gcc: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108896
 * clang: https://github.com/llvm/llvm-project/pull/76348
 */
#ifndef HAVE___COUNTED_BY
#if __has_attribute(__counted_by__)
# define __counted_by(member)           __attribute__((__counted_by__(member)))
#else
# define __counted_by(member)
#endif
#endif /* HAVE___COUNTED_BY */

#endif /* _COMPAT_LINUX_COMPILER_TYPES_H */
