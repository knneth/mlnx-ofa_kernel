#ifndef _COMPAT_LINUX_COMPILER_ATTRIBUTES_H
#define _COMPAT_LINUX_COMPILER_ATTRIBUTES_H

#include "../../compat/config.h"

#include_next <linux/compiler_attributes.h>
#include <linux/types.h>

#ifndef __GCC4_has_attribute___fallthrough__
# define __GCC4_has_attribute___fallthrough__         0
 /* Add the pseudo keyword 'fallthrough' so case statement blocks
 * must end with any of these keywords:
 *   break;
 *   fallthrough;
 *   goto <label>;
 *   return [expression];
 *
 *  gcc: https://gcc.gnu.org/onlinedocs/gcc/Statement-Attributes.html#Statement-Attributes
 */
#undef fallthrough
#if __has_attribute(__fallthrough__)
# define fallthrough                    __attribute__((__fallthrough__))
#else
# define fallthrough                    do {} while (0)  /* fallthrough */
#endif
#endif /* __GCC4_has_attribute___fallthrough__ */

/*
 * Optional: only supported since gcc >= 15
 * Optional: only supported since clang >= 18
 *
 *   gcc: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108896
 * clang: https://github.com/llvm/llvm-project/pull/76348
 */
#ifndef __counted_by
#if __has_attribute(__counted_by__)
# define __counted_by(member)           __attribute__((__counted_by__(member)))
#else
# define __counted_by(member)
#endif
#endif /* __counted_by */

#ifndef __cleanup
#define __cleanup(func)			__attribute__((__cleanup__(func)))
#endif
#endif /* _COMPAT_LINUX_COMPILER_ATTRIBUTES_H */
