#ifndef _COMPAT_LINUX_STRING_H
#define _COMPAT_LINUX_STRING_H

#include "../../compat/config.h"

#include_next <linux/string.h>

#ifndef HAVE_STRNICMP
#ifndef __HAVE_ARCH_STRNICMP
#define strnicmp strncasecmp
#endif
#endif /* HAVE_STRNICMP */

#ifndef HAVE_MEMCHR_INV
#define memchr_inv LINUX_BACKPORT(memchr_inv)
void *memchr_inv(const void *start, int c, size_t bytes);
#endif

#ifndef HAVE_MEMDUP_USER_NUL
#define memdup_user_nul LINUX_BACKPORT(memdup_user_nul)
void *memdup_user_nul(const void __user *src, size_t len);
#endif

#endif /* _COMPAT_LINUX_STRING_H */
