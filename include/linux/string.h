#ifndef _COMPAT_LINUX_STRING_H
#define _COMPAT_LINUX_STRING_H

#include "../../compat/config.h"

#include_next <linux/string.h>

#ifndef HAVE_STRNICMP
#ifndef __HAVE_ARCH_STRNICMP
#define strnicmp strncasecmp
#endif
#endif /* HAVE_STRNICMP */

#ifndef HAVE_MEMDUP_USER_NUL
#define memdup_user_nul LINUX_BACKPORT(memdup_user_nul)
void *memdup_user_nul(const void __user *src, size_t len);
#endif

#ifndef HAVE_MEMCPY_AND_PAD
/**
 * memcpy_and_pad - Copy one buffer to another with padding
 * @dest: Where to copy to
 * @dest_len: The destination buffer size
 * @src: Where to copy from
 * @count: The number of bytes to copy
 * @pad: Character to use for padding if space is left in destination.
 */
#define memcpy_and_pad LINUX_BACKPORT(memcpy_and_pad)
static inline void memcpy_and_pad(void *dest, size_t dest_len,
				  const void *src, size_t count, int pad)
{
	if (dest_len > count) {
		memcpy(dest, src, count);
		memset(dest + count, pad,  dest_len - count);
	} else
		memcpy(dest, src, dest_len);
}
#endif

#ifndef HAVE_KSTRTOBOOL
int kstrtobool(const char *s, bool *res);
#endif

#ifndef HAVE_MEMZERO_EXPLICIT
/**
 * memzero_explicit - Fill a region of memory (e.g. sensitive
 *		      keying data) with 0s.
 * @s: Pointer to the start of the area.
 * @count: The size of the area.
 *
 * Note: usually using memset() is just fine (!), but in cases
 * where clearing out _local_ data at the end of a scope is
 * necessary, memzero_explicit() should be used instead in
 * order to prevent the compiler from optimising away zeroing.
 *
 * memzero_explicit() doesn't need an arch-specific version as
 * it just invokes the one of memset() implicitly.
 */
#define memzero_explicit LINUX_BACKPORT(memzero_explicit)
static inline void memzero_explicit(void *s, size_t count)
{
	memset(s, 0, count);
#ifdef HAVE_BARRIER_DATA
	barrier_data(s);
#else
	barrier();
#endif
}
#endif
#endif /* _COMPAT_LINUX_STRING_H */
