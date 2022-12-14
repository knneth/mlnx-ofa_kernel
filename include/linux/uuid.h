#ifndef _COMPAT_LINUX_UUID_H
#define _COMPAT_LINUX_UUID_H

#include "../../compat/config.h"
#include <linux/version.h>

#include_next <linux/uuid.h>

#if (defined(RHEL_MAJOR) && RHEL_MAJOR -0 == 7 && RHEL_MINOR -0 >= 2) || \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0))

#ifndef HAVE_UUID_GEN

#define uuid_t		uuid_be
#define uuid_gen	uuid_be_gen
#define uuid_parse	uuid_be_to_bin

static inline void uuid_copy(uuid_t *dst, const uuid_t *src)
{
	memcpy(dst, src, sizeof(uuid_be));
}

#ifndef HAVE_UUID_BE_TO_BIN
/*
* The length of a UUID string ("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
* not including trailing NUL.
*/
#define        UUID_STRING_LEN         36
#define uuid_is_valid LINUX_BACKPORT(uuid_is_valid)
bool __must_check uuid_is_valid(const char *uuid);

#define uuid_le_index LINUX_BACKPORT(uuid_le_index)
extern const u8 uuid_le_index[16];
#define uuid_be_index LINUX_BACKPORT(uuid_be_index)
extern const u8 uuid_be_index[16];

#define uuid_le_to_bin LINUX_BACKPORT(uuid_le_to_bin)
int uuid_le_to_bin(const char *uuid, uuid_le *u);
#define uuid_be_to_bin LINUX_BACKPORT(uuid_be_to_bin)
int uuid_be_to_bin(const char *uuid, uuid_be *u);

#endif /* HAVE_UUID_BE_TO_BIN */

#endif /* HAVE_UUID_GEN */

#ifndef HAVE_UUID_EQUAL
#define uuid_equal LINUX_BACKPORT(uuid_equal)
static inline bool uuid_equal(const uuid_t *u1, const uuid_t *u2)
{
	return memcmp(u1, u2, sizeof(uuid_t)) == 0;
}
#endif

#endif

#endif /* _COMPAT_LINUX_UUID_H */
