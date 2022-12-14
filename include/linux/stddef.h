#ifndef _COMPAT_LINUX_STDDEF_H
#define _COMPAT_LINUX_STDDEF_H

#include "../../compat/config.h"

#include_next <linux/stddef.h>

#ifndef sizeof_field
/**
 * sizeof_field(TYPE, MEMBER)
 *
 * @TYPE: The structure containing the field of interest
 * @MEMBER: The field to return the size of
 */
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#endif /* sizeof_field */

#define __DECLARE_FLEX_ARRAY(TYPE, NAME)  \
	struct { \
		struct { } __empty_ ## NAME; \
		TYPE NAME[]; \
	}

#define DECLARE_FLEX_ARRAY(TYPE, NAME) \
	__DECLARE_FLEX_ARRAY(TYPE, NAME)

#endif /* _COMPAT_LINUX_STDDEF_H */
