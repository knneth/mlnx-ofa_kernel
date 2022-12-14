#ifndef COMPAT_LINUX_STDDEF_H
#define COMPAT_LINUX_STDDEF_H

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

#endif /* COMPAT_LINUX_STDDEF_H */
