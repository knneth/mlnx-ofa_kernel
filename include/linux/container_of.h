/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _COMPAT_LINUX_CONTAINER_OF_H
#define _COMPAT_LINUX_CONTAINER_OF_H

#include "../../compat/config.h"

#ifdef HAVE_CONTAINER_OF_H
#include_next <linux/container_of.h>
#endif
/**
 * container_of_const - cast a member of a structure out to the containing
 *			structure and preserve the const-ness of the pointer
 * @ptr:		the pointer to the member
 * @type:		the type of the container struct this is embedded in.
 * @member:		the name of the member within the struct.
 */
#ifndef container_of_const
#define container_of_const(ptr, type, member)				\
	_Generic(ptr,							\
		const typeof(*(ptr)) *: ((const type *)container_of(ptr, type, member)),\
		default: ((type *)container_of(ptr, type, member))	\
	)
#endif

#endif	/* _COMPAT_LINUX_CONTAINER_OF_H */
