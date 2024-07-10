/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2014 Felix Fietkau <nbd@nbd.name>
 * Copyright (C) 2004 - 2009 Ivo van Doorn <IvDoorn@gmail.com>
 */

#ifndef _COMPAT_LINUX_BITFIELD_H
#define _COMAPAT_LINUX_BITFIELD_H

#include "../../compat/config.h"

#include_next <linux/bitfield.h>


#ifndef FIELD_PREP_CONST
#define __BF_CHECK_POW2(n)  BUILD_BUG_ON_ZERO(((n) & ((n) - 1)) != 0)

#define FIELD_PREP_CONST(_mask, _val)                                 \
(                                                       \
								/* mask must be non-zero */                      \
								BUILD_BUG_ON_ZERO((_mask) == 0) +                \
								/* check if value fits */                        \
								BUILD_BUG_ON_ZERO(~((_mask) >> __bf_shf(_mask)) & (_val)) + \
								/* check if mask is contiguous */                \
								__BF_CHECK_POW2((_mask) + (1ULL << __bf_shf(_mask))) +  \
								/* and create the value */                       \
								(((typeof(_mask))(_val) << __bf_shf(_mask)) & (_mask))  \
								)
#endif /* FIELD_PREP_CONST */
#endif /* _COMPAT_LINUX_BITFIELD_H */
