/* SPDX-License-Identifier: GPL-2.0 */
#ifndef COMPAT_VDSO_CONST_H
#define COMPAT_VDSO_CONST_H

#include <uapi/linux/const.h>

#ifndef UL
#define UL(x)		(_UL(x))
#endif

#ifndef ULL
#define ULL(x)		(_ULL(x))
#endif

#endif /* COMPAT_VDSO_CONST_H */
