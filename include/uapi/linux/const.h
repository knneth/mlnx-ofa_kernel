/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* const.h: Macros for dealing with constants.  */

#ifndef _COMPAT_UAPI_LINUX_CONST_H
#define _COMPAT_UAPI_LINUX_CONST_H

/* Some constant macros are used in both assembler and
 * C code.  Therefore we cannot annotate them always with
 * 'UL' and other type specifiers unilaterally.  We
 * use the following macros to deal with this.
 *
 * Similarly, _AT() will cast an expression with a type in C, but
 * leave it unchanged in asm.
 */
#include "../../../compat/config.h"

#include_next <uapi/linux/const.h>

#ifdef __ASSEMBLY__
#ifndef _AC
#define _AC(X,Y)	X
#endif
#ifndef _AT
#define _AT(T,X)	X
#endif
#else
#ifndef __AC
#define __AC(X,Y)	(X##Y)
#endif
#ifndef _AC
#define _AC(X,Y)	__AC(X,Y)
#endif
#ifndef _AT
#define _AT(T,X)	((T)(X))
#endif
#endif /* __ASSEMBLY__ */

#ifndef _UL
#define _UL(x)		(_AC(x, UL))
#endif
#ifndef _ULL
#define _ULL(x)		(_AC(x, ULL))
#endif

#ifndef _BITUL
#define _BITUL(x)	(_UL(1) << (x))
#endif
#ifndef _BITULL
#define _BITULL(x)	(_ULL(1) << (x))
#endif

#endif /* _COMPAT__UAPI_LINUX_CONST_H */
