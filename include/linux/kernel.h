#ifndef _COMPAT_LINUX_KERNEL_H
#define _COMPAT_LINUX_KERNEL_H

#include "../../compat/config.h"

#include_next <linux/kernel.h>

#ifndef HAVE_PANIC_H
#ifndef TAINT_FWCTL
#define TAINT_FWCTL                19
#undef  TAINT_FLAGS_COUNT
#define TAINT_FLAGS_COUNT          20
#endif
#endif /* HAVE_PANIC_H */

#ifndef PTR_IF
#define PTR_IF(cond, ptr)	((cond) ? (ptr) : NULL)
#endif

#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, a)        __ALIGN_KERNEL((x) - ((a) - 1), (a))
#endif

#ifndef DIV_ROUND_DOWN_ULL
#define DIV_ROUND_DOWN_ULL(ll, d) \
        ({ unsigned long long _tmp = (ll); do_div(_tmp, d); _tmp; })
#endif

#ifndef DIV_ROUND_UP_ULL
#define DIV_ROUND_UP_ULL(ll,d) \
	({ unsigned long long _tmp = (ll)+(d)-1; do_div(_tmp, d); _tmp; })
#endif

#ifndef u64_to_user_ptr
#define u64_to_user_ptr(x) (            \
{       				\
	typecheck(u64, x);          	\
	(void __user *)(uintptr_t)x;    \
}                                 	\
)
#endif

#endif /* _COMPAT_LINUX_KERNEL_H */
