#ifndef _COMPAT_LINUX_TIMER_H
#define _COMPAT_LINUX_TIMER_H 1

#include "../../compat/config.h"

#include_next <linux/timer.h>

#ifndef HAVE_TIMER_CONTAINER_OF
/* Backport for kernel 6.16+ where from_timer was renamed to timer_container_of */
#define timer_container_of(var, callback_timer, timer_fieldname)	\
		container_of(callback_timer, typeof(*var), timer_fieldname)
#endif

#endif /* _COMPAT_LINUX_TIMER_H */
