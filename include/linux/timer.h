#ifndef _COMPAT_LINUX_TIMER_H
#define _COMPAT_LINUX_TIMER_H 1

#include "../../compat/config.h"

#include_next <linux/timer.h>

/* Backport for kernel 6.16+ where from_timer was renamed to timer_container_of */
#ifndef HAVE_FROM_TIMER
#define from_timer(var, callback_timer, timer_fieldname) \
	timer_container_of(var, callback_timer, timer_fieldname)
#endif

#endif /* _COMPAT_LINUX_TIMER_H */
