#ifndef _COMPAT_LINUX_CLOCKSOURCE_H
#define _COMPAT_LINUX_CLOCKSOURCE_H

#include "../../compat/config.h"

#include_next <linux/clocksource.h>

#ifndef HAVE_TIMECOUNTER_ADJTIME
/**
* timecounter_adjtime - Shifts the time of the clock.
* @delta:     Desired change in nanoseconds.
*/
static inline void timecounter_adjtime(struct timecounter *tc, s64 delta)
{
	tc->nsec += delta;
}
#endif /* HAVE_TIMECOUNTER_H */

#endif /* _COMPAT_LINUX_CLOCKSOURCE_H */
