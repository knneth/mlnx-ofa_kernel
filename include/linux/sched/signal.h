#ifndef _COMPAT_LINUX_SCHED_SIGNAL_H
#define _COMPAT_LINUX_SCHED_SIGNAL_H

#include "../../../compat/config.h"

#ifdef HAVE_SCHED_SIGNAL_H
#include_next <linux/sched/signal.h>
#endif

#endif /* _COMPAT_LINUX_SCHED_SIGNAL_H */
