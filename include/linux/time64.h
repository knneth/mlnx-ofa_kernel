#ifndef _COMPAT_LINUX_TIME64_H
#define _COMPAT_LINUX_TIME64_H 1

#include "../../compat/config.h"

#ifdef HAVE_TIME64_H
#include_next <linux/time64.h>
#endif

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC    1000000000L
#endif

#endif	/* _COMPAT_LINUX_TIME64_H */
