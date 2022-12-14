#ifndef _COMPAT_LINUX_KERN_LEVELS_H
#define _COMPAT_LINUX_KERN_LEVELS_H 1

#include "../../compat/config.h"

#include_next <linux/kern_levels.h>

#ifndef HAVE_LOGLEVEL_DEFAULT
/* integer equivalents of KERN_<LEVEL> */
#define LOGLEVEL_SCHED          -2      /* Deferred messages from sched code
                                         * are set to this special level */
#define LOGLEVEL_DEFAULT        -1      /* default (or last) loglevel */
#define LOGLEVEL_EMERG          0       /* system is unusable */
#define LOGLEVEL_ALERT          1       /* action must be taken immediately */
#define LOGLEVEL_CRIT           2       /* critical conditions */
#define LOGLEVEL_ERR            3       /* error conditions */
#define LOGLEVEL_WARNING        4       /* warning conditions */
#define LOGLEVEL_NOTICE         5       /* normal but significant condition */
#define LOGLEVEL_INFO           6       /* informational */
#define LOGLEVEL_DEBUG          7       /* debug-level messages */
#endif /* HAVE_LOGLEVEL_DEFAULT */
#endif	/*  _COMPAT_LINUX_KERN_LEVELS_H */
