#ifndef _COMPAT_LINUX_DCBNL_H
#define _COMPAT_LINUX_DCBNL_H

#include "../../compat/config.h"

#include_next <linux/dcbnl.h>

#ifndef IEEE_8021QAZ_APP_SEL_DSCP
#define IEEE_8021QAZ_APP_SEL_DSCP	5
#endif

#endif /* _COMPAT_LINUX_DCBNL_H */
