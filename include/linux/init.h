#ifndef _COMPAT_LINUX_INIT_H
#define _COMPAT_LINUX_INIT_H

#include "../../compat/config.h"

#include_next <linux/init.h>

#define __devinit
#define __devinitdata
#define __devinitconst
#define __devexit
#define __devexitdata
#define __devexitconst
#define __devexit_p


#endif /* _COMPAT_LINUX_INIT_H */
