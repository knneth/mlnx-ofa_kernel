#ifndef _COMPAT_LINUX_KCONFIG_H
#define _COMPAT_LINUX_KCONFIG_H 1

#include "../../compat/config.h"
#include_next <linux/kconfig.h>

#ifndef IS_REACHABLE
#define IS_REACHABLE(option) (config_enabled(option) || \
	      (config_enabled(option##_MODULE) && config_enabled(MODULE)))
#endif

#endif /* _COMPAT_LINUX_KCONFIG_H */
