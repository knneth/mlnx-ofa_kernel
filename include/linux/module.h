#ifndef _COMPAT_LINUX_MODULE_H
#define _COMPAT_LINUX_MODULE_H

#include "../../compat/config.h"

#include_next <linux/module.h>

#ifdef MODULE_IMPORT_NS
#undef MODULE_IMPORT_NS
#define MODULE_IMPORT_NS(ns) MODULE_INFO(import_ns, ns)
#else
#define MODULE_IMPORT_NS(ns)
#endif

#endif /* _COMPAT_LINUX_MODULE_H */
