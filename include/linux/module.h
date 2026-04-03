#ifndef _COMPAT_LINUX_MODULE_H
#define _COMPAT_LINUX_MODULE_H

#include "../../compat/config.h"

#include_next <linux/module.h>

/* MODULE_IMPORT_NS is defind on all supported OS */
#undef MODULE_IMPORT_NS

#ifdef HAVE___EXPORT_SYMBOL_NS // 5.4 only
#define MODULE_IMPORT_NS(ns) MODULE_INFO(import_ns, #ns)
#else /* HAVE___EXPORT_SYMBOL_NS */
#define MODULE_IMPORT_NS(ns) MODULE_INFO(import_ns, ns)
#endif /* HAVE___EXPORT_SYMBOL_NS */

#endif /* _COMPAT_LINUX_MODULE_H */
