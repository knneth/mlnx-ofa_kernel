#ifndef _COMPAT_LINUX_EXPORT_H
#define _COMPAT_LINUX_EXPORT_H 1

#include "../../compat/config.h"

#include_next <linux/export.h>

#ifndef EXPORT_SYMBOL_NS_GPL
#define EXPORT_SYMBOL_NS_GPL(sym, ns)   EXPORT_SYMBOL_GPL(sym)
#endif

#ifndef __EXPORT_SYMBOL_NS
#define __EXPORT_SYMBOL_NS __EXPORT_SYMBOL
#endif

#endif	/* _COMPAT_LINUX_EXPORT_H */
