#ifndef _COMPAT_LINUX_EXPORT_H
#define _COMPAT_LINUX_EXPORT_H 1

#include "../../compat/config.h"
#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0))
#include_next <linux/export.h>
#else
#include <linux/module.h>
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)) */

#ifndef EXPORT_SYMBOL_NS_GPL
#define EXPORT_SYMBOL_NS_GPL(sym, ns)   EXPORT_SYMBOL_GPL(sym)
#endif

#ifndef __EXPORT_SYMBOL_NS
#define __EXPORT_SYMBOL_NS __EXPORT_SYMBOL
#endif

#endif	/* _COMPAT_LINUX_EXPORT_H */
