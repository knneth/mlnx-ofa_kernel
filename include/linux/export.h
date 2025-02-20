#ifndef _COMPAT_LINUX_EXPORT_H
#define _COMPAT_LINUX_EXPORT_H 1

#include "../../compat/config.h"

#include_next <linux/export.h>

#ifdef EXPORT_SYMBOL_NS_GPL
#undef EXPORT_SYMBOL_NS_GPL
#ifdef __EXPORT_SYMBOL_REF  // ddb5cdbafaaa 6.5 and above
#define EXPORT_SYMBOL_NS_GPL(sym, ns)  __EXPORT_SYMBOL(sym, "GPL", ns)
#else // 6.4 and below
#ifdef __EXPORT_SYMBOL_NS // 5.4 only
#define EXPORT_SYMBOL_NS_GPL(sym, ns)   __EXPORT_SYMBOL_NS(sym, "_gpl", ns)
#else //  __EXPORT_SYMBOL_NS
#define EXPORT_SYMBOL_NS_GPL(sym, ns)   __EXPORT_SYMBOL(sym, "_gpl", ns)
#endif // __EXPORT_SYMBOL_NS
#endif // __EXPORT_SYMBOL_REF
#else // EXPORT_SYMBOL_NS_GPL
#define EXPORT_SYMBOL_NS_GPL(sym, ns)   EXPORT_SYMBOL_GPL(sym)
#endif // EXPORT_SYMBOL_NS_GPL

#ifndef __EXPORT_SYMBOL_NS
#define __EXPORT_SYMBOL_NS __EXPORT_SYMBOL
#endif

#endif	/* _COMPAT_LINUX_EXPORT_H */
