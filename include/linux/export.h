#ifndef _COMPAT_LINUX_EXPORT_H
#define _COMPAT_LINUX_EXPORT_H 1

#include "../../compat/config.h"

#include_next <linux/export.h>

#ifdef HAVE_EXPORT_SYMBOL_NS_GPL
#undef EXPORT_SYMBOL_NS_GPL
#ifdef HAVE___EXPORT_SYMBOL_REF  // ddb5cdbafaaa 6.5 and above
#define EXPORT_SYMBOL_NS_GPL(sym, ns)  __EXPORT_SYMBOL(sym, "GPL", ns)
#else // 6.4 and below
#ifdef HAVE___EXPORT_SYMBOL_NS // 5.4 only
#define EXPORT_SYMBOL_NS_GPL(sym, ns)   __EXPORT_SYMBOL_NS(sym, "_gpl", ns)
#else //  HAVE___EXPORT_SYMBOL_NS
#define EXPORT_SYMBOL_NS_GPL(sym, ns)   __EXPORT_SYMBOL(sym, "_gpl", ns)
#endif // HAVE___EXPORT_SYMBOL_NS
#endif // HAVE___EXPORT_SYMBOL_REF
#else // HAVE_EXPORT_SYMBOL_NS_GPL
#define EXPORT_SYMBOL_NS_GPL(sym, ns)   EXPORT_SYMBOL_GPL(sym)
#endif // HAVE_EXPORT_SYMBOL_NS_GPL

#endif	/* _COMPAT_LINUX_EXPORT_H */
