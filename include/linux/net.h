#ifndef _COMPAT_LINUX_NET_H
#define _COMPAT_LINUX_NET_H 1

#include "../../compat/config.h"

#include_next <linux/net.h>

#if !defined(HAVE_SENDPAGE_OK)
#include <linux/page_ref.h>

static inline bool sendpage_ok(struct page *page)
{
	return !PageSlab(page) && page_count(page) >= 1;
}
#endif

#endif	/* _COMPAT_LINUX_NET_H */
