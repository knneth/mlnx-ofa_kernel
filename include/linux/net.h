#ifndef _COMPAT_LINUX_NET_H
#define _COMPAT_LINUX_NET_H 1

#include "../../compat/config.h"

#include_next <linux/net.h>

#ifndef SOCK_ASYNC_NOSPACE
#define SOCK_ASYNC_NOSPACE SOCKWQ_ASYNC_NOSPACE
#endif

#ifndef SOCK_ASYNC_WAITDATA
#define SOCK_ASYNC_WAITDATA SOCKWQ_ASYNC_WAITDATA
#endif

#if !defined(HAVE_SENDPAGE_OK) && defined(HAVE_PAGE_COUNT)
#include <linux/page_ref.h>

static inline bool sendpage_ok(struct page *page)
{
	return !PageSlab(page) && page_count(page) >= 1;
}
#endif

#endif	/* _COMPAT_LINUX_NET_H */
