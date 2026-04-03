#ifndef _COMPAT_LINUX_SUNRPC_SVC_H
#define _COMPAT_LINUX_SUNRPC_SVC_H

#include "../../../compat/config.h"
#include_next <linux/sunrpc/svc.h>

// Define RPCSVC_MAXPAGES if kernel doesn't have it
#ifndef HAVE_RPCSVC_MAXPAGES
#define RPCSVC_MAXPAGES ((RPCSVC_MAXPAYLOAD+PAGE_SIZE-1)/PAGE_SIZE + 2 + 1)
#endif

#ifndef HAVE_SVC_SERV_MAXPAGES
static inline unsigned long svc_serv_maxpages(const struct svc_serv *serv)
{
	return DIV_ROUND_UP(serv->sv_max_mesg, PAGE_SIZE) + 2 + 1;
}
#endif
#endif /* _COMPAT_LINUX_SUNRPC_SVC_H */
