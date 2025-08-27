#ifndef _COMPAT_LINUX_SUNRPC_SVC_H
#define _COMPAT_LINUX_SUNRPC_SVC_H

#include "../../../compat/config.h"
#include_next <linux/sunrpc/svc.h>

// Define RPCSVC_MAXPAGES if kernel doesn't have it
#ifndef HAVE_RPCSVC_MAXPAGES
#define RPCSVC_MAXPAGES ((RPCSVC_MAXPAYLOAD+PAGE_SIZE-1)/PAGE_SIZE + 2 + 1)
#endif

#endif /* _COMPAT_LINUX_SUNRPC_SVC_H */
