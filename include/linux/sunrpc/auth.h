#ifndef _COMPAT_LINUX_SUNRPC_AUTH_H
#define _COMPAT_LINUX_SUNRPC_AUTH_H

#include "../../../compat/config.h"

#include_next <linux/sunrpc/auth.h>

#ifndef RPCAUTH_AUTH_DATATOUCH
/* rpc_auth au_flags */
#define RPCAUTH_AUTH_DATATOUCH 0x00000002
#endif

#endif /* _COMPAT_LINUX_SUNRPC_AUTH_H */
