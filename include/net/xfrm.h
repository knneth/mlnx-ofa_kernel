#ifndef _COMPAT_NET_XFRM_H
#define _COMPAT_NET_XFRM_H 1

#include "../../compat/config.h"

#include_next <net/xfrm.h>
#ifndef HAVE_XFRM_ADD_STATS
#ifdef CONFIG_XFRM_STATISTICS
#define XFRM_ADD_STATS(net, field, val) SNMP_ADD_STATS((net)->mib.xfrm_statistics, field, val)
#else
#define XFRM_ADD_STATS(net, field, val) ((void)(net))
#endif
#endif

#if !defined(HAVE_XFRM_DEV_DIR) && !defined(HAVE_XFRM_STATE_DIR)
enum {
	XFRM_DEV_OFFLOAD_IN = 1,
	XFRM_DEV_OFFLOAD_OUT,
	XFRM_DEV_OFFLOAD_FWD,
};
#endif

#ifndef HAVE_XFRM_DEV_TYPE
enum {
	XFRM_DEV_OFFLOAD_UNSPECIFIED,
	XFRM_DEV_OFFLOAD_CRYPTO,
	XFRM_DEV_OFFLOAD_PACKET,
};
#endif

#endif	/* _COMPAT_NET_XFRM_H */
