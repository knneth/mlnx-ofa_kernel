#ifndef _COMPAT_NET_XFRM_H
#define _COMPAT_NET_XFRM_H 1

#include "../../compat/config.h"

#include_next <net/xfrm.h>
#ifndef XFRM_ADD_STATS
#ifdef CONFIG_XFRM_STATISTICS
#define XFRM_ADD_STATS(net, field, val) SNMP_ADD_STATS((net)->mib.xfrm_statistics, field, val)
#else
#define XFRM_ADD_STATS(net, field, val) ((void)(net))
#endif
#endif


#ifndef XFRM_ESP_NO_TRAILER
#define XFRM_ESP_NO_TRAILER     64
#endif

#endif	/* _COMPAT_NET_XFRM_H */
