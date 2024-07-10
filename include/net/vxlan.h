#ifndef _COMPAT_NET_VXLAN_H
#define _COMPAT_NET_VXLAN_H

#include "../../compat/config.h"
#include_next <net/vxlan.h>

#ifndef IANA_VXLAN_UDP_PORT 
#define IANA_VXLAN_UDP_PORT     4789
#endif

#ifndef HAVE_NETIF_IS_VXLAN
static inline bool netif_is_vxlan(const struct net_device *dev)
{
	return dev->rtnl_link_ops &&
		!strcmp(dev->rtnl_link_ops->kind, "vxlan");
}
#endif

#endif /* _COMPAT_NET_VXLAN_H */
