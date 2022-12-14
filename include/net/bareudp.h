#ifndef _COMPAT_NET_BAREUDP_H
#define _COMPAT_NET_BAREUDP_H 1

#include "../../compat/config.h"

#ifdef HAVE_NET_BAREUDP_H
#include_next <net/bareudp.h>

#ifndef HAVE_NETIF_IS_BAREUDP
#include <net/rtnetlink.h>
static inline bool netif_is_bareudp(const struct net_device *dev)
{
	return dev->rtnl_link_ops &&
	       !strcmp(dev->rtnl_link_ops->kind, "bareudp");
}
#endif
#endif

#endif /* _COMPAT_NET_BAREUDP_H */
