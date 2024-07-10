#ifndef _COMPAT_NET_SWITCHDEV_H
#define _COMPAT_NET_SWITCHDEV_H

#include "../../compat/config.h"

#include_next <net/switchdev.h>

#if !defined(HAVE_NETDEV_PORT_SAME_PARENT_ID) && defined(HAVE_SWITCHDEV_PORT_SAME_PARENT_ID)
static inline bool
netdev_port_same_parent_id(struct net_device *a, struct net_device *b)
{
	return switchdev_port_same_parent_id(a, b);
}
#endif

#endif /* _COMPAT_NET_SWITCHDEV_H */
