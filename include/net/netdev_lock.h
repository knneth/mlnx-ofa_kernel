#ifndef _COMPAT_NET_NETDEV_LOCK_H
#define _COMPAT_NET_NETDEV_LOCK_H

#include "../../compat/config.h"

#ifdef HAVE_NET_NETDEV_LOCK_H
/* Newer kernels: net/netdev_lock.h header exists, include upstream header */
#include_next <net/netdev_lock.h>
#elif defined(HAVE_NET_DEVICE_LOCK_FIELD)
/* Older kernels: net/netdev_lock.h doesn't exist, provide functions */
#include <linux/netdevice.h>

static inline bool netdev_trylock(struct net_device *dev)
{
	return mutex_trylock(&dev->lock);
}

#ifndef HAVE_NETDEVICE_NETDEV_LOCK
static inline void netdev_unlock(struct net_device *dev)
{
	mutex_unlock(&dev->lock);
}
#endif /* HAVE_NETDEVICE_NETDEV_LOCK */
#endif

#endif /* _COMPAT_NET_NETDEV_LOCK_H */
