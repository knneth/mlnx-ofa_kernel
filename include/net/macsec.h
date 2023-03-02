#ifndef _COMPAT_NET_MACSEC_H
#define _COMPAT_NET_MACSEC_H

#include "../../compat/config.h"

#include_next <net/macsec.h>

#ifndef HAVE_FUNC_MACSEC_GET_REAL_DEV
#define macsec_get_real_dev LINUX_BACKPORT(macsec_get_real_dev)
struct net_device *macsec_get_real_dev(const struct net_device *dev);
#endif /* HAVE_FUNC_MACSEC_GET_REAL_DEV_ */

#ifndef HAVE_FUNC_MACSEC_NETDEV_IS_OFFLOADED
#define macsec_netdev_is_offloaded LINUX_BACKPORT(macsec_netdev_is_offloaded)
bool macsec_netdev_is_offloaded(struct net_device *dev);
#endif /* HAVE_FUNC_MACSEC_NETDEV_IS_OFFLOADED */

#endif /* _COMPAT_NET_MACSEC_H */
