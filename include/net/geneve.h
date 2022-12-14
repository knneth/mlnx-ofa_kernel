/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _COMPAT_NET_GENEVE_H
#define _COMPAT_NET_GENEVE_H

#include "../../compat/config.h"

#ifdef HAVE_NET_GENEVE_H
#include_next <net/geneve.h>
#endif

#ifndef GENEVE_UDP_PORT
#define GENEVE_UDP_PORT		6081
#endif

#ifndef HAVE_NETIF_IS_GENEVE
static inline bool netif_is_geneve(const struct net_device *dev)
{
	return dev->rtnl_link_ops &&
	       !strcmp(dev->rtnl_link_ops->kind, "geneve");
}
#endif

#endif /* _COMPAT_NET_GENEVE_H */
