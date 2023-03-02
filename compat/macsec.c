// SPDX-License-Identifier: GPL-2.0-or-later
#include <net/macsec.h>

#ifndef HAVE_FUNC_MACSEC_GET_REAL_DEV
#include <linux/netdevice.h>
#include <net/gro_cells.h>

#ifdef CONFIG_NET_DEV_REFCNT_TRACKER
#include <linux/ref_tracker.h>
typedef struct ref_tracker *netdevice_tracker_compat;
#else
typedef struct {} netdevice_tracker_compat;
#endif

struct macsec_dev_compat {
	struct macsec_secy secy;
	struct net_device *real_dev;
	netdevice_tracker_compat dev_tracker;
	struct pcpu_secy_stats __percpu *stats;
	struct list_head secys;
	struct gro_cells gro_cells;
	enum macsec_offload offload;
};

struct net_device *macsec_get_real_dev(const struct net_device *dev)
{
	return ((struct macsec_dev_compat *)netdev_priv(dev))->real_dev;
}
EXPORT_SYMBOL_GPL(macsec_get_real_dev);
#endif /* HAVE_FUNC_MACSEC_GET_REAL_DEV_ */

#ifndef HAVE_FUNC_MACSEC_NETDEV_IS_OFFLOADED
#ifdef HAVE_FUNC_MACSEC_GET_REAL_DEV
#include <linux/netdevice.h>
#include <net/gro_cells.h>

#ifdef CONFIG_NET_DEV_REFCNT_TRACKER
#include <linux/ref_tracker.h>
typedef struct ref_tracker *netdevice_tracker_compat;
#else
typedef struct {} netdevice_tracker_compat;
#endif

struct macsec_dev_compat {
	struct macsec_secy secy;
	struct net_device *real_dev;
	netdevice_tracker_compat dev_tracker;
	struct pcpu_secy_stats __percpu *stats;
	struct list_head secys;
	struct gro_cells gro_cells;
	enum macsec_offload offload;
};
#endif
#define MACSEC_OFFLOAD_PHY_COMPAT 1
#define MACSEC_OFFLOAD_MAC_COMPAT 2

bool macsec_netdev_is_offloaded(struct net_device *dev)
{
	struct macsec_dev_compat *macsec_dev;

	if (!dev)
		return false;

	macsec_dev = (struct macsec_dev_compat *)netdev_priv(dev);

	if (macsec_dev->offload == MACSEC_OFFLOAD_MAC_COMPAT ||
	    macsec_dev->offload == MACSEC_OFFLOAD_PHY_COMPAT)
		return true;

	return false;
}
EXPORT_SYMBOL_GPL(macsec_netdev_is_offloaded);
#endif /* HAVE_FUNC_MACSEC_NETDEV_IS_OFFLOADED */
