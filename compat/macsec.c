// SPDX-License-Identifier: GPL-2.0-or-later
#include <net/macsec.h>

#ifndef HAVE_FUNC_MACSEC_GET_REAL_DEV
#include <linux/netdevice.h>
struct macsec_dev_compat {
	struct macsec_secy secy;
	struct net_device *real_dev;
	netdevice_tracker dev_tracker;
	struct pcpu_secy_stats __percpu *stats;
	struct list_head secys;
	struct gro_cells gro_cells;
	enum macsec_offload offload;
};

struct net_device *macsec_get_real_dev(const struct net_device *dev)
{
	return (struct macsec_dev_compat *)netdev_priv(dev)->real_dev;
}
EXPORT_SYMBOL_GPL(macsec_get_real_dev);
#endif /* HAVE_FUNC_MACSEC_GET_REAL_DEV_ */
