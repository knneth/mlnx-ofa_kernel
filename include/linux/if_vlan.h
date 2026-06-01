#ifndef _COMPAT_LINUX_IF_VLAN_H
#define _COMPAT_LINUX_IF_VLAN_H

#include "../../compat/config.h"

#include_next <linux/if_vlan.h>

#ifndef skb_vlan_tag_present
#define skb_vlan_tag_present vlan_tx_tag_present
#define skb_vlan_tag_get vlan_tx_tag_get
#define skb_vlan_tag_get_id vlan_tx_tag_get_id
#endif

static inline int vlan_get_encap_level(struct net_device *dev)
{
#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
	struct net_device *real_dev;

	BUG_ON(!is_vlan_dev(dev));

	real_dev = vlan_dev_priv(dev)->real_dev;

	return (real_dev && is_vlan_dev(real_dev)) ? 2 : 1;
#else
	BUG();

	return 0;
#endif
}

#endif /* _COMPAT_LINUX_IF_VLAN_H */
