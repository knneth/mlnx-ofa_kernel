#ifndef _COMPAT_LINUX_NETDEVICE_H
#define _COMPAT_LINUX_NETDEVICE_H 1

#include "../../compat/config.h"
#include <linux/kconfig.h>

#include_next <linux/netdevice.h>

#if !IS_ENABLED(CONFIG_NET_CLS_E2E_CACHE)
#define TC_SETUP_E2E_BLOCK 0xFFFF
#endif

#undef alloc_netdev
#define alloc_netdev(sizeof_priv, name, name_assign_type, setup) \
	        alloc_netdev_mqs(sizeof_priv, name, name_assign_type, setup, 1, 1)

#ifndef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(netdev,ops) \
    ( (netdev)->ethtool_ops = (ops) )
#endif

static inline int netdev_set_master(struct net_device *dev,
				    struct net_device *master)
{
	int rc = 0;

	if (master) {
		rc = netdev_master_upper_dev_link(dev, master,
						  NULL, NULL, NULL);
	} else {
		master = netdev_master_upper_dev_get_rcu(dev);
		netdev_upper_dev_unlink(dev, master);
	}
	return rc;
}

/* This is geared toward old kernels that have Bonding.h and don't have TX type.
 * It's tested on RHEL 6.9, 7.2 and 7.3 in addition to Ubuntu 16.04.
 */


#ifndef HAVE_NETDEV_NET_NOTIFIER
struct netdev_net_notifier {
	struct list_head list;
	struct notifier_block *nb;
};

static inline int
register_netdevice_notifier_dev_net(struct net_device *dev,
				    struct notifier_block *nb,
				    struct netdev_net_notifier *nn)
{
	return register_netdevice_notifier(nb);
}

static inline int
unregister_netdevice_notifier_dev_net(struct net_device *dev,
				      struct notifier_block *nb,
				      struct netdev_net_notifier *nn)
{
	return unregister_netdevice_notifier(nb);
}
#endif /* HAVE_NETDEV_NET_NOTIFIER */

/* const version */
static inline bool netif_device_present_const(const struct net_device *dev)
{
	return test_bit(__LINK_STATE_PRESENT, &dev->state);
}

#ifndef HAVE_NET_PREFETCH
static inline void net_prefetch(void *p)
{
       prefetch(p);
#if L1_CACHE_BYTES < 128
       prefetch((u8 *)p + L1_CACHE_BYTES);
#endif
}

static inline void net_prefetchw(void *p)
{
       prefetchw(p);
#if L1_CACHE_BYTES < 128
       prefetchw((u8 *)p + L1_CACHE_BYTES);
#endif
}
#endif /* HAVE_NET_PREFETCH */

#if !defined(HAVE_NETDEV_PUT_AND_HOLD)

static inline void mlx5_compat_dev_hold(struct net_device *netdev)
{
	if (netdev)
		dev_hold(netdev);
}

static inline void mlx5_compat_dev_put(struct net_device *netdev)
{
	if (netdev)
		dev_put(netdev);
}

#undef dev_hold
#define dev_hold(net_device_ptr) mlx5_compat_dev_hold(net_device_ptr)

#undef dev_put
#define dev_put(net_device_ptr) mlx5_compat_dev_put(net_device_ptr)

#endif /* HAVE_NETDEV_PUT_AND_HOLD */

#ifndef HAVE_DEV_NET_RCU
static inline struct net *dev_net_rcu(struct net_device *dev)
{
#ifdef HAVE_READ_PNET_RCU
	return read_pnet_rcu(&dev->nd_net);
#else

#ifdef CONFIG_NET_NS
	return rcu_dereference(dev->nd_net.net);
#else
	return &init_net;
#endif	/* CONFIG_NET_NS */

#endif	/* HAVE_READ_PNET_RCU */
}
#endif	/* HAVE_DEV_NET_RCU */

#undef for_each_netdev_in_bond_rcu
#define for_each_netdev_in_bond_rcu(bond, slave)        \
	for_each_netdev_rcu(dev_net_rcu(bond), slave)   \
		if (netdev_master_upper_dev_get_rcu(slave) == (bond))

#endif	/* _COMPAT_LINUX_NETDEVICE_H */
