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

/* supports eipoib flags */
#ifndef IFF_EIPOIB_VIF
#define IFF_EIPOIB_VIF  0x800       /* IPoIB VIF intf(eg ib0.x, ib1.x etc.), using IFF_DONT_BRIDGE */
#endif

#ifndef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(netdev,ops) \
    ( (netdev)->ethtool_ops = (ops) )
#endif

#ifndef NETDEV_BONDING_INFO
#define NETDEV_BONDING_INFO     0x0019
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

#ifndef NAPI_POLL_WEIGHT
/* Default NAPI poll() weight
 * Device drivers are strongly advised to not use bigger value
 */
#define NAPI_POLL_WEIGHT 64
#endif

#ifndef NETDEV_JOIN
#define NETDEV_JOIN           0x0014
#endif

/* This is geared toward old kernels that have Bonding.h and don't have TX type.
 * It's tested on RHEL 6.9, 7.2 and 7.3 in addition to Ubuntu 16.04.
 */

#ifndef NET_NAME_UNKNOWN
#define NET_NAME_UNKNOWN        0       /*  unknown origin (not exposed to userspace) */
#endif

#ifndef netdev_WARN_ONCE

#define netdev_level_once(level, dev, fmt, ...)			\
do {								\
	static bool __print_once __read_mostly;			\
								\
	if (!__print_once) {					\
		__print_once = true;				\
		netdev_printk(level, dev, fmt, ##__VA_ARGS__);	\
	}							\
} while (0)

#define netdev_emerg_once(dev, fmt, ...) \
	netdev_level_once(KERN_EMERG, dev, fmt, ##__VA_ARGS__)
#define netdev_alert_once(dev, fmt, ...) \
	netdev_level_once(KERN_ALERT, dev, fmt, ##__VA_ARGS__)
#define netdev_crit_once(dev, fmt, ...) \
	netdev_level_once(KERN_CRIT, dev, fmt, ##__VA_ARGS__)
#define netdev_err_once(dev, fmt, ...) \
	netdev_level_once(KERN_ERR, dev, fmt, ##__VA_ARGS__)
#define netdev_warn_once(dev, fmt, ...) \
	netdev_level_once(KERN_WARNING, dev, fmt, ##__VA_ARGS__)
#define netdev_notice_once(dev, fmt, ...) \
	netdev_level_once(KERN_NOTICE, dev, fmt, ##__VA_ARGS__)
#define netdev_info_once(dev, fmt, ...) \
	netdev_level_once(KERN_INFO, dev, fmt, ##__VA_ARGS__)

#endif /* netdev_WARN_ONCE */

/* WA for broken netdev_WARN_ONCE in some kernels */
#ifdef netdev_WARN_ONCE
#undef netdev_WARN_ONCE
#endif
#define netdev_WARN_ONCE(dev, format, args...)				\
	WARN_ONCE(1, "netdevice: %s%s: " format, netdev_name(dev),	\
		  netdev_reg_state(dev), ##args)

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

#ifndef HAVE___NETDEV_TX_SENT_QUEUE
static inline bool __netdev_tx_sent_queue(struct netdev_queue *dev_queue,
					  unsigned int bytes,
					  bool xmit_more)
{
	if (xmit_more) {
#ifdef CONFIG_BQL
		dql_queued(&dev_queue->dql, bytes);
#endif
		return netif_tx_queue_stopped(dev_queue);
	}
	netdev_tx_sent_queue(dev_queue, bytes);
	return true;
}
#endif /* HAVE___NETDEV_TX_SENT_QUEUE */

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

#endif	/* _COMPAT_LINUX_NETDEVICE_H */
