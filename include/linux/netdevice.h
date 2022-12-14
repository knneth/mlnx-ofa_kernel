#ifndef _COMPAT_LINUX_NETDEVICE_H
#define _COMPAT_LINUX_NETDEVICE_H 1

#include "../../compat/config.h"
#include <linux/kconfig.h>

#include_next <linux/netdevice.h>

/* supports eipoib flags */
#ifndef IFF_EIPOIB_VIF
#define IFF_EIPOIB_VIF  0x800       /* IPoIB VIF intf(eg ib0.x, ib1.x etc.), using IFF_DONT_BRIDGE */
#endif

#ifndef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(netdev,ops) \
    ( (netdev)->ethtool_ops = (ops) )
#endif

#if !defined(HAVE_NETDEV_EXTENDED_HW_FEATURES)     && \
    !defined(HAVE_NETDEV_OPS_EXT_NDO_FIX_FEATURES) && \
    !defined(HAVE_NETDEV_OPS_EXT_NDO_SET_FEATURES) && \
    !defined(HAVE_NDO_SET_FEATURES)
#define LEGACY_ETHTOOL_OPS
#endif

#ifndef NETDEV_BONDING_INFO
#define NETDEV_BONDING_INFO     0x0019
#endif


#ifndef HAVE_NETDEV_MASTER_UPPER_DEV_GET_RCU
#define netdev_master_upper_dev_get_rcu(x) (x)->master
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
#ifdef HAVE_ALLOC_ETHERDEV_MQ
#ifndef HAVE_NETIF_SET_REAL_NUM_TX_QUEUES
static inline void netif_set_real_num_tx_queues(struct net_device *netdev,
						unsigned int txq)
{
	netdev->real_num_tx_queues = txq;
}
#endif
#endif
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18) */

#ifndef HAVE_NETDEV_RSS_KEY_FILL
static inline void netdev_rss_key_fill(void *addr, size_t len)
{
	__be32 *hkey;

	hkey = (__be32 *)addr;
	hkey[0] = cpu_to_be32(0xD181C62C);
	hkey[1] = cpu_to_be32(0xF7F4DB5B);
	hkey[2] = cpu_to_be32(0x1983A2FC);
	hkey[3] = cpu_to_be32(0x943E1ADB);
	hkey[4] = cpu_to_be32(0xD9389E6B);
	hkey[5] = cpu_to_be32(0xD1039C2C);
	hkey[6] = cpu_to_be32(0xA74499AD);
	hkey[7] = cpu_to_be32(0x593D56D9);
	hkey[8] = cpu_to_be32(0xF3253C06);
	hkey[9] = cpu_to_be32(0x2ADC1FFC);
}
#endif

#ifndef HAVE_NETIF_TRANS_UPDATE
static inline void netif_trans_update(struct net_device *dev)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);

	if (txq->trans_start != jiffies)
		txq->trans_start = jiffies;
}
#endif

#ifndef NAPI_POLL_WEIGHT
/* Default NAPI poll() weight
 * Device drivers are strongly advised to not use bigger value
 */
#define NAPI_POLL_WEIGHT 64
#endif

#ifndef NETDEV_JOIN
#define NETDEV_JOIN           0x0014
#endif

#ifndef NETDEV_MASTER_UPPER_DEV_LINK_4_PARAMS
#define netdev_master_upper_dev_link(a,b,c,d) netdev_master_upper_dev_link(a,b)
#endif

#ifdef HAVE_ALLOC_NETDEV_MQS_5_PARAMS
#define alloc_netdev_mqs(p1, p2, p3, p4, p5, p6) alloc_netdev_mqs(p1, p2, p4, p5, p6)
#elif defined(HAVE_ALLOC_NETDEV_MQ_4_PARAMS)
#define alloc_netdev_mqs(sizeof_priv, name, name_assign_type, setup, txqs, rxqs)	\
	alloc_netdev_mq(sizeof_priv, name, setup,					\
			max_t(unsigned int, txqs, rxqs))
#endif


#ifndef HAVE_NETIF_IS_BOND_MASTER
#define netif_is_bond_master LINUX_BACKPORT(netif_is_bond_master)
static inline bool netif_is_bond_master(struct net_device *dev)
{
	return dev->flags & IFF_MASTER && dev->priv_flags & IFF_BONDING;
}
#endif

#ifndef HAVE_SELECT_QUEUE_FALLBACK_T
#define fallback(dev, skb) __netdev_pick_tx(dev, skb)
#endif

#ifndef HAVE_NAPI_SCHEDULE_IRQOFF
#define napi_schedule_irqoff(napi) napi_schedule(napi)
#endif

#ifndef HAVE_DEV_UC_DEL
#define dev_uc_del(netdev, mac) dev_unicast_delete(netdev, mac)
#endif
#ifndef HAVE_DEV_MC_DEL
#define dev_mc_del(netdev, mac) dev_mc_delete(netdev, mac, netdev->addr_len, true)
#endif

#ifdef HAVE_REGISTER_NETDEVICE_NOTIFIER_RH
#define register_netdevice_notifier register_netdevice_notifier_rh
#define unregister_netdevice_notifier unregister_netdevice_notifier_rh
#endif

#ifndef HAVE_NETDEV_NOTIFIER_INFO_TO_DEV
#define netdev_notifier_info_to_dev LINUX_BACKPORT(netdev_notifier_info_to_dev)
static inline struct net_device *
netdev_notifier_info_to_dev(void *ptr)
{
	return (struct net_device *)ptr;
}
#endif

#ifndef NET_NAME_UNKNOWN
#define NET_NAME_UNKNOWN        0       /*  unknown origin (not exposed to userspace) */
#endif


#if IS_ENABLED(CONFIG_VXLAN) && (defined(HAVE_NDO_ADD_VXLAN_PORT) || defined(HAVE_NDO_UDP_TUNNEL_ADD))
#define HAVE_KERNEL_WITH_VXLAN_SUPPORT_ON
#endif

#if (defined(HAVE_NDO_GET_STATS64) && !defined(HAVE_NETDEV_STATS_TO_STATS64))
static inline void netdev_stats_to_stats64(struct rtnl_link_stats64 *stats64,
					   const struct net_device_stats *netdev_stats)
{
#if BITS_PER_LONG == 64
	BUILD_BUG_ON(sizeof(*stats64) != sizeof(*netdev_stats));
	memcpy(stats64, netdev_stats, sizeof(*stats64));
#else
	size_t i, n = sizeof(*stats64) / sizeof(u64);
	const unsigned long *src = (const unsigned long *)netdev_stats;
	u64 *dst = (u64 *)stats64;

	BUILD_BUG_ON(sizeof(*netdev_stats) / sizeof(unsigned long) !=
		     sizeof(*stats64) / sizeof(u64));
	for (i = 0; i < n; i++)
		dst[i] = src[i];
#endif
}
#endif


#endif	/* _COMPAT_LINUX_NETDEVICE_H */
