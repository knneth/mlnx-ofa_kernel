dnl Examine kernel functionality
AC_DEFUN([LINUX_CONFIG_COMPAT],
[
	AC_MSG_CHECKING([if has netdev_notifier_info_to_dev])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/netdevice.h>
	],[
		return netdev_notifier_info_to_dev(NULL) ? 1 : 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_NOTIFIER_INFO_TO_DEV, 1,
			[netdev_notifier_info_to_dev is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm has register_netdevice_notifier_rh])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/netdevice.h>
	],[
		return register_netdevice_notifier_rh(NULL);
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REGISTER_NETDEVICE_NOTIFIER_RH, 1,
			[register_netdevice_notifier_rh is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if get_user_pages uses gup flags])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		unsigned long start;
		unsigned long nr_pages;
		unsigned int gup_flags;
		struct page **page_list;
		struct vm_area_struct **vmas;
		int ret;

		ret = get_user_pages(start, nr_pages, gup_flags, page_list,
					vmas);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_USER_PAGES_GUP_FLAGS, 1,
			[get_user_pages uses gup_flags])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if string.h has memchr_inv])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/string.h>
	],[
		memchr_inv(NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MEMCHR_INV, 1,
		[memchr_inv is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ip6_fib.h has ip6_rt_put])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <uapi/linux/in6.h>
	#include <net/ip6_fib.h>
	],[
		ip6_rt_put(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IP6_RT_PUT, 1,
		[ip6_rt_put is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_namespace.h has pernet_operations_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <net/net_namespace.h>
	],[
		int cma_pernet_id = 0;
		int ret;

		struct pernet_operations test = {
			.id = &cma_pernet_id,
		};

		ret = register_pernet_subsys(&test);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PERENT_OPERATIONS_ID, 1,
		[pernet_operations_id is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if rtble has direct dst])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <net/route.h>
	],[
		struct rtable *rt;
		struct dst_entry *dst = NULL;

                rt = container_of(dst, struct rtable, dst);
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RT_DIRECT_DST, 1,
		[rtble has direct dst])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm has get_user_pages_remote with 7 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/mm.h>
	],[
		get_user_pages_remote(NULL, NULL, 0, 0, 0, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_USER_PAGES_REMOTE_7_PARAMS, 1,
			[get_user_pages_remote is defined with 7 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm has get_user_pages_remote with 8 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/mm.h>
	],[
		get_user_pages_remote(NULL, NULL, 0, 0, 0, 0, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_USER_PAGES_REMOTE_8_PARAMS, 1,
			[get_user_pages_remote is defined with 8 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm has get_user_pages_remote with 8 parameters with locked])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/mm.h>
	],[
		get_user_pages_remote(NULL, NULL, 0, 0, 0, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_USER_PAGES_REMOTE_8_PARAMS_W_LOCKED, 1,
			[get_user_pages_remote is defined with 8 parameters with locked])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if kernel has ktime_get_ns])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ktime.h>
	],[
		unsigned long long ns;

		ns = ktime_get_ns();
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KTIME_GET_NS, 1,
			  [ktime_get_ns defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if if_vlan.h has __vlan_get_protocol])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_vlan.h>
	],[
		__vlan_get_protocol(NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VLAN_GET_PROTOCOL, 1,
			  [__vlan_get_protocol defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if page_ref.h has page_ref_count/add/sub/inc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/page_ref.h>
	],[
		page_ref_count(NULL);
		page_ref_add(NULL, 0);
		page_ref_sub(NULL, 0);
		page_ref_inc(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_REF_COUNT_ADD_SUB_INC, 1,
			  [page_ref_count/add/sub/inc defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ifla_vf_info has tx_rate])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_link.h>
	],[
		struct ifla_vf_info *ivf;

		ivf->max_tx_rate = 0;
		ivf->min_tx_rate = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TX_RATE_LIMIT, 1,
			  [max_tx_rate is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has ndo_set_vf_tx_rate])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops ndops = {
			.ndo_set_vf_tx_rate = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VF_TX_RATE, 1,
			  [ndo_set_vf_tx_rate is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has ndo_get_phys_port_name])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops ndops = {
			.ndo_get_phys_port_name = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_GET_PHYS_PORT_NAME, 1,
			  [ndo_get_phys_port_name is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_ops has eswitch_mode_get/set])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_ops dlops = {
			.eswitch_mode_get = NULL,
			.eswitch_mode_set = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(DEVLINK_HAS_ESWITCH_MODE_GET_SET, 1,
			  [eswitch_mode_get/set is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ifla_vf_info has vlan_proto])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_link.h>
	],[
		struct ifla_vf_info *ivf;

		ivf->vlan_proto = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VF_VLAN_PROTO, 1,
			  [vlan_proto is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if napi_gro_flush has 2 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		napi_gro_flush(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(NAPI_GRO_FLUSH_2_PARAMS, 1,
			  [napi_gro_flush has 2 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_master_upper_dev_link gets 4 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_master_upper_dev_link(NULL, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(NETDEV_MASTER_UPPER_DEV_LINK_4_PARAMS, 1,
			  [netdev_master_upper_dev_link gets 4 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_rxfh])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_rxfh_key_size = NULL,
			.get_rxfh = NULL,
			.set_rxfh = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_RXFH, 1,
			  [get/set_rxfh is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get_rxfh_indir_size])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_rxfh_indir_size = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RXFH_INDIR_SIZE, 1,
			[get_rxfh_indir_size is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops_ext has get_rxfh_indir_size])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops_ext en_ethtool_ops_ext = {
			.get_rxfh_indir_size = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RXFH_INDIR_SIZE_EXT, 1,
			[get_rxfh_indir_size is defined in ethtool_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_rxfh_indir])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>

		int mlx4_en_get_rxfh_indir(struct net_device *d, u32 *r)
		{
			return 0;
		}
	],[
		struct ethtool_ops en_ethtool_ops;
		en_ethtool_ops.get_rxfh_indir = mlx4_en_get_rxfh_indir;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_RXFH_INDIR, 1,
			[get/set_rxfh_indir is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool has set_phys_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.set_phys_id = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SET_PHYS_ID, 1,
			  [set_phys_id is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_tunable])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_tunable = NULL,
			.set_tunable = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_TUNABLE, 1,
			  [get/set_tunable is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if exist struct ethtool_ops_ext])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops_ext en_ethtool_ops_ext = {
			.size = sizeof(struct ethtool_ops_ext),
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_OPS_EXT, 1,
			  [struct ethtool_ops_ext is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if exist struct ethtool_flow_ext])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		struct ethtool_flow_ext en_ethtool_flow_ext;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_FLOW_EXT, 1,
			  [struct ethtool_flow_ext is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if exist union ethtool_flow_union])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		union ethtool_flow_union test_ethtool_flow_union;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_FLOW_UNION, 1,
			  [union ethtool_flow_union is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops_ext has get/set_rxfh_indir])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops_ext en_ethtool_ops_ext = {
			.get_rxfh_indir = NULL,
			.set_rxfh_indir = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_RXFH_INDIR_EXT, 1,
			  [get/set_rxfh_indir is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has __ethtool_get_link_ksettings])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		 __ethtool_get_link_ksettings(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE___ETHTOOL_GET_LINK_KSETTINGS, 1,
			  [__ethtool_get_link_ksettings is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has neigh_priv_len])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		dev->neigh_priv_len = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_DEVICE_NEIGH_PRIV_LEN, 1,
			  [neigh_priv_len is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has dev_port])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		dev->dev_port = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_DEVICE_DEV_PORT, 1,
			  [dev_port is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has min/max])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		dev->min_mtu = 0;
		dev->max_mtu = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_DEVICE_MIN_MAX_MTU, 1,
			  [net_device min/max is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct netdev_xdp exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct netdev_xdp xdp;
		xdp = xdp;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_XDP, 1,
			  [struct netdev_xdp is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct tc_cls_flower_offload exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		struct tc_cls_flower_offload x;
		x = x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_FLOWER_OFFLOAD, 1,
			  [struct tc_cls_flower_offload is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ptp_clock_info exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ptp_clock_kernel.h>
	],[
		struct ptp_clock_info info;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PTP_CLOCK_INFO, 1,
			  [ptp_clock_info is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ptp_clock_info has n_pins])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ptp_clock_kernel.h>
	],[
		struct ptp_clock_info *info;
		info->n_pins = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PTP_CLOCK_INFO_N_PINS, 1,
			  [n_pins is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ptp_clock_info has gettime])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ptp_clock_kernel.h>
	],[
		struct ptp_clock_info info = {
			.gettime = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PTP_CLOCK_INFO_GETTIME_32BIT, 1,
			  [gettime 32bit is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h pci_enable_msix_range])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		int x = pci_enable_msix_range(NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_ENABLE_MSIX_RANGE, 1,
			  [pci_enable_msix_range is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h pci_sriov_get_totalvfs])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		int x = pci_sriov_get_totalvfs(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_SRIOV_GET_TOTALVFS, 1,
			[pci_sriov_get_totalvfs is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm.h has page_is_pfmemalloc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		bool x = page_is_pfmemalloc(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_IS_PFMEMALLOC, 1,
			[page_is_pfmemalloc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has select_queue_fallback_t])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		select_queue_fallback_t fallback;

		fallback = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SELECT_QUEUE_FALLBACK_T, 1,
			  [select_queue_fallback_t is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h has skb_set_hash])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_set_hash(NULL, 0, PKT_HASH_TYPE_L3);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_SET_HASH, 1,
			  [skb_set_hash is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h has napi_alloc_skb])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		napi_alloc_skb(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NAPI_ALLOC_SKB, 1,
			  [napi_alloc_skb is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h has skb_transport_header_was_set])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_transport_header_was_set(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_TRANSPORT_HEADER_WAS_SET, 1,
			  [skb_transport_header_was_set is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h has build_skb])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		 build_skb(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BUILD_SKB, 1,
			  [build_skb is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h has dev_alloc_pages])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		dev_alloc_pages(0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEV_ALLOC_PAGES, 1,
			  [dev_alloc_pages is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h has skb_vlan_pop])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_vlan_pop(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_VLAN_POP, 1,
			  [skb_vlan_pop is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h has skb_pull_inline])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct sk_buff skb;
		skb_pull_inline(&skb, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_PULL_INLINE, 1,
			  [skb_pull_inline is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sockios.h has SIOCGHWTSTAMP])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sockios.h>
	],[
		int x = SIOCGHWTSTAMP;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SIOCGHWTSTAMP, 1,
			  [SIOCGHWTSTAMP is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ipv6_chk_addr accepts a const second parameter])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/addrconf.h>
	],[
		const struct sockaddr *addr;
		ipv6_chk_addr(NULL,
					  &((const struct sockaddr_in6 *)addr)->sin6_addr,
					  NULL,
					  0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IPV6_CHK_ADDR_TAKES_CONST, 1,
			  [ipv6_chk_addr accepts a const second parameter])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h skb_flow_dissect_flow_keys has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_flow_dissect_flow_keys(NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_FLOW_DISSECT_FLOW_KEYS_HAS_3_PARAMS, 1,
			  [skb_flow_dissect_flow_keys has 3 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ip.h inet_get_local_port_range has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/ip.h>
	],[
		inet_get_local_port_range(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_INET_GET_LOCAL_PORT_RANGE_3_PARAMS, 1,
			  [inet_get_local_port_range has 3 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h has enum pcie_link_width])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		enum pcie_link_width width = PCIE_LNK_WIDTH_UNKNOWN;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCIE_LINK_WIDTH, 1,
			  [pcie_link_width is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h has enum pci_bus_speed])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		enum pci_bus_speed speed = PCI_SPEED_UNKNOWN;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_BUS_SPEED, 1,
			  [pci_bus_speed is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ifla_vf_info has linkstate])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_link.h>
	],[
		struct ifla_vf_info *x;
		x->linkstate = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LINKSTATE, 1,
			  [linkstate is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h enum pci_dev_flags has PCI_DEV_FLAGS_ASSIGNED])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		enum pci_dev_flags x = PCI_DEV_FLAGS_ASSIGNED;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_DEV_FLAGS_ASSIGNED, 1,
			  [PCI_DEV_FLAGS_ASSIGNED is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if switchdev.h enum switchdev_attr_id has SWITCHDEV_ATTR_ID_PORT_PARENT_ID])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/switchdev.h>
	],[
		enum switchdev_attr_id x = SWITCHDEV_ATTR_ID_PORT_PARENT_ID;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SWITCHDEV_ATTR_ID_PORT_PARENT_ID, 1,
			  [SWITCHDEV_ATTR_ID_PORT_PARENT_ID is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if switchdev.h has struct switchdev_ops])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/switchdev.h>
	],[
		struct switchdev_ops x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SWITCHDEV_OPS, 1,
			  [HAVE_SWITCHDEV_OPS is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has napi_hash_add])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		napi_hash_add(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NAPI_HASH_ADD, 1,
			  [napi_hash_add is defined])
	],[
		AC_MSG_RESULT(no)
	])

        AC_MSG_CHECKING([if netdevice.h has netif_keep_dst])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/netdevice.h>
	        ],[
                netif_keep_dst(NULL);

                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_NETIF_KEEP_DST, 1,
                          [netif_keep_dst is defined])
        ],[
                AC_MSG_RESULT(no)
        ])

	AC_MSG_CHECKING([if netdevice.h has netdev_txq_bql_complete_prefetchw])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_txq_bql_complete_prefetchw(NULL);
		netdev_txq_bql_enqueue_prefetchw(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_TXQ_BQL_PREFETCHW, 1,
			  [netdev_txq_bql_complete_prefetchw is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct sk_buff has xmit_more])
	case $LINUXRELEASE in
	3\.1[[0-7]]*fbk*|2*fbk*)
	AC_MSG_RESULT(Not checking xmit_more support for fbk kernel: $LINUXRELEASE)
	;;
	*)
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct sk_buff *skb;
		skb->xmit_more = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_BUFF_XMIT_MORE, 1,
			  [xmit_more is defined])
	],[
		AC_MSG_RESULT(no)
	])
	;;
	esac

	AC_MSG_CHECKING([if struct sk_buff has encapsulation])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct sk_buff *skb;
		skb->encapsulation = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_BUFF_ENCAPSULATION, 1,
			  [encapsulation is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if etherdevice.h has eth_get_headlen])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/etherdevice.h>
	],[
		eth_get_headlen(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETH_GET_HEADLEN, 1,
			  [eth_get_headlen is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct sk_buff has csum_level])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct sk_buff *skb;
		skb->csum_level = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_BUFF_CSUM_LEVEL, 1,
			  [csum_level is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct skbuff.h has skb_inner_transport_header])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_inner_transport_header(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_INNER_TRANSPORT_HEADER, 1,
			  [skb_inner_transport_header is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct skbuff.h has napi_consume_skb])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		napi_consume_skb(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NAPI_CONSUME_SKB, 1,
			  [napi_consume_skb is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct skbuff.h has skb_inner_transport_offset])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_inner_transport_offset(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_INNER_TRANSPORT_OFFSET, 1,
			  [skb_inner_transport_offset is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct skbuff.h has skb_inner_network_header])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_inner_network_header(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_INNER_NETWORK_HEADER, 1,
			  [skb_inner_network_header is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if if_vlan.h has vlan_dev_get_egress_qos_mask])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_vlan.h>
	],[
		vlan_dev_get_egress_qos_mask(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VLAN_DEV_GET_EGRESS_QOS_MASK, 1,
			  [vlan_dev_get_egress_qos_mask is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_set_num_tc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_set_num_tc(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_SET_NUM_TC, 1,
			  [netdev_set_num_tc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_get_num_tc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_get_num_tc(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_GET_NUM_TC, 1,
			  [netdev_get_num_tc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ndo_select_queue has accel_priv])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		static u16 select_queue(struct net_device *dev, struct sk_buff *skb,
				        void *accel_priv)
		{
			return 0;
		}
	],[
		struct net_device_ops ndops = {
			.ndo_select_queue = select_queue,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(NDO_SELECT_QUEUE_HAS_ACCEL_PRIV, 1,
			  [ndo_select_queue has accel_priv])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if setapp returns int])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>

		static int mlx4_en_dcbnl_setapp(struct net_device *netdev, u8 idtype,
						u16 id, u8 up)
		{
			return 0;
		}

	],[
		struct dcbnl_rtnl_ops mlx4_en_dcbnl_ops = {
			.setapp		= mlx4_en_dcbnl_setapp,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(NDO_SETAPP_RETURNS_INT, 1,
			  [if setapp returns int])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if getapp returns int])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>

		static int mlx4_en_dcbnl_getapp(struct net_device *netdev, u8 idtype,
						u16 id)
		{
			return 0;
		}
	],[
		struct dcbnl_rtnl_ops mlx4_en_dcbnl_ops = {
			.getapp		= mlx4_en_dcbnl_getapp,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(NDO_GETAPP_RETURNS_INT, 1,
			  [if getapp returns int])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if getnumtcs returns int])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>

		static int mlx4_en_dcbnl_getnumtcs(struct net_device *netdev, int tcid, u8 *num)

		{
			return 0;
		}

	],[
		struct dcbnl_rtnl_ops mlx4_en_dcbnl_ops = {
			.getnumtcs	= mlx4_en_dcbnl_getnumtcs,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(NDO_GETNUMTCS_RETURNS_INT, 1,
			  [if getnumtcs returns int])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/net/bonding.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/bonding.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BONDING_H, 1,
			  [include/net/bonding.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/generated/utsrelease.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <generated/utsrelease.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UTSRELEASE_H, 1,
			  [include/generated/utsrelease.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/net/devlink.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_H, 1,
			  [include/net/devlink.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/net/tc_act/tc_vlan.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tc_act/tc_vlan.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_VLAN_H, 1,
			  [include/net/tc_act/tc_vlan.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/linux/interval_tree_generic.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/interval_tree_generic.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_INTERVAL_TREE_GENERIC_H, 1,
			[include/linux/interval_tree_generic.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if tc_vlan.h has is_tcf_vlan])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tc_act/tc_vlan.h>
	],[
		is_tcf_vlan(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IS_TCF_VLAN, 1,
			  [is_tcf_vlan is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if tc_vlan.h has tcf_vlan_action])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tc_act/tc_vlan.h>
	],[
		tcf_vlan_action(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TCF_VLAN_ACTION, 1,
			  [tcf_vlan_action is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if tc_vlan.h has tcf_vlan_push_vid])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tc_act/tc_vlan.h>
	],[
		tcf_vlan_push_vid(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TCF_VLAN_PUSH_VID, 1,
			  [tcf_vlan_push_vid is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if tc_vlan.h has tcf_vlan_push_proto])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tc_act/tc_vlan.h>
	],[
		tcf_vlan_push_proto(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TCF_VLAN_PUSH_PROTO, 1,
			  [tcf_vlan_push_proto is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow_dissector.h enum flow_dissector_key_keyid has FLOW_DISSECTOR_KEY_VLAN])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_dissector.h>
	],[
		enum flow_dissector_key_id keyid = FLOW_DISSECTOR_KEY_VLAN;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_DISSECTOR_KEY_VLAN, 1,
			  [FLOW_DISSECTOR_KEY_VLAN is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if etherdevice.h has ether_addr_copy])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/etherdevice.h>
	],[
		ether_addr_copy(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHER_ADDR_COPY, 1,
			  [ether_addr_copy is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if etherdevice.h has eth_random_addr])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/etherdevice.h>
	],[
		eth_random_addr(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETH_RANDOM_ADDR, 1,
			  [eth_random_addr is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_extended has hw_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		netdev_extended(dev)->hw_features = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_EXTENDED_HW_FEATURES, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_extended has wanted_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		netdev_extended(dev)->wanted_features = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_EXTENDED_WANTED_FEATURES, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_extended has _tx_ext])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		netdev_extended(dev)->_tx_ext = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_DEVICE_EXTENDED_TX_EXT, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_extended has dev_port])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		netdev_extended(dev)->dev_port = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_EXTENDED_DEV_PORT, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_busy_poll])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_busy_poll = NULL;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_BUSY_POLL, 1,
			  [ndo_busy_poll is defined])
	],[
		AC_MSG_RESULT(no)
	])


	AC_MSG_CHECKING([if net_device_extended has ndo_busy_poll])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int busy_poll(struct napi_struct *napi)
		{
			return 0;
		}
	],[
		struct net_device *dev = NULL;

		netdev_extended(dev)->ndo_busy_poll = busy_poll;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_EXTENDED_NDO_BUSY_POLL, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has set_netdev_hw_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		set_netdev_hw_features(dev, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SET_NETDEV_HW_FEATURES, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netif_set_xps_queue])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		netif_set_xps_queue(dev, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_SET_XPS_QUEUE, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_update_features exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;

		netdev_update_features(dev);

		return 0;
	],[
	AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_UPDATE_FEATURES, 1,
		  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has unregister_netdevice_queue])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		unregister_netdevice_queue(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UNREGISTER_NETDEVICE_QUEUE, 1,
			[unregister_netdevice_queue is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_set_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_set_features = NULL;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SET_FEATURES, 1,
			  [ndo_set_features is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_set_tx_maxrate])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops x = {
			.ndo_set_tx_maxrate = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SET_TX_MAXRATE, 1,
			  [ndo_set_tx_maxrate is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_setup_tc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops x = {
			.ndo_setup_tc = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SETUP_TC, 1,
			  [ndo_setup_tc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netif_tx_napi_add])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netif_tx_napi_add(NULL, NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_TX_NAPI_ADD, 1,
			  [netif_tx_napi_add is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ndo_setup_tc takes 4 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int mlx4_en_setup_tc(struct net_device *dev, u32 handle,
							 __be16 protocol, struct tc_to_netdev *tc)
		{
			return 0;
		}
	],[
		struct net_device_ops x = {
			.ndo_setup_tc = mlx4_en_setup_tc,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SETUP_TC_4_PARAMS, 1,
			  [ndo_setup_tc takes 4 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pkt_cls.h has tcf_exts_to_list])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		tcf_exts_to_list(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TCF_EXTS_TO_LIST, 1,
			  [tcf_exts_to_list is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if tc_mirred.h has is_tcf_mirred_redirect])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tc_act/tc_mirred.h>
	],[
		is_tcf_mirred_redirect(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IS_TCF_MIRRED_REDIRECT, 1,
			  [is_tcf_mirred_redirect is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_get_iflink])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops x = {
			.ndo_get_iflink = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_GET_IFLINK, 1,
			  [ndo_get_iflink is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_fix_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops x = {
			.ndo_fix_features = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_FIX_FEATURES, 1,
			  [ndo_fix_features is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_rx_flow_steer])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int rx_flow_steer(struct net_device *dev,
                                                     const struct sk_buff *skb,
                                                     u16 rxq_index,
                                                     u32 flow_id)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_rx_flow_steer = rx_flow_steer;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_RX_FLOW_STEER, 1,
			  [ndo_rx_flow_steer is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_get_stats64])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		struct rtnl_link_stats64* get_stats_64(struct net_device *dev,
                                                     struct rtnl_link_stats64 *storage)
		{
			struct rtnl_link_stats64 stats_64;
			return &stats_64;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_get_stats64 = get_stats_64;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_GET_STATS64, 1,
			  [ndo_get_stats64 is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_stats_to_stats64])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_stats_to_stats64(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_STATS_TO_STATS64, 1,
			[netdev_stats_to_stats64 is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops ndo_vlan_rx_add_vid has 3 parameters ])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int vlan_rx_add_vid(struct net_device *dev,__be16 proto, u16 vid)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_vlan_rx_add_vid = vlan_rx_add_vid;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_RX_ADD_VID_HAS_3_PARAMS, 1,
			  [ndo_vlan_rx_add_vid has 3 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops ndo_vlan_rx_add_vid has 2 parameters and returns int])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int vlan_rx_add_vid(struct net_device *dev, u16 vid)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops = {
			.ndo_vlan_rx_add_vid = vlan_rx_add_vid,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_RX_ADD_VID_HAS_2_PARAMS_RET_INT, 1,
			  [ndo_vlan_rx_add_vid has 2 parameters and returns int])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops has ndo_get_phys_port_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int get_phys_port_id(struct net_device *dev,
				     struct netdev_phys_port_id *ppid)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_get_phys_port_id = get_phys_port_id;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_NDO_GET_PHYS_PORT_ID, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops_ext exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops_ext netdev_ops_ext = {
			.size = sizeof(struct net_device_ops_ext),
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_DEVICE_OPS_EXT, 1,
			  [struct net_device_ops_ext is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops_ext has ndo_get_phys_port_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int get_phys_port_id(struct net_device *dev,
				     struct netdev_phys_port_id *ppid)
		{
			return 0;
		}
	],[
		struct net_device_ops_ext netdev_ops_ext;

		netdev_ops_ext.ndo_get_phys_port_id = get_phys_port_id;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_EXT_NDO_GET_PHYS_PORT_ID, 1,
			  [ndo_get_phys_port_id is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops has ndo_set_vf_spoofchk])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_spoofchk(struct net_device *dev, int vf, bool setting)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_set_vf_spoofchk = set_vf_spoofchk;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_NDO_SET_VF_SPOOFCHK, 1,
			  [ndo_set_vf_spoofchk is defined in net_device_ops])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops has ndo_set_vf_trust])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_trust(struct net_device *dev, int vf, bool setting)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_set_vf_trust = set_vf_trust;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_NDO_SET_VF_TRUST, 1,
			  [ndo_set_vf_trust is defined in net_device_ops])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops ndo_set_vf_vlan has 5 parameters ])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_vlan(struct net_device *dev, int vf, u16 vlan, u8 qos, __be16 vlan_proto){
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_set_vf_vlan = set_vf_vlan;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SET_VF_VLAN_HAS_5_PARAMS, 1,
			  [ndo_set_vf_vlan has 5 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops_ext has ndo_set_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops_ext netdev_ops_ext;

		netdev_ops_ext.ndo_set_features = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_EXT_NDO_SET_FEATURES, 1,
			  [ndo_set_features is defined in net_device_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops_ext has ndo_fix_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops_ext netdev_ops_ext;

		netdev_ops_ext.ndo_fix_features = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_EXT_NDO_FIX_FEATURES, 1,
			  [ndo_fix_features is defined in net_device_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops_ext has ndo_set_vf_spoofchk])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_spoofchk(struct net_device *dev, int vf, bool setting)
		{
			return 0;
		}
	],[
		struct net_device_ops_ext netdev_ops_ext;

		netdev_ops_ext.ndo_set_vf_spoofchk = set_vf_spoofchk;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_EXT_NDO_SET_VF_SPOOFCHK, 1,
			  [ndo_set_vf_spoofchk is defined in net_device_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops has ndo_set_vf_link_state])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_link_state(struct net_device *dev, int vf, int link_state)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_set_vf_link_state = set_vf_link_state;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_NDO_SET_VF_LINK_STATE, 1,
			  [ndo_set_vf_link_state is defined in net_device_ops])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_device_ops_ext has ndo_set_vf_link_state])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_link_state(struct net_device *dev, int vf, int link_state)
		{
			return 0;
		}
	],[
		struct net_device_ops_ext netdev_ops_ext;

		netdev_ops_ext.ndo_set_vf_link_state = set_vf_link_state;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_OPS_EXT_NDO_SET_VF_LINK_STATE, 1,
			  [ndo_set_vf_link_state is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netif_set_real_num_tx_queues])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device dev;
		netif_set_real_num_tx_queues(&dev, 2);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_SET_REAL_NUM_TX_QUEUES, 1,
			  [netif_set_real_num_tx_queues is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has enum netdev_lag_tx_type])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		enum netdev_lag_tx_type x;
		x = 0;

		return x;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LAG_TX_TYPE, 1,
			  [enum netdev_lag_tx_type is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct netdevice.h has struct xps_map])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct xps_map map;
		map.len = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPS_MAP, 1,
			  [struct xps_map is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool_ext has set_phys_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops_ext en_ethtool_ops_ext = {
			.set_phys_id = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SET_PHYS_ID_EXT, 1,
			  [set_phys_id is defined in ethtool_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_channels])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_channels = NULL,
			.set_channels = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_CHANNELS, 1,
			  [get/set_channels is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_msglevel])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_msglevel = NULL,
			.set_msglevel = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_MSGLEVEL, 1,
			  [get/set_msglevel is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_link_ksettings])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_link_ksettings = NULL,
			.set_link_ksettings = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_LINK_KSETTINGS, 1,
			  [get/set_link_ksettings is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_priv_flags])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_priv_flags = NULL,
			.set_priv_flags = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_PRIV_FLAGS, 1,
			  [get/set_priv_flags is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_flags])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_flags = NULL,
			.set_flags = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_FLAGS, 1,
			  [get/set_flags is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_tso])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_tso = NULL,
			.set_tso = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_TSO, 1,
			  [get/set_tso is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_sg])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_sg = NULL,
			.set_sg = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_SG, 1,
			  [get/set_sg is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_tx_csum])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_tx_csum = NULL,
			.set_tx_csum = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_TX_CSUM, 1,
			  [get/set_tx_csum is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_rx_csum])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_rx_csum = NULL,
			.set_rx_csum = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_RX_CSUM, 1,
			  [get/set_rx_csum is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops_ext has get/set_channels])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops_ext en_ethtool_ops_ext = {
			.get_channels = NULL,
			.set_channels = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_CHANNELS_EXT, 1,
			  [get/set_channels is defined in ethtool_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get_ts_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_ts_info = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_TS_INFO, 1,
			  [get_ts_info is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops_ext has get_ts_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops_ext en_ethtool_ops_ext = {
			.get_ts_info = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_TS_INFO_EXT, 1,
			  [get_ts_info is defined in ethtool_ops_ext])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_flow_ext has h_dest])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		unsigned char mac[ETH_ALEN];
		struct ethtool_flow_ext h_ext;

		memcpy(&mac, h_ext.h_dest, ETH_ALEN);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_FLOW_EXT_H_DEST, 1,
			  [ethtool_flow_ext has h_dest])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ETH_P_8021AD exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_vlan.h>
	],[
		__be16 vlan_proto = htons(ETH_P_8021AD);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETH_P_8021AD, 1,
			  [ETH_P_8021AD exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops get_rxnfc gets u32 *rule_locs])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
		static int mlx4_en_get_rxnfc(struct net_device *dev, struct ethtool_rxnfc *c,
					     u32 *rule_locs)
		{
			return 0;
		}
	],[
		struct ethtool_ops x = {
			.get_rxnfc = mlx4_en_get_rxnfc,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_OPS_GET_RXNFC_U32_RULE_LOCS, 1,
			  [ethtool_ops get_rxnfc gets u32 *rule_locs])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h has pci_vfs_assigned])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		struct pci_dev pdev;
		pci_vfs_assigned(&pdev);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_VFS_ASSIGNED, 1,
			  [pci_vfs_assigned is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h struct pci_driver has sriov_configure])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		struct pci_driver x = {
			.sriov_configure = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_DRIVER_SRIOV_CONFIGURE, 1,
			  [pci_driver sriov_configure is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if __vlan_hwaccel_put_tag has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_vlan.h>
	],[
		struct sk_buff *skb;
		__vlan_hwaccel_put_tag(skb, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_3_PARAMS_FOR_VLAN_HWACCEL_PUT_TAG, 1,
			  [__vlan_hwaccel_put_tag has 3 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has hw_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device dev;
		dev.hw_features = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_HW_FEATURES, 1,
			  [hw_features is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has wanted_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device dev;
		dev.wanted_features = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_WANTED_FEATURES, 1,
			  [wanted_features is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if if_vlan.h has vlan_features_check])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_vlan.h>
	],[
		vlan_features_check(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VLAN_FEATURES_CHECK, 1,
			  [vlan_features_check is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if vxlan.h has vxlan_features_check])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/vxlan.h>
	],[
		vxlan_features_check(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VXLAN_FEATURES_CHECK, 1,
			  [vxlan_features_check is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has hw_enc_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device dev;
		dev.hw_enc_features = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_HW_ENC_FEATURES, 1,
			  [hw_enc_features is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has rx_cpu_rmap])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device dev;
		dev.rx_cpu_rmap = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_RX_CPU_RMAP, 1,
			  [rx_cpu_rmap is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has IFF_UNICAST_FLT])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		int x = IFF_UNICAST_FLT;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_IFF_UNICAST_FLT, 1,
			  [IFF_UNICAST_FLT is defined])
	],[
		AC_MSG_RESULT(no)
	])


	AC_MSG_CHECKING([if netdevice.h has IFF_LIVE_ADDR_CHANGE])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		int x = IFF_LIVE_ADDR_CHANGE;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_IFF_LIVE_ADDR_CHANGE, 1,
			  [IFF_LIVE_ADDR_CHANGE is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has dev_uc_del])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		dev_uc_del(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEV_UC_DEL, 1,
			  [dev_uc_del is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has dev_mc_del])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		dev_mc_del(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEV_MC_DEL, 1,
			  [dev_mc_del is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_for_each_mc_addr])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct netdev_hw_addr *ha;
		struct net_device *netdev;
		netdev_for_each_mc_addr(ha, netdev);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_FOR_EACH_MC_ADDR, 1,
			  [netdev_for_each_mc_addr is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if irqdesc.h has irq_desc_get_irq_data])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/irq.h>
		#include <linux/irqdesc.h>
	],[
		struct irq_desc desc;
		struct irq_data *data = irq_desc_get_irq_data(&desc);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IRQ_DESC_GET_IRQ_DATA, 1,
			  [irq_desc_get_irq_data is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if irq.h irq_data has member affinity])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/irq.h>
		#include <linux/cpumask.h>
	],[
		cpumask_var_t x;
		struct irq_data y = {
			.affinity = x,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IRQ_DATA_AFFINITY, 1,
			  [irq_data member affinity is defined])
	],[
		AC_MSG_RESULT(no)
	])


	AC_MSG_CHECKING([if pci_dev has pcie_mpss])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		struct pci_dev *pdev;

		pdev->pcie_mpss = 0;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_DEV_PCIE_MPSS, 1,
			  [pcie_mpss is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if uapi/linux/if_ether.h exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <uapi/linux/if_ether.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UAPI_LINUX_IF_ETHER_H, 1,
			  [uapi/linux/if_ether.h exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ifla_vf_info has spoofchk])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_link.h>
	],[
		struct ifla_vf_info *ivf;

		ivf->spoofchk = 0;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VF_INFO_SPOOFCHK, 1,
			  [spoofchk is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ifla_vf_info has trust])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_link.h>
	],[
		struct ifla_vf_info *ivf;

		ivf->trusted = 0;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VF_INFO_TRUST, 1,
			  [trust is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if if_link.h has IFLA_VF_IB_NODE_PORT_GUID])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_link.h>
	],[
		int type = IFLA_VF_IB_NODE_GUID;

		type = IFLA_VF_IB_PORT_GUID;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IFLA_VF_IB_NODE_PORT_GUID, 1,
			  [trust is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if kthread.h has struct kthread_work])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/kthread.h>
	],[
		struct kthread_work x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KTHREAD_WORK, 1,
			  [struct kthread_work is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/timecounter.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/timecounter.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TIMECOUNTER_H, 1,
			  [linux/timecounter.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	# timecounter_adjtime can be in timecounter.h or clocksource.h
	AC_MSG_CHECKING([if linux/timecounter.h has timecounter_adjtime])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/timecounter.h>
	],[
		struct timecounter x;
		s64 y = 0;
		timecounter_adjtime(&x, y);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TIMECOUNTER_ADJTIME, 1,
			  [timecounter_adjtime is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/clocksource.h has timecounter_adjtime])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/clocksource.h>
	],[
		struct timecounter x;
		s64 y = 0;
		timecounter_adjtime(&x, y);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TIMECOUNTER_ADJTIME, 1,
			  [timecounter_adjtime is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has napi_schedule_irqoff])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		napi_schedule_irqoff(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NAPI_SCHEDULE_IRQOFF, 1,
			  [napi_schedule_irqoff is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h enum ethtool_stringset has ETH_SS_RSS_HASH_FUNCS])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		enum ethtool_stringset x = ETH_SS_RSS_HASH_FUNCS;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETH_SS_RSS_HASH_FUNCS, 1,
			  [ETH_SS_RSS_HASH_FUNCS is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pkt_cls.h enum enum tc_fl_command has TC_CLSFLOWER_STATS])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		enum tc_fl_command x = TC_CLSFLOWER_STATS;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_CLSFLOWER_STATS, 1,
			  [HAVE_TC_CLSFLOWER_STATS is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has napi_complete_done])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		napi_complete_done(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NAPI_COMPLETE_DONE, 1,
			  [napi_complete_done is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/inetdevice.h inet_confirm_addr has 5 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/inetdevice.h>
        ],[
               inet_confirm_addr(NULL, NULL, 0, 0, 0);

                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_INET_CONFIRM_ADDR_5_PARAMS, 1,
                          [inet_confirm_addr has 5 parameters])
        ],[
                AC_MSG_RESULT(no)
        ])

	AC_MSG_CHECKING([if netdevice.h has netdev_rss_key_fill])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_rss_key_fill(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_RSS_KEY_FILL, 1,
			  [netdev_rss_key_fill is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has struct netdev_phys_item_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct netdev_phys_item_id x;
		x.id_len = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_PHYS_ITEM_ID, 1,
			  [netdev_phys_item_id is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if cyclecounter_cyc2ns has 4 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/timecounter.h>
	],[
		cyclecounter_cyc2ns(NULL, 0, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CYCLECOUNTER_CYC2NS_4_PARAMS, 1,
			  [cyclecounter_cyc2ns has 4 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h struct net_device_ops has ndo_features_check])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		static const struct net_device_ops mlx4_netdev_ops = {
			.ndo_features_check	= NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_FEATURES_T, 1,
			  [netdev_features_t is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_features.h has NETIF_F_RXFCS])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdev_features.h>
	],[
		netdev_features_t rxfcs = NETIF_F_RXFCS;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_RXFCS, 1,
			[NETIF_F_RXFCS is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_features.h has NETIF_F_HW_VLAN_STAG_RX])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdev_features.h>
	],[
		netdev_features_t stag = NETIF_F_HW_VLAN_STAG_RX;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_HW_VLAN_STAG_RX, 1,
			[NETIF_F_HW_VLAN_STAG_RX is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_features.h has NETIF_F_RXALL])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdev_features.h>
	],[
		netdev_features_t rxfcs = NETIF_F_RXALL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_RXALL, 1,
			[NETIF_F_RXALL is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_features.h has NETIF_IS_BOND_MASTER])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev;
		return netif_is_bond_master(dev);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_IS_BOND_MASTER, 1,
			[NETIF_IS_BOND_MASTER is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if if_vlan.h has vlan_gro_receive])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_vlan.h>
	],[
		vlan_gro_receive(NULL, NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VLAN_GRO_RECEIVE, 1,
			[vlan_gro_receive is defined in if_vlan.h])
	],[
		AC_MSG_RESULT(no)
	])

       AC_MSG_CHECKING([if if_vlan.h has vlan_hwaccel_rx])
       MLNX_BG_LB_LINUX_TRY_COMPILE([
               #include <linux/if_vlan.h>
       ],[
               vlan_hwaccel_rx(NULL, NULL, 0);

               return 0;
       ],[
               AC_MSG_RESULT(yes)
               MLNX_AC_DEFINE(HAVE_VLAN_HWACCEL_RX, 1,
                       [vlan_hwaccel_rx is defined in if_vlan.h])
       ],[
               AC_MSG_RESULT(no)
       ])

	AC_MSG_CHECKING([if vxlan has vxlan_get_rx_port])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#if IS_ENABLED(CONFIG_VXLAN)
		#include <net/vxlan.h>
		#endif
	],[
		vxlan_get_rx_port(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VXLAN_ENABLED, 1,
			  [vxlan_get_rx_port is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h skb_shared_info has UNION tx_flags])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct skb_shared_info x;
		x.tx_flags.flags = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_SHARED_INFO_UNION_TX_FLAGS, 1,
			  [skb_shared_info has union tx_flags])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if vxlan have ndo_add_vxlan_port])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		#if IS_ENABLED(CONFIG_VXLAN)
		void add_vxlan_port(struct net_device *dev, sa_family_t sa_family, __be16 port)
		{
			return 0;
		}
		#endif
	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_add_vxlan_port = add_vxlan_port;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VXLAN_DYNAMIC_PORT, 1,
			[ndo_add_vxlan_port is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if udp_tunnel has udp_tunnel_get_rx_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#if IS_ENABLED(CONFIG_VXLAN)
		#include <uapi/linux/if.h>
		#include <net/udp_tunnel.h>
		#endif
	],[
		udp_tunnel_get_rx_info(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UDP_TUNNEL_GET_RX_INFO, 1,
			  [udp_tunnel_get_rx_info is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ndo_add_vxlan_port have udp_tunnel_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		#if IS_ENABLED(CONFIG_VXLAN)
		void add_vxlan_port(struct net_device *dev, struct udp_tunnel_info *ti)
		{
			return;
		}
		#endif

	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_udp_tunnel_add = add_vxlan_port;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ADD_VXLAN_PORT_UDP_TUNNEL, 1,
			[ndo_add_vxlan_port is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if vxlan.h has vxlan_gso_check])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/vxlan.h>
	],[
		vxlan_gso_check(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VXLAN_GSO_CHECK, 1,
			  [vxlan_gso_check is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dst.h has dst_get_neighbour])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/dst.h>
	],[
		struct neighbour *neigh = dst_get_neighbour(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DST_GET_NEIGHBOUR, 1,
			  [dst_get_neighbour is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dst.h has dst_neigh_lookup])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/dst.h>
	],[
		struct neighbour *neigh = dst_neigh_lookup(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DST_NEIGH_LOOKUP, 1,
			  [dst_neigh_lookup is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink.h netlink_dump_control has dump])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		struct netlink_dump_control c = {
			.dump = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_DUMP_CONTROL_DUMP, 1,
			  [netlink_dump_control dump is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink.h netlink_dump_control has module])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		struct netlink_dump_control c = {
			.module = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_DUMP_CONTROL_MODULE, 1,
			  [netlink_dump_control module is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink.h netlink_callback has module])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		struct netlink_callback c = {
			.module = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_CALLBACK_MODULE, 1,
			  [netlink_callback module is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink.h netlink_skb_parms has sk])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		struct netlink_skb_parms nsp = {
			.sk = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_SKB_PARMS_SK, 1,
			  [netlink_skb_params has sk])
	],[
		AC_MSG_RESULT(no)
	])

        AC_MSG_CHECKING([if netlink.h has netlink_capable])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <linux/netlink.h>
        ],[
                bool b = netlink_capable(NULL, 0);

                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_NETLINK_CAPABLE, 1,
                          [netlink_capable is defined])
        ],[
                AC_MSG_RESULT(no)
        ])

	AC_MSG_CHECKING([if netlink.h netlink_kernel_cfg has input])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		struct netlink_kernel_cfg cfg = {
			.input = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_KERNEL_CFG_INPUT, 1,
			  [netlink_kernel_cfg input is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink_kernel_create has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		netlink_kernel_create(NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_KERNEL_CREATE_3_PARAMS, 1,
			  [netlink_kernel_create has 3 params])
	],[
		AC_MSG_RESULT(no)
	])


	AC_MSG_CHECKING([if netlink_dump_start has 5 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		int ret = netlink_dump_start(NULL, NULL, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_DUMP_START_5P, 1,
			  [ is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct dcbnl_rtnl_ops has ieee_getmaxrate/ieee_setmaxrate])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>
	],[
		const struct dcbnl_rtnl_ops en_dcbnl_ops = {
			.ieee_getmaxrate = NULL,
			.ieee_setmaxrate = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IEEE_GET_SET_MAXRATE, 1,
			  [ieee_getmaxrate/ieee_setmaxrate is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dcbnl.h dcbnl_rtnl_ops getnumtcs returns int])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>
		static int func1(struct net_device * a, int b, u8 * c) {
			return 0;
		}

	],[
		struct dcbnl_rtnl_ops x = {
			.getnumtcs = func1,
		};
			return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DCBNL_RTNL_OPS_GETNUMTCS_RET_INT, 1,
 			       [getnumtcs returns int])
 	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has get_module_eeprom])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops x = {
			.get_module_eeprom = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_MODULE_EEPROM, 1,
			  [HAVE_GET_MODULE_EEPROM is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has set_dump])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops x = {
			.set_dump = NULL,
			.get_dump_data = NULL,
			.get_dump_flag = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_SET_DUMP, 1,
			[HAVE_GET_SET_DUMP is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has get_module_eeprom])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops_ext x = {
			.get_module_eeprom = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_MODULE_EEPROM_EXT, 1,
			[HAVE_GET_MODULE_EEPROM_EXT is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h skb_add_rx_frag has 5 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_add_rx_frag(NULL, 0, NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_ADD_RX_FRAG_5_PARAMS, 1,
			  [skb_add_rx_frag has 5 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if addrconf.h has addrconf_ifid_eui48])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/addrconf.h>
	],[
		int x = addrconf_ifid_eui48(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ADDRCONF_IFID_EUI48, 1,
			  [addrconf_ifid_eui48 is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has struct netdev_bonding_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct netdev_bonding_info x;
		x.master.num_slaves = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_BONDING_INFO, 1,
			  [netdev_bonding_info is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/net/dcbnl.h struct dcbnl_rtnl_ops has *ieee_getqcn])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>
	],[
		struct dcbnl_rtnl_ops x = {
			.ieee_getqcn = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IEEE_GETQCN, 1,
			  [ieee_getqcn is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dcbnl.h has struct ieee_qcn])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>
	],[
		struct ieee_qcn x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRUCT_IEEE_QCN, 1,
			  [ieee_qcn is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_master_upper_dev_get])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_master_upper_dev_get(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_MASTER_UPPER_DEV_GET, 1,
			  [netdev_master_upper_dev_get is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_master_upper_dev_get_rcu])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_master_upper_dev_get_rcu(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_MASTER_UPPER_DEV_GET_RCU, 1,
			  [netdev_master_upper_dev_get_rcu is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_for_each_all_upper_dev_rcu])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev;
		struct net_device *upper;
		struct list_head *list;

		netdev_for_each_all_upper_dev_rcu(dev, upper, list);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_FOR_EACH_ALL_UPPER_DEV_RCU, 1,
			  [netdev_master_upper_dev_get_rcu is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_walk_all_upper_dev_rcu])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		struct upper_list {
			struct list_head list;
			struct net_device *upper;
		};

		static int netdev_upper_walk(struct net_device *upper, void *data) {
			return 0;
		}
	],[
		struct net_device *ndev;
		struct list_head upper_list;

		netdev_walk_all_upper_dev_rcu(ndev, netdev_upper_walk, &upper_list);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_WALK_ALL_UPPER_DEV_RCU, 1,
			  [netdev_walk_all_upper_dev_rcu is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_has_upper_dev_all_rcu])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev;
		struct net_device *upper;

		netdev_has_upper_dev_all_rcu(dev, upper);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_HAS_UPPER_DEV_ALL_RCU, 1,
			  [netdev_has_upper_dev_all_rcu is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_notifier_changeupper_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct netdev_notifier_changeupper_info info;

		info.master = 1;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_NOTIFIER_CHANGEUPPER_INFO, 1,
			  [netdev_notifier_changeupper_info is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ip_fib.h fib_res_put exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bug.h>
		#include <linux/string.h>
		#include <net/ip_fib.h>
	],[
		fib_res_put(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FIB_RES_PUT, 1,
			[fib_res_put])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ip_fib.h fib_lookup has 4 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bug.h>
		#include <linux/string.h>
		#include <net/ip_fib.h>
	],[
		fib_lookup(NULL, NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FIB_LOOKUP_4_PARAMS, 1,
			[fib_lookup has 4 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct inet6_ifaddr has member if_list])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/if_inet6.h>
	],[
		struct inet6_ifaddr x;
		struct list_head xlist;
		x.if_list = xlist;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_INET6_IF_LIST, 1,
			  [if_list is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if workqueue.h has __cancel_delayed_work])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/workqueue.h>
	],[
		__cancel_delayed_work(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE___CANCEL_DELAYED_WORK, 1,
			  [__cancel_delayed_work is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if workqueue.h has WQ_UNBOUND])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/workqueue.h>
	],[
		struct workqueue_struct *my_wq = alloc_workqueue("my_wq", WQ_UNBOUND, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_WQ_UNBOUND, 1,
			  [WQ_UNBOUND is defined])
	],[
		AC_MSG_RESULT(no)
	])
	AC_MSG_CHECKING([if workqueue.h has WQ_NON_REENTRANT])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/workqueue.h>
	],[
		struct workqueue_struct *my_wq = alloc_workqueue("my_wq", WQ_NON_REENTRANT, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_WQ_NON_REENTRANT, 1,
			  [WQ_NON_REENTRANT is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if workqueue.h has alloc_workqueue])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/workqueue.h>
	],[
		struct workqueue_struct *my_wq = alloc_workqueue("my_wq", 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ALLOC_WORKQUEUE, 1,
			  [alloc_workqueue is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if workqueue.h has WQ_HIGHPRI])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/workqueue.h>
	],[
		struct workqueue_struct *my_wq = alloc_workqueue("my_wq", WQ_HIGHPRI, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_WQ_HIGHPRI, 1,
			  [WQ_HIGHPRI is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if workqueue.h has WQ_MEM_RECLAIM])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/workqueue.h>
	],[
		struct workqueue_struct *my_wq = alloc_workqueue("my_wq", WQ_MEM_RECLAIM, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_WQ_MEM_RECLAIM, 1,
			  [WQ_MEM_RECLAIM is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if workqueue.h has WQ_UNBOUND_MAX_ACTIVE])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/workqueue.h>
	],[
		struct workqueue_struct *my_wq = alloc_workqueue("my_wq", 0, WQ_UNBOUND_MAX_ACTIVE);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_WQ_UNBOUND_MAX_ACTIVE, 1,
			  [WQ_UNBOUND_MAX_ACTIVE is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct mm_struct has member pinned_vm])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm_types.h>
	],[
		struct mm_struct x;
		x.pinned_vm = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PINNED_VM, 1,
			  [pinned_vm is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if proc_fs.h has proc_set_user])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/proc_fs.h>
		#include <linux/uidgid.h>
	],[
		kuid_t a;
		kgid_t b;
		proc_set_user(NULL, a, b);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PROC_SET_USER, 1,
			  [proc_set_user is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if uapi/linux/if_bonding.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <uapi/linux/if_bonding.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UAPI_IF_BONDING_H, 1,
			  [uapi/linux/if_bonding.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sock.h has sk_clone_lock])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
	],[
		struct sock sk;
		sk_clone_lock(&sk, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_CLONE_LOCK, 1,
			  [sk_clone_lock is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sock.h sk_wait_data has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
	],[
		sk_wait_data(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_WAIT_DATA_3_PARAMS, 1,
			  [sk_wait_data has 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if proc_fs.h has PDE_DATA])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/proc_fs.h>
	],[
		PDE_DATA(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PDE_DATA, 1,
			  [PDE_DATA is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if route.h struct rtable has member rt_uses_gateway])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/route.h>
	],[
		struct rtable x = {
			.rt_uses_gateway = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RT_USES_GATEWAY, 1,
			  [rt_uses_gateway is defined])
	],[
		AC_MSG_RESULT(no)
	])

	LB_CHECK_SYMBOL_EXPORT([split_page],
		[mm/page_alloc.c],
		[AC_DEFINE(HAVE_SPLIT_PAGE_EXPORTED, 1,
			[split_page is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([ip6_dst_hoplimit],
                [net/ipv6/output_core.c],
                [AC_DEFINE(HAVE_IP6_DST_HOPLIMIT, 1,
                        [ip6_dst_hoplimit is exported by the kernel])],
        [])

	LB_CHECK_SYMBOL_EXPORT([udp4_hwcsum],
		[net/ipv4/udp.c],
		[AC_DEFINE(HAVE_UDP4_HWCSUM, 1,
			[udp4_hwcsum is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([inet_confirm_addr],
		[net/ipv4/devinet.c],
		[AC_DEFINE(HAVE_INET_CONFIRM_ADDR_EXPORTED, 1,
			[inet_confirm_addr is exported by the kernel])],
	[])

	AC_MSG_CHECKING([if route.h has ip4_dst_hoplimit])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/route.h>
	],[
		ip4_dst_hoplimit(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IP4_DST_HOPLIMIT, 1,
		[ip4_dst_hoplimit is defined])
	],[
		AC_MSG_RESULT(no)
	])

	LB_CHECK_SYMBOL_EXPORT([irq_to_desc],
		[kernel/irq/irqdesc.c],
		[AC_DEFINE(HAVE_IRQ_TO_DESC_EXPORTED, 1,
			[irq_to_desc is exported by the kernel])],
	[])

	AC_MSG_CHECKING([if ptp_clock_kernel.h ptp_clock_register has 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ptp_clock_kernel.h>
	],[
		ptp_clock_register(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PTP_CLOCK_REGISTER_2_PARAMS, 1,
			  [ptp_clock_register has 2 params is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sock.h has skwq_has_sleeper])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/net.h>
		#include <net/sock.h>
	],[
		struct socket_wq wq;
		skwq_has_sleeper(&wq);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKWQ_HAS_SLEEPER, 1,
			  [skwq_has_sleeper is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h pci_physfn])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		struct pci_dev x;
		pci_physfn(&x);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_PHYSFN, 1,
			  [pci_physfn is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/printk.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/printk.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LINUX_PRINTK_H, 1,
			  [linux/printk.h is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if printk.h has struct va_format])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/printk.h>
	],[
		struct va_format x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VA_FORMAT, 1,
			  [va_format is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct netdevice.h has NETIF_F_RXHASH])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		int x = NETIF_F_RXHASH;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_RXHASH, 1,
			  [NETIF_F_RXHASH is defined in netdevice.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct netdev_features.h has NETIF_F_RXHASH])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdev_features.h>
	],[
		int x = NETIF_F_RXHASH;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_RXHASH, 1,
			  [NETIF_F_RXHASH is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct netdev_features.h has NETIF_F_GSO_UDP_TUNNEL])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdev_features.h>
	],[
		int x = NETIF_F_GSO_UDP_TUNNEL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_GSO_UDP_TUNNEL, 1,
			  [NETIF_F_GSO_UDP_TUNNEL is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct netdev_features.h has NETIF_F_GSO_UDP_TUNNEL_CSUM])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdev_features.h>
	],[
		int x = NETIF_F_GSO_UDP_TUNNEL_CSUM;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_GSO_UDP_TUNNEL_CSUM, 1,
			  [NETIF_F_GSO_UDP_TUNNEL_CSUM is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct netdev_features.h has NETIF_F_GSO_PARTIAL])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdev_features.h>
	],[
		int x = NETIF_F_GSO_PARTIAL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_GSO_PARTIAL, 1,
			  [NETIF_F_GSO_PARTIAL is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if if_vlan.h has is_vlan_dev])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <linux/if_vlan.h>
	],[
		struct net_device dev;
		is_vlan_dev(&dev);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IS_VLAN_DEV, 1,
			  [is_vlan_dev is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_set_vf_mac])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_mac(struct net_device *dev, int queue, u8 *mac)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_set_vf_mac = set_vf_mac;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SET_VF_MAC, 1,
			  [ndo_set_vf_mac is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_get_vf_stats])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int get_vf_stats(struct net_device *dev, int vf, struct ifla_vf_stats *vf_stats)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_get_vf_stats = get_vf_stats;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_GET_VF_STATS, 1,
			  [ndo_get_vf_stats is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_set_vf_guid])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int set_vf_guid(struct net_device *dev, int vf, u64 guid, int guid_type)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_set_vf_guid = set_vf_guid;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SET_VF_GUID, 1,
			  [ndo_set_vf_guid is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if if_link.h struct has struct ifla_vf_stats])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_link.h>

	],[
		struct ifla_vf_stats x;
		x = x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IFLA_VF_STATS, 1,
			  [struct ifla_vf_stats is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h has pci_num_vf])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		struct pci_dev x;
		pci_num_vf(&x);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_NUM_VF, 1,
			  [pci_num_vf is defined])
	],[
		AC_MSG_RESULT(no)
	])

	LB_CHECK_SYMBOL_EXPORT([elfcorehdr_addr],
		[kernel/crash_dump.c],
		[AC_DEFINE(HAVE_ELFCOREHDR_ADDR_EXPORTED, 1,
			[elfcorehdr_addr is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([fib_lookup],
		[net/ipv4/fib_rules.c],
		[AC_DEFINE(HAVE_FIB_LOOKUP_EXPORTED, 1,
			[fib_lookup is exported by the kernel])],
	[])

	AC_MSG_CHECKING([if idr.h has idr_alloc_cyclic])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/idr.h>
	],[
		idr_alloc_cyclic(NULL, NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IDR_ALLOC_CYCLIC, 1,
			  [idr_alloc_cyclic is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if idr.h has idr_alloc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/idr.h>
	],[
		idr_alloc(NULL, NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IDR_ALLOC, 1,
			  [idr_alloc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if random.h has prandom_u32])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/random.h>
	],[
		prandom_u32();

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PRANDOM_U32, 1,
			  [prandom_u32 is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if timekeeping.h has ktime_get_real_ns])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ktime.h>
		#include <linux/timekeeping.h>
	],[
		ktime_get_real_ns();

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KTIME_GET_REAL_NS, 1,
			  [ktime_get_real_ns is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if timekeeping.h has ktime_get_boot_ns])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ktime.h>
		#include <linux/timekeeping.h>
	],[
		ktime_get_boot_ns();

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KTIME_GET_BOOT_NS, 1,
			  [ktime_get_boot_ns is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_transfer_length is defind])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_cmnd.h>
	],[
		scsi_transfer_length(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_TRANSFER_LENGTH, 1,
			  [scsi_transfer_length is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if string.h has strnicmp])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/string.h>
	],[
		char a[10] = "aaa";
		char b[10] = "bbb";
		strnicmp(a, b, sizeof(a));

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRNICMP, 1,
			  [strnicmp is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if string.h has kfree_const])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/string.h>
	],[
		const char *x;
		kfree_const(x);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KFREE_CONST, 1,
			  [kfree_const is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if alloc_etherdev_mq is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/etherdevice.h>
	],[
		alloc_etherdev_mq(0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ALLOC_ETHERDEV_MQ, 1,
			  [alloc_etherdev_mq is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netif_set_real_num_rx_queues is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		int rc = netif_set_real_num_rx_queues(NULL, 0);

		return rc;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_SET_REAL_NUM_RX_QUEUES, 1,
			  [netif_set_real_num_rx_queues is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct dcbnl_rtnl_ops has get/set ets and dcbnl defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/dcbnl.h>
	],[
		const struct dcbnl_rtnl_ops en_dcbnl_ops = {
			.ieee_getets = NULL,
			.ieee_setets = NULL,
		};

		struct net_device dev = {
			.dcbnl_ops = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IEEE_DCBNL_ETS, 1,
			  [ieee_getets/ieee_setets is defined and dcbnl defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if list.h hlist_for_each_entry has 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/list.h>

		struct mlx5_l2_addr_node {
			struct hlist_node hlist;
			u8                addr[10];
		};
	],[
		struct mlx5_l2_addr_node *hn;
		struct hlist_head *hash;
		hlist_for_each_entry(hn, hash, hlist);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_HLIST_FOR_EACH_ENTRY_3_PARAMS, 1,
			  [hlist_for_each_entry has 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if device.h class devnode gets umode_t])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/device.h>
		static char *cm_devnode(struct device *dev, umode_t *mode) {
			return NULL;
		}

	],[
		struct class cm_class = {
			.devnode = cm_devnode,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CLASS_DEVNODE_UMODE_T, 1,
			  [class devnode gets umode_t])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if device.h CLASS_ATTR_STRING])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/device.h>
		#include <linux/stat.h>
		#include <linux/stringify.h>
	],[
		CLASS_ATTR_STRING(abi_version, S_IRUGO,
			 __stringify(5));

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CLASS_ATTR_STRING, 1,
			  [CLASS_ATTR_STRING is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if file.h has fdget])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/file.h>
	],[
		fdget(0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FDGET, 1,
			  [fdget is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if file.h has get_unused_fd_flags])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/file.h>
		/* Don't use backported get_unused_fd_flags
		** it uses an unexported function
		*/
		#ifdef get_unused_fd_flags
		#undef get_unused_fd_flags
		#endif
	],[
		get_unused_fd_flags(0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_UNUSED_FD_FLAGS, 1,
			  [GET_UNUSED_FD_FLAGS is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow.h has flowi4, flowi6 - AF specific instances])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bug.h>
		#include <net/flow.h>
	],[
		struct flowi4 fl4;
		struct flowi6 fl6;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOWI_AF_SPECIFIC_INSTANCES, 1,
			  [flowi4, flowi6  is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pat.h has pat_enabled as a function])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <asm/pat.h>
	],[
		bool px = pat_enabled();

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAT_ENABLED_AS_FUNCTION, 1,
			  [pat.h has pat_enabled as a function])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if icmpv6.h icmpv6_send has 4 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/icmpv6.h>
	],[
		icmpv6_send(NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ICMPV6_SEND_4_PARAMS, 1,
			  [icmpv6_send has 4 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dst_ops.h update_pmtu has 4 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
		#include <net/dst_ops.h>

		static void mtu_up (struct dst_entry *dst, struct sock *sk,
				    struct sk_buff *skb, u32 mtu)
		{
			return;
		}
	],[
		struct dst_ops x = {
			.update_pmtu = mtu_up,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UPDATE_PMTU_4_PARAMS, 1,
			  [update_pmtu has 4 paramters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if rtnetlink.h rtnl_link_ops newlink has 4 paramters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/rtnetlink.h>

		static int ipoib_new_child_link(struct net *src_net, struct net_device *dev,
						struct nlattr *tb[], struct nlattr *data[])
		{
			return 0;
		}
	],[
		struct rtnl_link_ops x = {
			.newlink = ipoib_new_child_link,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RTNL_LINK_OPS_NEWLINK_4_PARAMS, 1,
			  [newlink has 4 paramters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if rtnetlink.h rtnl_link_ops dellink newlink has 2 paramters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/rtnetlink.h>

		static void ipoib_unregister_child_dev(struct net_device *dev, struct list_head *head)
		{
			return;
		}
	],[
		struct rtnl_link_ops x = {
			.dellink = ipoib_unregister_child_dev,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RTNL_LINK_OPS_DELLINK_2_PARAMS, 1,
			  [dellink has 2 paramters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ipv6.h has ipv6_addr_copy])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/ipv6.h>
	],[

		struct in6_addr x1;
		const struct in6_addr x2;
		ipv6_addr_copy(&x1, &x2);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IPV6_ADDR_COPY, 1,
			  [ipv6_addr_copy is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/flow_keys.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
		#include <net/flow_keys.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_FLOW_KEYS_H, 1,
			  [net/flow_keys.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netif_tx_queue_stopped])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netif_tx_queue_stopped(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_TX_QUEUE_STOPPED, 1,
			  [netif_tx_queue_stopped is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netif_trans_update])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netif_trans_update(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_TRANS_UPDATE, 1,
			  [netif_trans_update is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/linux/inet_lro.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/inet_lro.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_INET_LRO_H, 1,
			  [include/linux/inet_lro.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netif_xmit_stopped])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netif_xmit_stopped(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_XMIT_STOPPED, 1,
			  [netif_xmit_stopped is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_get_tx_queue])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_get_tx_queue(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_GET_TX_QUEUE, 1,
			  [netdev_get_tx_queue is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h alloc_netdev_mqs has 6 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		alloc_netdev_mqs(0, NULL, NET_NAME_UNKNOWN, NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ALLOC_NETDEV_MQS_6_PARAMS, 1,
			  [alloc_netdev_mqs has 6 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm.h get_user_pages has 8 params])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <linux/mm.h>
        ],[
                get_user_pages(NULL, NULL, 0, 0, 0, 0, NULL, NULL);

                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_GET_USER_PAGES_8_PARAMS, 1,
                          [get_user_pages has 8 params])
        ],[
                AC_MSG_RESULT(no)
        ])

	AC_MSG_CHECKING([if mm_types.h struct page has _count])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
		#include <linux/mm_types.h>
	],[
		struct page p;
		p._count.counter = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MM_PAGE__COUNT, 1,
			  [struct page has _count])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/ethtool.h has ETHTOOL_xLINKSETTINGS API])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		enum ethtool_link_mode_bit_indices x = ETHTOOL_LINK_MODE_TP_BIT;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_xLINKSETTINGS, 1,
			  [ETHTOOL_xLINKSETTINGS API is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if configfs.h default_groups is list_head])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/configfs.h>
	],[
		struct config_group x = {
			.group_entry = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CONFIGFS_DEFAULT_GROUPS_LIST, 1,
			  [default_groups is list_head])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/linux/irq_poll.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/irq_poll.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IRQ_POLL_H, 1,
			  [include/linux/irq_poll.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if slab.h has kmalloc_array])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/slab.h>
	],[
		kmalloc_array(0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KMALLOC_ARRAY, 1,
			  [kmalloc_array is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if kernel.h has reciprocal_scale])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/kernel.h>
	],[
		reciprocal_scale(0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RECIPROCAL_SCALE, 1,
			  [reciprocal_scale is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if io_mapping_map_wc has 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/io-mapping.h>
	],[
		io_mapping_map_wc(NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IO_MAPPING_MAP_WC_3_PARAMS, 1,
			  [io_mapping_map_wc has 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/dma-mapping.h has struct dma_attrs])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-mapping.h>
	],[
		struct dma_attrs *attrs;
		int ret;

		ret = dma_get_attr(DMA_ATTR_WRITE_BARRIER, attrs);

		return ret;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRUCT_DMA_ATTRS, 1,
			  [struct dma_attrs is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct blk_mq_ops has map_queue])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		struct blk_mq_ops ops = {
			.map_queue = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_OPS_MAP_QUEUE, 1,
			  [struct blk_mq_ops has map_queue])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct blk_mq_ops has map_queues])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		struct blk_mq_ops ops = {
			.map_queues = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_OPS_MAP_QUEUES, 1,
			  [struct blk_mq_ops has map_queues])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/linux/blk-mq-pci.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq-pci.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_PCI_H, 1,
			  [include/linux/blk-mq-pci.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dma-mapping.h has DMA_ATTR_NO_WARN])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-mapping.h>
	],[
		int x = DMA_ATTR_NO_WARN;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DMA_ATTR_NO_WARN, 1,
			  [DMA_ATTR_NO_WARN is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if lightnvm.h struct nvm_dev has member dev])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/lightnvm.h>
	],[
		struct device devx = {0};
		struct nvm_dev d = {
			.dev = devx,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LIGHTNVM_NVM_DEV, 1,
			  [nvm_dev dev is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if filter.h has struct xdp_buff])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/filter.h>
	],[
		struct xdp_buff d = {
			.data = NULL,
			.data_end = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_BUFF, 1,
			  [xdp is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi.h has SG_MAX_SEGMENTS])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi.h>
	],[
		int x = SG_MAX_SEGMENTS;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SG_MAX_SEGMENTS, 1,
			  [SG_MAX_SEGMENTS is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_device.h has SCSI_SCAN_INITIAL])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_device.h>
	],[
		int x = SCSI_SCAN_INITIAL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_SCAN_INITIAL, 1,
			  [SCSI_SCAN_INITIAL is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsi_transport.h struct iscsit_transport has member rdma_shutdown])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/iscsi/iscsi_transport.h>
	],[
		struct iscsit_transport it = {
			.rdma_shutdown = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSIT_TRANSPORT_RDMA_SHUTDOWN, 1,
			  [rdma_shutdown is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsi_transport.h struct iscsit_transport has member iscsit_get_rx_pdu])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/iscsi/iscsi_transport.h>

		static void isert_get_rx_pdu(struct iscsi_conn *conn)
		{
			return;
		}
	],[
		struct iscsit_transport it = {
			.iscsit_get_rx_pdu = isert_get_rx_pdu,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSIT_TRANSPORT_ISCSIT_GET_RX_PDU, 1,
			  [iscsit_get_rx_pdu is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsi_target_core.h struct iscsi_conn has member login_sockaddr])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/iscsi/iscsi_target_core.h>
	],[
		struct iscsi_conn c = {
			.login_sockaddr = {0},
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_CONN_LOGIN_SOCKADDR, 1,
			  [iscsi_conn has member login_sockaddr])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsi_target_core.h struct iscsi_conn has member local_sockaddr])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/iscsi/iscsi_target_core.h>
	],[
		struct iscsi_conn c = {
			.local_sockaddr = {0},
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_CONN_LOCAL_SOCKADDR, 1,
			  [iscsi_conn has members local_sockaddr])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk_queue_virt_boundary exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		blk_queue_virt_boundary(NULL, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_QUEUE_VIRT_BOUNDARY, 1,
				[blk_queue_virt_boundary exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if target_put_sess_cmd has 1 parameter])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/target_core_base.h>
		#include <target/target_core_fabric.h>
	],[
		target_put_sess_cmd(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TARGET_PUT_SESS_CMD_HAS_1_PARAM, 1,
			  [target_put_sess_cmd in target_core_fabric.h has 1 parameter])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_device.h has scsi_change_queue_depth])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_device.h>
	],[
		scsi_change_queue_depth(NULL, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_CHANGE_QUEUE_DEPTH, 1,
			[scsi_change_queue_depth exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_host.h struct scsi_host_template has member track_queue_depth])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_host.h>
	],[
		struct scsi_host_template sh = {
			.track_queue_depth = 0,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_HOST_TEMPLATE_TRACK_QUEUE_DEPTH, 1,
			[scsi_host_template has members track_queue_depth])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk-mq.h has blk_mq_unique_tag])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_mq_unique_tag(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_UNIQUE_TAG, 1,
				[blk_mq_unique_tag exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_host.h struct Scsi_Host has member nr_hw_queues])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_host.h>
	],[
		struct Scsi_Host sh = {
			.nr_hw_queues = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_HOST_NR_HW_QUEUES, 1,
				[Scsi_Host has members nr_hw_queues])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsi_target_core and iscsi_target_stat.h are under include/])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/iscsi/iscsi_target_core.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_TARGET_CORE_ISCSI_TARGET_STAT_H, 1,
			  [iscsi_target_core.h and iscsi_target_stat.h are under include/])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsi_target_core.h has iscsit_find_cmd_from_itt])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/iscsi/iscsi_target_core.h>
	],[
		iscsit_find_cmd_from_itt(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSIT_FIND_CMD_FROM_ITT, 1,
		[iscsit_find_cmd_from_itt is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_cmnd.h struct scsi_cmnd  has member prot_flags])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_cmnd.h>
	],[
		struct scsi_cmnd sc = {
			.prot_flags = 0,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_CMND_PROT_FLAGS, 1,
			[scsi_cmnd has members prot_flags])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_transport_iscsi.h struct iscsi_transport has member check_protection])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_transport_iscsi.h>
	],[
		struct iscsi_transport iscsi_iser_transport = {
			.check_protection = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_TRANSPORT_CHECK_PROTECTION, 1,
			  [check_protection is defined])
	],[
		AC_MSG_RESULT(no)
	])

    AC_MSG_CHECKING([if iscsi_transport.h struct iscsit_transport has member iscsit_get_sup_prot_ops])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/iscsi/iscsi_transport.h>

		enum target_prot_op get_sup_prot_ops(struct iscsi_conn *conn)
		{
			return 0;
		}

	],[
		struct iscsit_transport it = {
			.iscsit_get_sup_prot_ops = get_sup_prot_ops,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSIT_TRANSPORT_HAS_GET_SUP_PROT_OPS, 1,
			[iscsit_transport has member iscsit_get_sup_prot_ops])
	],[
		AC_MSG_RESULT(no)
	])

    AC_MSG_CHECKING([if target_core_base.h struct se_cmd has member prot_checks])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/target_core_base.h>

	],[
		struct se_cmd se = {
			.prot_checks = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SE_CMD_HAS_PROT_CHECKS, 1,
			[struct se_cmd has member prot_checks])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if target_core_fabric.h has target_reverse_dma_direction function])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/target_core_base.h>
		#include <target/target_core_fabric.h>
	],[
		target_reverse_dma_direction(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TARGET_FABRIC_HAS_TARGET_REVERSE_DMA_DIRECTION, 1,
			  [target_core_fabric.h has target_reverse_dma_direction function])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm_types.h struct mm_struct has free_area_cache ])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm_types.h>
	],[
		struct mm_struct x;
		x.free_area_cache = NULL;
		x.cached_hole_size = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MM_STRUCT_FREE_AREA_CACHE, 1,
			[mm_types.h struct mm_struct has free_area_cache])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if types.h has cycle_t])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/types.h>
	],[
		cycle_t x = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TYPE_CYCLE_T, 1,
			[type cycle_t is defined in linux/types.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/clocksource.h has cycle_t])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/clocksource.h>
	],[
		cycle_t x = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CLOCKSOURCE_CYCLE_T, 1,
			  [cycle_t is defined in linux/clocksource.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if highmem.h has kmap_atomic function with km_type])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/highmem.h>
	],[
		kmap_atomic(NULL, KM_USER0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KM_TYPE, 1,
			  [highmem.h has kmap_atomic function with km_type])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsi_proto.h has structure iscsi_cmd])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/iscsi_proto.h>
	],[
		struct iscsi_cmd hdr;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_CMD, 1,
			  [iscsi_proto.h has structure iscsi_cmd])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_device.h struct scsi_device has u64 lun])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_device.h>
	],[
		struct scsi_device sdev = {
			.lun = 0,
		};

		pr_err("lun %llu", sdev.lun);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_DEVICE_U64_LUN, 1,
			  [scsi_device.h struct scsi_device has u64 lun])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_namespace.h has register_net_sysctl])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/net_namespace.h>
	],[
		register_net_sysctl(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REGISTER_NET_SYSCTL, 1,
			  [register_net_sysctl is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_host.h struct scsi_host_template has member use_blk_tags])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_host.h>
	],[
		struct scsi_host_template sh = {
			.use_blk_tags = 0,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_HOST_TEMPLATE_USE_BLK_TAGS, 1,
			[scsi_host_template has members use_blk_tags])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_host.h struct scsi_host_template has member change_queue_type])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_host.h>
	],[
		struct scsi_host_template sh = {
			.change_queue_type = 0,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_HOST_TEMPLATE_CHANGE_QUEUE_TYPE, 1,
			[scsi_host_template has members change_queue_type])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_tcq.h has function scsi_change_queue_type])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_tcq.h>
	],[
		scsi_change_queue_type(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_TCQ_SCSI_CHANGE_QUEUE_TYPE, 1,
			[scsi_tcq.h has function scsi_change_queue_type])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_host.h struct scsi_host_template has member use_host_wide_tags])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_host.h>
	],[
		struct scsi_host_template sh = {
			.use_host_wide_tags = 0,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_HOST_TEMPLATE_USE_HOST_WIDE_TAGS, 1,
			[scsi_host_template has members use_host_wide_tags])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_host.h struct Scsi_Host has member use_blk_mq])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_host.h>
	],[
		struct Scsi_Host sh = {
			.use_blk_mq = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_HOST_USE_BLK_MQ, 1,
				[Scsi_Host has members use_blk_mq])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_tcq.h has function scsi_init_shared_tag_map])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_tcq.h>
	],[
		scsi_init_shared_tag_map(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_TCQ_SCSI_INIT_SHARED_TAG_MAP, 1,
			[scsi_tcq.h has function scsi_init_shared_tag_map])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if target_core_base.h se_cmd transport_complete_callback has three params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/target_core_base.h>

		sense_reason_t transport_complete_callback(struct se_cmd *se, bool b, int *i) {
			  return 0;
		}
	],[
		struct se_cmd se = {
			  .transport_complete_callback = transport_complete_callback,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SE_CMD_TRANSPORT_COMPLETE_CALLBACK_HAS_THREE_PARAM, 1,
			  [target_core_base.h se_cmd transport_complete_callback has three params])
	],[
		AC_MSG_RESULT(no)
	])
	AC_MSG_CHECKING([if target_core_base.h se_cmd supports compare_and_write])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/target_core_base.h>
	],[
		uint64_t flag = SCF_COMPARE_AND_WRITE;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TARGET_SUPPORT_COMPARE_AND_WRITE, 1,
			  [target_core_base.h se_cmd supports compare_and_write])
	],[
		AC_MSG_RESULT(no)
	])
])
#
# COMPAT_CONFIG_HEADERS
#
# add -include config.h
#
AC_DEFUN([COMPAT_CONFIG_HEADERS],[
#
#	Wait for remaining build tests running in background
#
	wait
#
#	Append confdefs.h files from CONFDEFS_H_DIR to the main confdefs.h file
#
	/bin/cat CONFDEFS_H_DIR/confdefs.h.* >> confdefs.h
	/bin/rm -rf CONFDEFS_H_DIR
#
#	Generate the config.h header file
#
	AC_CONFIG_HEADERS([config.h])
	EXTRA_KCFLAGS="-include $PWD/config.h $EXTRA_KCFLAGS"
	AC_SUBST(EXTRA_KCFLAGS)
])

AC_DEFUN([MLNX_PROG_LINUX],
[

LB_LINUX_PATH
LB_LINUX_SYMVERFILE
LB_LINUX_CONFIG([MODULES],[],[
    AC_MSG_ERROR([module support is required to build mlnx kernel modules.])
])
LB_LINUX_CONFIG([MODVERSIONS])
LB_LINUX_CONFIG([KALLSYMS],[],[
    AC_MSG_ERROR([compat_mlnx requires that CONFIG_KALLSYMS is enabled in your kernel.])
])

LINUX_CONFIG_COMPAT
COMPAT_CONFIG_HEADERS

])
