#ifndef __COMPAT_NET_DST_METADATA_H
#define __COMPAT_NET_DST_METADATA_H 1

#ifndef CONFIG_COMPAT_IP_TUNNELS
#include_next <net/dst_metadata.h>
#else

#include <linux/skbuff.h>
#include <net/ip_tunnels.h>
#include <net/dst.h>

enum metadata_type {
	METADATA_IP_TUNNEL,
	METADATA_HW_PORT_MUX,
};

struct hw_port_info {
	struct net_device *lower_dev;
	u32 port_id;
};

struct metadata_dst {
	struct dst_entry		dst;
	enum metadata_type		type;
	union {
		struct ip_tunnel_info	tun_info;
		struct hw_port_info	port_info;
	} u;
};

static inline struct metadata_dst *skb_metadata_dst(struct sk_buff *skb)
{
    return NULL;
}


static inline struct ip_tunnel_info *skb_tunnel_info(struct sk_buff *skb)
{
    return NULL;
}

#endif

#endif /* __COMPAT_NET_DST_METADATA_H */
