#ifndef _COMPAT_NET_DST_METADATA_H
#define _COMPAT_NET_DST_METADATA_H

#include "../../compat/config.h"

#include_next <net/dst_metadata.h>
#ifdef CONFIG_NET_SCHED_NEW
static inline struct metadata_dst *backport__ip_tun_set_dst(__be32 saddr,
							    __be32 daddr,
							    __u8 tos, __u8 ttl,
							    __be16 tp_dst,
							    __be16 flags,
							    __be64 tunnel_id,
							    int md_size)
{
	struct metadata_dst *tun_dst;

	tun_dst = tun_rx_dst(md_size);
	if (!tun_dst)
		return NULL;

	ip_tunnel_key_init(&tun_dst->u.tun_info.key,
			   saddr, daddr, tos, ttl,
			   0, 0, tp_dst, tunnel_id, flags);
	return tun_dst;
}

static inline struct metadata_dst *backport__ipv6_tun_set_dst(const struct in6_addr *saddr,
							      const struct in6_addr *daddr,
							      __u8 tos, __u8 ttl,
							      __be16 tp_dst,
							      __be32 label,
							      __be16 flags,
							      __be64 tunnel_id,
							      int md_size)
{
	struct metadata_dst *tun_dst;
	struct ip_tunnel_info *info;

	tun_dst = tun_rx_dst(md_size);
	if (!tun_dst)
		return NULL;

	info = &tun_dst->u.tun_info;
	info->mode = IP_TUNNEL_INFO_IPV6;
	info->key.tun_flags = flags;
	info->key.tun_id = tunnel_id;
	info->key.tp_src = 0;
	info->key.tp_dst = tp_dst;

	info->key.u.ipv6.src = *saddr;
	info->key.u.ipv6.dst = *daddr;

	info->key.tos = tos;
	info->key.ttl = ttl;
	info->key.label = label;

	return tun_dst;
}
#endif
#endif /* _COMPAT_NET_DST_METADATA_H */
