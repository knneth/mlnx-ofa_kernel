/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2018 Mellanox Technologies. */

#ifndef __MLX5_EN_TC_TUNNEL_H__
#define __MLX5_EN_TC_TUNNEL_H__

#include <linux/netdevice.h>
#include <linux/mlx5/fs.h>
#include <net/pkt_cls.h>
#include <linux/netlink.h>
#include "../en.h"
#include "../en_rep.h"

enum {
	MLX5E_TC_TUNNEL_TYPE_UNKNOWN,
	MLX5E_TC_TUNNEL_TYPE_VXLAN,
	MLX5E_TC_TUNNEL_TYPE_GENEVE,
	MLX5E_TC_TUNNEL_TYPE_GRETAP,
	MLX5E_TC_TUNNEL_TYPE_MPLSOUDP,
};

struct mlx5e_encap_key {
	const struct ip_tunnel_key *ip_tun_key;
	struct mlx5e_tc_tunnel     *tc_tunnel;
};

struct mlx5e_tc_tunnel {
	int tunnel_type;
	enum mlx5_flow_match_level match_level;

	bool (*can_offload)(struct mlx5e_priv *priv);
	int (*calc_hlen)(struct mlx5e_encap_entry *e);
	int (*init_encap_attr)(struct net_device *tunnel_dev,
			       struct mlx5e_priv *priv,
			       struct mlx5e_encap_entry *e,
			       struct netlink_ext_ack *extack);
	int (*generate_ip_tun_hdr)(char buf[],
				   __u8 *ip_proto,
				   struct mlx5e_encap_entry *e);
	int (*parse_udp_ports)(struct mlx5e_priv *priv,
			       struct mlx5_flow_spec *spec,
			       struct flow_cls_offload *f,
			       void *headers_c,
			       void *headers_v);
	int (*parse_tunnel)(struct mlx5e_priv *priv,
			    struct mlx5_flow_spec *spec,
			    struct flow_cls_offload *f,
			    void *headers_c,
			    void *headers_v);
	int (*cmp_encap_info)(struct mlx5e_encap_key *a,
			      struct mlx5e_encap_key *b);
};

/* Helper struct for accessing a struct containing list_head array.
 * Containing struct
 *   |- Helper array
 *      [0] Helper item 0
 *          |- list_head item 0
 *          |- index (0)
 *      [1] Helper item 1
 *          |- list_head item 1
 *          |- index (1)
 * To access the containing struct from one of the list_head items:
 * 1. Get the helper item from the list_head item using
 *    helper item =
 *        container_of(list_head item, helper struct type, list_head field)
 * 2. Get the contining struct from the helper item and its index in the array:
 *    containing struct =
 *        container_of(helper item, containing struct type, helper field[index])
 */
struct encap_flow_item {
	struct mlx5e_encap_entry *e; /* attached encap instance */
	struct list_head list;
	int index;
};

struct encap_route_flow_item {
	struct mlx5e_route_entry *r; /* attached route instance */
	int index;
};

extern struct mlx5e_tc_tunnel vxlan_tunnel;
extern struct mlx5e_tc_tunnel geneve_tunnel;
extern struct mlx5e_tc_tunnel gre_tunnel;
extern struct mlx5e_tc_tunnel mplsoudp_tunnel;

struct mlx5e_tc_tunnel *mlx5e_get_tc_tun(struct net_device *tunnel_dev);

int mlx5e_tc_tun_init_encap_attr(struct net_device *tunnel_dev,
				 struct mlx5e_priv *priv,
				 struct mlx5e_encap_entry *e,
				 struct netlink_ext_ack *extack);

void mlx5e_tc_set_attr_tx_tun(struct mlx5e_tc_flow *flow,
			      struct mlx5_flow_spec *spec);

int mlx5e_tc_tun_query_route_vport(struct net_device *out_dev, struct net_device *route_dev,
				   u16 *vport);

int mlx5e_tc_tun_create_header_ipv4(struct mlx5e_priv *priv,
				    struct net_device *mirred_dev,
				    struct mlx5e_encap_entry *e);
int mlx5e_tc_tun_update_header_ipv4(struct mlx5e_priv *priv,
				    struct net_device *mirred_dev,
				    struct mlx5e_encap_entry *e);

#if IS_ENABLED(CONFIG_INET) && IS_ENABLED(CONFIG_IPV6)
int mlx5e_tc_tun_create_header_ipv6(struct mlx5e_priv *priv,
				    struct net_device *mirred_dev,
				    struct mlx5e_encap_entry *e);
int mlx5e_tc_tun_update_header_ipv6(struct mlx5e_priv *priv,
				    struct net_device *mirred_dev,
				    struct mlx5e_encap_entry *e);
#else
static inline int
mlx5e_tc_tun_create_header_ipv6(struct mlx5e_priv *priv,
				struct net_device *mirred_dev,
				struct mlx5e_encap_entry *e) { return -EOPNOTSUPP; }
int mlx5e_tc_tun_update_header_ipv6(struct mlx5e_priv *priv,
				    struct net_device *mirred_dev,
				    struct mlx5e_encap_entry *e)
{ return -EOPNOTSUPP; }
#endif
int mlx5e_tc_tun_route_lookup(struct mlx5e_priv *priv,
			      struct mlx5_esw_flow_attr *attr,
			      struct mlx5_flow_spec *spec);

bool mlx5e_tc_tun_device_to_offload(struct mlx5e_priv *priv,
				    struct net_device *netdev);

int mlx5e_tc_tun_parse(struct net_device *filter_dev,
		       struct mlx5e_priv *priv,
		       struct mlx5_flow_spec *spec,
		       struct flow_cls_offload *f,
		       u8 *match_level);

int mlx5e_tc_tun_parse_udp_ports(struct mlx5e_priv *priv,
				 struct mlx5_flow_spec *spec,
				 struct flow_cls_offload *f,
				 void *headers_c,
				 void *headers_v);

int mlx5e_tc_tun_cmp_encap_info_generic(struct mlx5e_encap_key *a,
					struct mlx5e_encap_key *b);

void mlx5e_detach_encap(struct mlx5e_priv *priv,
			struct mlx5e_tc_flow *flow, int out_index);

int mlx5e_attach_encap(struct mlx5e_priv *priv,
		       struct mlx5e_tc_flow *flow,
		       struct net_device *mirred_dev,
		       int out_index,
		       struct netlink_ext_ack *extack,
		       struct net_device **encap_dev,
		       bool *encap_valid);
int mlx5e_attach_decap(struct mlx5e_priv *priv,
		       struct mlx5e_tc_flow *flow,
		       struct netlink_ext_ack *extack);
void mlx5e_detach_decap(struct mlx5e_priv *priv,
			struct mlx5e_tc_flow *flow);
int mlx5e_attach_decap_route(struct mlx5e_priv *priv,
			     struct mlx5e_tc_flow *flow);
void mlx5e_detach_decap_route(struct mlx5e_priv *priv,
			      struct mlx5e_tc_flow *flow);

struct ip_tunnel_info *mlx5e_dup_tun_info(const struct ip_tunnel_info *tun_info);

int mlx5e_tc_fib_event(struct notifier_block *nb, unsigned long event, void *ptr);

#endif //__MLX5_EN_TC_TUNNEL_H__
