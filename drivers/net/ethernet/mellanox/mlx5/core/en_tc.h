/*
 * Copyright (c) 2016, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __MLX5_EN_TC_H__
#define __MLX5_EN_TC_H__

#include <net/pkt_cls.h>
#include <net/ip_tunnels.h>
#include <net/vxlan.h>
#include "eswitch.h"

#define MLX5E_TC_FLOW_ID_MASK 0x0000ffff

#ifdef CONFIG_MLX5_ESWITCH

enum {
	MLX5E_TC_INGRESS = BIT(0),
	MLX5E_TC_EGRESS  = BIT(1),
	MLX5E_TC_NIC_OFFLOAD = BIT(2),
	MLX5E_TC_ESW_OFFLOAD = BIT(3),
	MLX5E_TC_LAST_EXPORTED_BIT = 3,
};

#define MLX5E_TC_FLOW_BASE (MLX5E_TC_LAST_EXPORTED_BIT + 1)

enum {
	MLX5E_TC_FLOW_INGRESS   = MLX5E_TC_INGRESS,
	MLX5E_TC_FLOW_EGRESS    = MLX5E_TC_EGRESS,
	MLX5E_TC_FLOW_ESWITCH   = MLX5E_TC_ESW_OFFLOAD,
	MLX5E_TC_FLOW_NIC       = MLX5E_TC_NIC_OFFLOAD,
	MLX5E_TC_FLOW_OFFLOADED = BIT(MLX5E_TC_FLOW_BASE),
	MLX5E_TC_FLOW_HAIRPIN   = BIT(MLX5E_TC_FLOW_BASE + 1),
	MLX5E_TC_FLOW_HAIRPIN_RSS = BIT(MLX5E_TC_FLOW_BASE + 2),
	MLX5E_TC_FLOW_SLOW        = BIT(MLX5E_TC_FLOW_BASE + 3),
	MLX5E_TC_FLOW_DUP         = BIT(MLX5E_TC_FLOW_BASE + 4),
	MLX5E_TC_FLOW_NOT_READY   = BIT(MLX5E_TC_FLOW_BASE + 5),
	MLX5E_TC_FLOW_INIT_DONE   = BIT(MLX5E_TC_FLOW_BASE + 6),
	MLX5E_TC_FLOW_SIMPLE      = BIT(MLX5E_TC_FLOW_BASE + 7),
	MLX5E_TC_FLOW_CT          = BIT(MLX5E_TC_FLOW_BASE + 8),
	MLX5E_TC_FLOW_CT_ORIG     = BIT(MLX5E_TC_FLOW_BASE + 9),
};

#define MLX5E_TC_MAX_SPLITS 1

struct mlx5_nic_flow_attr {
	u32 action;
	u32 flow_tag;
	u32 mod_hdr_id;
	u32 hairpin_tirn;
	u8 match_level;
	struct mlx5_flow_table	*hairpin_ft;
	struct mlx5_fc		*counter;
};

struct mlx5e_tc_flow {
	struct rhash_head	node;
	struct mlx5e_priv	*priv;
	u64			cookie;
	atomic_t		flags;
	struct mlx5_flow_handle *rule[MLX5E_TC_MAX_SPLITS + 1];
	struct mlx5e_tc_flow    *peer_flow;
	struct mlx5e_encap_entry *e; /* attached encap instance */
	struct list_head	encap;   /* flows sharing the same encap ID */
	unsigned long encap_init_jiffies;
	struct mlx5e_mod_hdr_entry *mh; /* attached mod header instance */
	struct list_head	mod_hdr; /* flows sharing the same mod hdr ID */
	struct mlx5e_hairpin_entry *hpe; /* attached hairpin instance */
	struct list_head	hairpin; /* flows sharing the same hairpin */
	struct list_head        peer; /* flows with peer flow */
	struct list_head        unready; /* flows not ready to be offloaded (e.g due to missing route) */
	refcount_t		refcnt;
	struct list_head        tmp_list;
	struct rcu_head		rcu_head;

	u64			version;
	struct mlx5e_miniflow   *miniflow;
	struct mlx5_fc          *dummy_counter;
	struct list_head        miniflow_list;
	struct rcu_head		rcu;
	struct list_head        nft_node;

	union {
		struct mlx5_esw_flow_attr esw_attr[0];
		struct mlx5_nic_flow_attr nic_attr[0];
	};
	/* Don't add any fields here */
};

struct mlx5e_tc_flow_parse_attr {
	struct ip_tunnel_info tun_info;
	struct mlx5_flow_spec spec;
	int num_mod_hdr_actions;
	int max_mod_hdr_actions;
	void *mod_hdr_actions;
	int mirred_ifindex;
};

#define MLX5_MH_ACT_SZ MLX5_UN_SZ_BYTES(set_action_in_add_action_in_auto)

int mlx5e_tc_nic_init(struct mlx5e_priv *priv);
void mlx5e_tc_nic_cleanup(struct mlx5e_priv *priv);

int mlx5e_tc_esw_init(struct mlx5e_priv *priv);
void mlx5e_tc_esw_cleanup(struct mlx5e_priv *priv);

int mlx5e_configure_flower(struct mlx5e_priv *priv,
			   struct tc_cls_flower_offload *f, int flags);
int mlx5e_delete_flower(struct mlx5e_priv *priv,
			struct tc_cls_flower_offload *f, int flags);

int mlx5e_stats_flower(struct mlx5e_priv *priv,
		       struct tc_cls_flower_offload *f, int flags);

struct mlx5e_encap_entry;
void mlx5e_tc_encap_flows_add(struct mlx5e_priv *priv,
			      struct mlx5e_encap_entry *e,
			      unsigned long n_updated);
void mlx5e_tc_encap_flows_del(struct mlx5e_priv *priv,
			      struct mlx5e_encap_entry *e,
			      unsigned long n_updated);
bool mlx5e_encap_take(struct mlx5e_encap_entry *e);
void mlx5e_encap_put(struct mlx5e_priv *priv, struct mlx5e_encap_entry *e);

struct mlx5e_neigh_hash_entry;
void mlx5e_tc_update_neigh_used_value(struct mlx5e_neigh_hash_entry *nhe);

int mlx5e_tc_num_filters(struct mlx5e_priv *priv, int flags);
void mlx5e_tc_reoffload_flows_work(struct mlx5_core_dev *mdev);

void *mlx5e_lookup_tc_ht(struct mlx5e_priv *priv,
			 unsigned long *cookie,
			 int flags);
void mlx5e_flow_put(struct mlx5e_priv *priv,
		    struct mlx5e_tc_flow *flow);
int mlx5e_tc_add_fdb_flow(struct mlx5e_priv *priv,
			  struct mlx5e_tc_flow_parse_attr *parse_attr,
			  struct mlx5e_tc_flow *flow,
			  struct netlink_ext_ack *extack);
int mlx5e_alloc_flow(struct mlx5e_priv *priv, int attr_size,
		     struct tc_cls_flower_offload *f,
		     u32 flow_flags, gfp_t flags,
		     struct mlx5e_tc_flow_parse_attr **__parse_attr,
		     struct mlx5e_tc_flow **__flow);
int alloc_mod_hdr_actions(struct mlx5e_priv *priv,
			  int nkeys, int namespace,
			  struct mlx5e_tc_flow_parse_attr *parse_attr,
			  gfp_t flags);
int mlx5e_tc_update_and_init_done_fdb_flow(struct mlx5e_priv *priv,
					   struct mlx5e_tc_flow *flow);

#else /* CONFIG_MLX5_ESWITCH */
static inline int  mlx5e_tc_nic_init(struct mlx5e_priv *priv) { return 0; }
static inline void mlx5e_tc_nic_cleanup(struct mlx5e_priv *priv) {}
static inline int  mlx5e_tc_num_filters(struct mlx5e_priv *priv, int flags) { return 0; }
#endif

#endif /* __MLX5_EN_TC_H__ */
