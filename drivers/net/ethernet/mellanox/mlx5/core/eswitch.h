/*
 * Copyright (c) 2015, Mellanox Technologies, Ltd.  All rights reserved.
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

#ifndef __MLX5_ESWITCH_H__
#define __MLX5_ESWITCH_H__

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_vlan.h>
#include <linux/bitmap.h>
#include <net/devlink.h>
#include <linux/mlx5/device.h>
#include <linux/mlx5/eswitch.h>
#include <linux/mlx5/fs.h>
#include "lib/mpfs.h"
#include "mlx5_core.h"

#ifdef CONFIG_MLX5_ESWITCH

#define MLX5_MAX_UC_PER_VPORT(dev) \
	(1 << MLX5_CAP_GEN(dev, log_max_current_uc_list))

#define MLX5_MAX_MC_PER_VPORT(dev) \
	(1 << MLX5_CAP_GEN(dev, log_max_current_mc_list))

#define MLX5_MAX_VLAN_PER_VPORT(dev) \
	(1 << MLX5_CAP_GEN(dev, log_max_vlan_list))

#define FDB_UPLINK_VPORT 0xffff

#define MLX5_MIN_BW_SHARE 1

#define MLX5_RATE_TO_BW_SHARE(rate, divider, limit) \
	min_t(u32, max_t(u32, (rate) / (divider), MLX5_MIN_BW_SHARE), limit)

struct vport_ingress {
	struct mlx5_flow_table *acl;
	struct mlx5_flow_group *allow_untagged_spoofchk_grp;
	struct mlx5_flow_group *allow_tagged_spoofchk_grp;
	struct mlx5_flow_group *drop_grp;
	struct list_head	allow_untagged_rules;
	struct list_head	allow_vlans_rules;
	struct mlx5_flow_handle	*drop_rule;
	struct mlx5_fc		*drop_counter;
};

struct vport_egress {
	struct mlx5_flow_table *acl;
	struct mlx5_flow_group *allow_untagged_grp;
	struct mlx5_flow_group *allowed_vlans_grp;
	struct mlx5_flow_group *drop_grp;
	struct mlx5_flow_handle  *allow_vst_vlan;
	struct mlx5_flow_handle  *drop_rule;
	struct mlx5_fc           *drop_counter;
	struct mlx5_flow_handle  *allow_untagged_rule;
	struct list_head        allow_vlans_rules;
};

struct mlx5_vport_drop_stats {
	u64 rx_dropped;
	u64 tx_dropped;
};

#define MAX_NUM_VMAC	4
struct mlx5_vmac {
	u8			mac[ETH_ALEN];
	struct mlx5_flow_handle	*fdb_rule;
	struct list_head	list;
};

struct mlx5_vport_info {
	u8                      mac[ETH_ALEN];
	u16                     vlan;
	u8                      qos;
	__be16			vlan_proto;
	u64                     node_guid;
	int                     link_state;
	u32                     min_rate;
	u32                     max_rate;
	bool                    spoofchk;
	bool                    trusted;
	bool                    roce;
	/* the admin approved vlan list */
	DECLARE_BITMAP(vlan_trunk_8021q_bitmap, VLAN_N_VID);
	struct list_head	vmac_list;
};

struct mlx5_vport {
	struct mlx5_core_dev    *dev;
	int                     vport;
	struct hlist_head       uc_list[MLX5_L2_ADDR_HASH_SIZE];
	struct hlist_head       mc_list[MLX5_L2_ADDR_HASH_SIZE];
	/* The requested vlan list from the vport side */
	DECLARE_BITMAP(req_vlan_bitmap, VLAN_N_VID);
	/* Actual accepted vlans on the acl tables */
	DECLARE_BITMAP(acl_vlan_8021q_bitmap, VLAN_N_VID);
	struct mlx5_flow_handle *promisc_rule;
	struct mlx5_flow_handle *allmulti_rule;
	struct work_struct      vport_change_handler;

	struct vport_ingress    ingress;
	struct vport_egress     egress;

	struct mlx5_vport_info  info;

	struct {
		bool            enabled;
		u32             esw_tsar_ix;
		u32             bw_share;
	} qos;

	bool                    enabled;
	u16                     enabled_events;
};

struct mlx5_eswitch_fdb {
	void *fdb;
	union {
		struct legacy_fdb {
			struct mlx5_flow_group *addr_grp;
			struct mlx5_flow_group *allmulti_grp;
			struct mlx5_flow_group *promisc_grp;
		} legacy;

		struct offloads_fdb {
			struct mlx5_flow_table *fdb;
			struct mlx5_flow_group *send_to_vport_grp;
			struct mlx5_flow_group *send_from_vport_grp;
			struct mlx5_flow_group *miss_grp;
			struct mlx5_flow_handle *miss_rule_multi;
			struct mlx5_flow_handle *miss_rule_uni;
			int vlan_push_pop_refcount;
		} offloads;
	};
};

struct mlx5_acl_entry {
	struct mlx5_flow_handle	*acl_rule;
	struct list_head	list;
};

struct mlx5_esw_sq {
	struct mlx5_flow_handle	*send_to_vport_rule;
	struct list_head	 list;
};

/* TODO: Should be moved to en_rep.h */
struct mlx5e_rep_context {
	struct net_device      *netdev;
	struct mlx5_flow_handle *vport_rx_rule;
	struct list_head       vport_sqs_list;
	u16		       vlan;
	u32		       vlan_refcount;
	struct mlx5_flow_handle	*refwd;
};

static inline
struct mlx5e_rep_context *mlx5e_rep_to_context(struct mlx5_eswitch_rep *rep)
{
	return (struct mlx5e_rep_context *)rep->rep_if[REP_ETH].ptr;
}

struct mlx5_esw_offload {
	struct mlx5_flow_table *ft_offloads;
	struct mlx5_flow_group *vport_rx_group;
	struct mlx5_eswitch_rep *vport_reps;
	DECLARE_HASHTABLE(encap_tbl, 8);
	DECLARE_HASHTABLE(mod_hdr_tbl, 8);
	u8 inline_mode;
	u64 num_flows;
	u8 encap;
};

/* E-Switch MC FDB table hash node */
struct esw_mc_addr { /* SRIOV only */
	struct l2addr_node     node;
	struct mlx5_flow_handle *uplink_rule; /* Forward to uplink rule */
	u32                    refcnt;
};

struct mlx5_eswitch {
	struct mlx5_core_dev    *dev;
	struct mlx5_eswitch_fdb fdb_table;
	struct hlist_head       mc_table[MLX5_L2_ADDR_HASH_SIZE];
	struct workqueue_struct *work_queue;
	struct mlx5_vport       *vports;
	int                     total_vports;
	int                     enabled_vports;
	/* Synchronize between vport change events
	 * and async SRIOV admin state changes
	 */
	struct mutex            state_lock;
	struct esw_mc_addr	mc_promisc;

	struct {
		bool            enabled;
		u32             root_tsar_id;
	} qos;

	struct mlx5_esw_offload offloads;
	int                     mode;

	/* number of VFs connected to eswitch
	 * (including VF0 aka PF)
	 */
	int			num_vfs;
};

void esw_offloads_cleanup(struct mlx5_eswitch *esw, int nvports);
int esw_offloads_init(struct mlx5_eswitch *esw, int nvports);
void esw_offloads_cleanup_reps(struct mlx5_eswitch *esw);
int esw_offloads_init_reps(struct mlx5_eswitch *esw);

/* E-Switch API */
int mlx5_eswitch_init(struct mlx5_core_dev *dev);
void mlx5_eswitch_cleanup(struct mlx5_eswitch *esw);
void mlx5_eswitch_vport_event(struct mlx5_eswitch *esw, struct mlx5_eqe *eqe);
int mlx5_eswitch_enable_sriov(struct mlx5_eswitch *esw, int nvfs, int mode);
void mlx5_eswitch_disable_sriov(struct mlx5_eswitch *esw);
int mlx5_eswitch_set_vport_mac(struct mlx5_eswitch *esw,
			       int vport, u8 mac[ETH_ALEN]);
int mlx5_eswitch_set_vport_state(struct mlx5_eswitch *esw,
				 int vport, int link_state);
int mlx5_eswitch_set_vport_vlan(struct mlx5_eswitch *esw,
				int vport, u16 vlan, u8 qos, __be16 vlan_proto);
int mlx5_eswitch_set_vport_spoofchk(struct mlx5_eswitch *esw,
				    int vport, bool spoofchk);
int mlx5_eswitch_set_vport_trust(struct mlx5_eswitch *esw,
				 int vport_num, bool setting);
int mlx5_eswitch_set_vport_rate(struct mlx5_eswitch *esw, int vport,
				u32 max_rate, u32 min_rate);
int mlx5_eswitch_get_vport_config(struct mlx5_eswitch *esw,
				  int vport, struct ifla_vf_info *ivi);
int mlx5_eswitch_get_vport_stats(struct mlx5_eswitch *esw,
				 u16 vport,
				 struct ifla_vf_stats *vf_stats);
int mlx5_eswitch_query_vport_drop_stats(struct mlx5_core_dev *dev,
					int vport_idx,
					struct mlx5_vport_drop_stats *stats);
int mlx5_eswitch_add_vport_trunk_range(struct mlx5_eswitch *esw,
				       int vport, u16 start_vlan, u16 end_vlan);
int mlx5_eswitch_del_vport_trunk_range(struct mlx5_eswitch *esw,
				       int vport, u16 start_vlan, u16 end_vlan);
int mlx5_eswitch_add_vport_vmac(struct mlx5_eswitch *esw,
				int vport, u8 mac[ETH_ALEN]);
int mlx5_eswitch_del_vport_vmac(struct mlx5_eswitch *esw,
				int vport, u8 mac[ETH_ALEN]);


struct mlx5_flow_spec;
struct mlx5_esw_flow_attr;

struct mlx5_flow_handle *
mlx5_eswitch_add_offloaded_rule(struct mlx5_eswitch *esw,
				struct mlx5_flow_spec *spec,
				struct mlx5_esw_flow_attr *attr);
void
mlx5_eswitch_del_offloaded_rule(struct mlx5_eswitch *esw,
				struct mlx5_flow_handle *rule,
				struct mlx5_esw_flow_attr *attr);

struct mlx5_flow_handle *
mlx5_eswitch_create_vport_rx_rule(struct mlx5_eswitch *esw, int vport,
				  struct mlx5_flow_destination *dest);

enum {
	SET_VLAN_STRIP	= BIT(0),
	SET_VLAN_INSERT	= BIT(1)
};

struct mlx5_esw_flow_attr {
	struct mlx5_eswitch_rep *in_rep;
	struct mlx5_eswitch_rep *out_rep;

	int	action;
	__be16	vlan_proto;
	u16	vlan_vid;
	u8	vlan_prio;
	bool	vlan_handled;
	u32	encap_id;
	u32	mod_hdr_id;
	struct mlx5e_tc_flow_parse_attr *parse_attr;
};

int mlx5_eswitch_sqs2vport_start(struct mlx5_eswitch *esw,
				 struct mlx5_eswitch_rep *rep,
				 u16 *sqns_array, int sqns_num);
void mlx5_eswitch_sqs2vport_stop(struct mlx5_eswitch *esw,
				 struct mlx5_eswitch_rep *rep);

int mlx5_devlink_eswitch_mode_set(struct devlink *devlink, u16 mode);
int mlx5_devlink_eswitch_mode_get(struct devlink *devlink, u16 *mode);
int mlx5_devlink_eswitch_inline_mode_set(struct devlink *devlink, u8 mode);
int mlx5_devlink_eswitch_inline_mode_get(struct devlink *devlink, u8 *mode);
int mlx5_eswitch_inline_mode_get(struct mlx5_eswitch *esw, int nvfs, u8 *mode);

int mlx5_eswitch_vport_modify_other_hca_cap_roce(struct mlx5_eswitch *esw,
						 int vport_num, bool value);
int mlx5_eswitch_vport_get_other_hca_cap_roce(struct mlx5_eswitch *esw,
					      int vport_num, bool *value);

int mlx5_devlink_eswitch_encap_mode_set(struct devlink *devlink, u8 encap);
int mlx5_devlink_eswitch_encap_mode_get(struct devlink *devlink, u8 *encap);
struct net_device *mlx5_eswitch_get_uplink_netdev(struct mlx5_eswitch *esw);

int mlx5_eswitch_add_vlan_action(struct mlx5_eswitch *esw,
				 struct mlx5_esw_flow_attr *attr);
int mlx5_eswitch_del_vlan_action(struct mlx5_eswitch *esw,
				 struct mlx5_esw_flow_attr *attr);
int __mlx5_eswitch_set_vport_vlan(struct mlx5_eswitch *esw, int vport,
				  u16 vlan, u8 qos, __be16 proto, u8 set_flags);

static inline bool mlx5_eswitch_vlan_actions_supported(struct mlx5_core_dev *dev)
{
	return MLX5_CAP_ESW_FLOWTABLE_FDB(dev, pop_vlan) &&
	       MLX5_CAP_ESW_FLOWTABLE_FDB(dev, push_vlan);
}

#define MLX5_DEBUG_ESWITCH_MASK BIT(3)

#define esw_info(dev, format, ...)				\
	pr_info("(%s): E-Switch: " format, (dev)->priv.name, ##__VA_ARGS__)

#define esw_warn(dev, format, ...)				\
	pr_warn("(%s): E-Switch: " format, (dev)->priv.name, ##__VA_ARGS__)

#define esw_debug(dev, format, ...)				\
	mlx5_core_dbg_mask(dev, MLX5_DEBUG_ESWITCH_MASK, format, ##__VA_ARGS__)
#else  /* CONFIG_MLX5_ESWITCH */
/* eswitch API stubs */
static inline int  mlx5_eswitch_init(struct mlx5_core_dev *dev) { return 0; }
static inline void mlx5_eswitch_cleanup(struct mlx5_eswitch *esw) {}
static inline void mlx5_eswitch_vport_event(struct mlx5_eswitch *esw, struct mlx5_eqe *eqe) {}
static inline int  mlx5_eswitch_enable_sriov(struct mlx5_eswitch *esw, int nvfs, int mode) { return 0; }
static inline void mlx5_eswitch_disable_sriov(struct mlx5_eswitch *esw) {}
#endif /* CONFIG_MLX5_ESWITCH */

static inline const char *mlx5_esw_mode_str(int mode)
{
	switch (mode) {
	case SRIOV_NONE: return "SRIOV_NONE";
	case SRIOV_LEGACY: return "SRIOV_LEGACY";
	case SRIOV_OFFLOADS: return "SRIOV_OFFLOADS";
	default: return "Unrecognized mode";
	}
}

int esw_offloads_stop(struct mlx5_eswitch *esw);
int esw_offloads_start(struct mlx5_eswitch *esw);

/* call only if this embedded cpu function */
static inline int ecpf_vport_index(struct mlx5_core_dev *dev)
{
	return MLX5_TOTAL_VPORTS(dev) - 1;
}

/* given index to the vports array esw->vports[],
 * return the vport number
 */
static inline int vport_idx2num(struct mlx5_core_dev *dev, int idx)
{
	if (!mlx5_core_is_ecpf(dev))
		return idx;

	if (idx == ecpf_vport_index(dev))
		return ECPF_ESW_PORT_NUMBER;

	return idx;
}

static inline int vport_num2idx(struct mlx5_core_dev *dev, int vport_num)
{
	if (!mlx5_core_is_ecpf(dev))
		return vport_num;

	if (vport_num == ECPF_ESW_PORT_NUMBER)
		return ecpf_vport_index(dev);

	return vport_num;
}

static inline int next_rep(struct mlx5_core_dev *dev, int cur, int total_vports)
{
	if (!mlx5_core_is_ecpf(dev))
		return cur + 1;

	if (cur == total_vports - 2)
		return MLX5_TOTAL_VPORTS(dev) - 1;

	return cur + 1;
}

static inline bool is_valid_rep_idx(struct mlx5_core_dev *dev, int cur, int total_vports)
{
	if (!mlx5_core_is_ecpf(dev))
		return cur < total_vports;

	return (cur == (MLX5_TOTAL_VPORTS(dev) - 1)) || (cur < total_vports - 1); // tbd sograyim
}

static inline int prev_rep(struct mlx5_core_dev *dev, int cur, int total_vports)
{
	if (!mlx5_core_is_ecpf(dev))
		return cur - 1;

	if (cur == MLX5_TOTAL_VPORTS(dev) - 1) {
		if (total_vports < 2) {
			mlx5_core_warn(dev, "BUG: total_vports %d\n", total_vports);
			return 0;
		}
		return total_vports - 2;
	}

	if (total_vports < 1) {
		mlx5_core_warn(dev, "BUG: total_vports %d\n", total_vports);
		return 0;
	}
	return cur - 1;
}

static inline int last_rep(struct mlx5_core_dev *dev, int total_vports)
{
	if (!mlx5_core_is_ecpf(dev))
		return total_vports - 1;

	return MLX5_TOTAL_VPORTS(dev) - 1;
}

static inline bool mlx5_priviliged_vport(struct mlx5_eswitch *esw,
					 u16 vport_num)
{
	if (mlx5_core_is_ecpf(esw->dev) && vport_num == ECPF_ESW_PORT_NUMBER)
		return true;

	if (!mlx5_core_is_ecpf(esw->dev) && !vport_num)
		return true;

	return false;
}

#endif /* SWITCH_H__ */
