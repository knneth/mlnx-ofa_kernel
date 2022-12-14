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
#include <linux/atomic.h>
#include <net/devlink.h>
#include <linux/mlx5/device.h>
#include <linux/mlx5/eswitch.h>
#include <linux/mlx5/vport.h>
#include <linux/mlx5/fs.h>
#include "lib/mpfs.h"
#include "mlx5_core.h"
#include "lib/fs_chains.h"
#include "sf/sf.h"
#include "en/tc_ct.h"
#include "en/tc_sample.h"
#include "net/mlxdevm.h"

#ifdef CONFIG_MLX5_ESWITCH

#define ESW_OFFLOADS_DEFAULT_NUM_GROUPS 15
#define ESW_DEFAULT_E2E_CACHE_SIZE 0

#define MLX5_MAX_UC_PER_VPORT(dev) \
	(1 << MLX5_CAP_GEN(dev, log_max_current_uc_list))

#define MLX5_MAX_MC_PER_VPORT(dev) \
	(1 << MLX5_CAP_GEN(dev, log_max_current_mc_list))

#define MLX5_MAX_VLAN_PER_VPORT(dev) \
	(1 << MLX5_CAP_GEN(dev, log_max_vlan_list))

#define MLX5_MIN_BW_SHARE 1

#define MLX5_RATE_TO_BW_SHARE(rate, divider, limit) \
	min_t(u32, max_t(u32, DIV_ROUND_UP(rate, divider), MLX5_MIN_BW_SHARE), limit)

#define mlx5_esw_has_fwd_fdb(dev) \
	MLX5_CAP_ESW_FLOWTABLE(dev, fdb_multi_path_to_table)

#define VHCA_VPORT_MATCH_ID_BITS 16
#define VHCA_VPORT_MATCH_ID_SIZE BIT(VHCA_VPORT_MATCH_ID_BITS)

#define esw_chains(esw) \
	((esw)->fdb_table.offloads.esw_chains_priv)

enum {
	MAPPING_ID_CHAIN,
	MAPPING_ID_TUNNEL,
	MAPPING_ID_TUNNEL_ENC_OPTS,
	MAPPING_ID_LABELS,
	MAPPING_ID_ZONE,
};

struct vport_meter {
	u64 rate;
	u64 burst;
	int meter_obj_id;
	int meter_idx;
	struct mlx5e_flow_meter_aso_obj *meter_obj;
	struct mlx5_flow_table *meter_tbl;
	struct mlx5_flow_group *meter_grp;
	struct mlx5_flow_handle *meter_rule;
	struct mlx5_flow_table *color_tbl;
	struct mlx5_flow_group *color_grp;
	struct mlx5_flow_handle *fwd_green_rule;
	struct mlx5_flow_handle *drop_red_rule;
	struct mlx5_fc *drop_counter;
	u64 packets_dropped;
	u64 bytes_dropped;
};

struct vport_ingress {
	struct mlx5_flow_table *acl;
	struct mlx5_flow_handle *allow_rule;
	struct {
		struct mlx5_flow_group *allow_tagged_spoofchk_grp;
		struct mlx5_flow_group *allow_untagged_spoofchk_grp;
		struct mlx5_flow_group *drop_grp;
		struct mlx5_flow_handle *drop_rule;
		struct mlx5_flow_handle  *allow_untagged_rule;
		struct list_head allow_vlans_rules;
		struct mlx5_fc *drop_counter;
	} legacy;
	struct {
		struct mutex vf_meter_lock;		/* protect vf meter operations */
		struct vport_meter *meter_xps[2];	/* bps: 0, pps: 1 */
		/* Optional group to add an FTE to do internal priority
		 * tagging on ingress packets.
		 */
		struct mlx5_flow_group *metadata_prio_tag_grp;
		/* Group to add default match-all FTE entry to tag ingress
		 * packet with metadata.
		 */
		struct mlx5_flow_group *metadata_allmatch_grp;
		struct mlx5_modify_hdr *modify_metadata;
		struct mlx5_flow_handle *modify_metadata_rule;
	} offloads;
};

struct vport_egress {
	struct mlx5_flow_table *acl;
	struct mlx5_flow_handle  *allowed_vlan;
	struct mlx5_flow_group *vlan_grp;
	struct {
		struct mlx5_flow_group *allow_untagged_grp;
		struct mlx5_flow_group *drop_grp;
		struct mlx5_flow_handle *drop_rule;
		struct mlx5_flow_handle *allow_untagged_rule;
		struct list_head allow_vlans_rules;
		struct mlx5_fc *drop_counter;
	} legacy;
	struct {
		struct mutex vf_meter_lock;		/* protect vf meter operations */
		struct vport_meter *meter_xps[2];	/* bps: 0, pps: 1 */
		struct mlx5_flow_handle *bounce_rule;
		struct mlx5_flow_group *bounce_grp;
		struct mlx5_flow_handle *fwd_rule;
		struct mlx5_flow_group *fwd_grp;
	} offloads;
};

struct mlx5_vport_drop_stats {
	u64 rx_dropped;
	u64 tx_dropped;
};

struct mlx5_vport_info {
	u8                      mac[ETH_ALEN];
	u16                     vlan;
	__be16			vlan_proto;
	u64                     node_guid;
	int                     link_state;
	u8                      qos;
	u8                      spoofchk: 1;
	u8                      trusted: 1;
	u8			roce: 1;
	/* the admin approved vlan list */
	DECLARE_BITMAP(vlan_trunk_8021q_bitmap, VLAN_N_VID);
};

/* Vport context events */
enum mlx5_eswitch_vport_event {
	MLX5_VPORT_UC_ADDR_CHANGE = BIT(0),
	MLX5_VPORT_MC_ADDR_CHANGE = BIT(1),
	MLX5_VPORT_VLAN_CHANGE = BIT(1),
	MLX5_VPORT_PROMISC_CHANGE = BIT(3),
};

struct mlx5_vport {
	struct mlx5_core_dev    *dev;
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
	u32                     default_metadata;
	u32                     metadata;

	struct mlx5_vport_info  info;

	struct {
		bool            enabled;
		u32             esw_tsar_ix;
		u32             bw_share;
		u32             min_rate;
		u32             max_rate;
		struct mlx5_vgroup *group;
	} qos;

	u16 vport;
	bool                    enabled;
	enum mlx5_eswitch_vport_event enabled_events;
	u16 match_id;
	int index;
	struct devlink_port *dl_port;
};

struct mlx5_esw_ipsec_priv;

struct mlx5_eswitch_fdb {
	union {
		struct legacy_fdb {
			struct mlx5_flow_table *fdb;
			struct mlx5_flow_group *addr_grp;
			struct mlx5_flow_group *allmulti_grp;
			struct mlx5_flow_group *promisc_grp;
			struct mlx5_flow_table *vepa_fdb;
			struct mlx5_flow_handle *vepa_uplink_rule;
			struct mlx5_flow_handle *vepa_star_rule;
		} legacy;

		struct offloads_fdb {
			struct mlx5_flow_namespace *ns;
			struct mlx5_flow_table *slow_fdb;
			struct mlx5_flow_group *send_to_vport_grp;
			struct mlx5_flow_group *send_to_vport_meta_grp;
			struct mlx5_flow_group *peer_miss_grp;
			struct mlx5_flow_handle **peer_miss_rules;
			struct mlx5_flow_group *miss_grp;
			struct mlx5_flow_handle **send_to_vport_meta_rules;
			struct mlx5_flow_handle *miss_rule_uni;
			struct mlx5_flow_handle *miss_rule_multi;
			int vlan_push_pop_refcount;

			struct mlx5_fs_chains *esw_chains_priv;
			struct {
				DECLARE_HASHTABLE(table, 8);
				/* Protects vports.table */
				struct mutex lock;
			} vports;
			struct mlx5_esw_ipsec_priv *esw_ipsec_priv;

			struct mlx5_flow_table *e2e_cache_fdb;
			struct mutex e2e_cache_lock; /* protects e2e_cache_fdb */
			refcount_t e2e_cache_ref;
			struct {
				DECLARE_HASHTABLE(table, 8);
				/* Protects indir.table */
				struct mutex lock;
			} indir;
		} offloads;
	};
	u32 flags;
};

struct mlx5_acl_vlan {
	struct mlx5_flow_handle	*acl_vlan_rule;
	struct list_head	list;
};

struct mlx5_pet_actions {
	struct mlx5_flow_table *ft;
	struct mlx5_flow_group *fg;
	struct mlx5_modify_hdr *hdr;
	struct mlx5_flow_handle *rule;
	struct mlx5_pkt_reformat *pkt_reformat;
};

struct mlx5_vport_match_actions {
	struct mlx5_pet_actions push_pet_hdr;
	struct mlx5_pet_actions copy_data_to_pet_hdr;
};

struct mlx5_pet_info {
	u16 ether_type;
	bool enabled;
};

struct mlx5_esw_offload {
	struct mlx5_flow_table *ft_offloads_restore;
	struct mlx5_flow_group *restore_group;
	struct mlx5_modify_hdr *restore_copy_hdr_id;
#if IS_ENABLED(CONFIG_MLX5_CLS_ACT)
	struct mapping_ctx *reg_c0_obj_pool;
#endif

	struct mlx5_flow_table *ft_offloads;
	struct mlx5_flow_group *vport_rx_group;
	struct mlx5_flow_group *vport_rx_internal_group;
	struct mlx5_flow_group *vport_rx_drop_group;
	struct mlx5_flow_handle *vport_rx_drop_rule;
	struct xarray vport_reps;
	struct list_head peer_flows;
	struct mutex peer_mutex;
	struct mutex encap_tbl_lock; /* protects encap_tbl */
	DECLARE_HASHTABLE(encap_tbl, 8);
	spinlock_t route_lock; /* protects route_tbl */
	unsigned long route_tbl_last_update;
	DECLARE_HASHTABLE(route_tbl, 8);
	struct mutex decap_tbl_lock; /* protects decap_tbl */
	DECLARE_HASHTABLE(decap_tbl, 8);
	struct mod_hdr_tbl mod_hdr;
	DECLARE_HASHTABLE(termtbl_tbl, 8);
	struct mutex termtbl_mutex; /* protects termtbl hash */
	const struct mlx5_eswitch_rep_ops *rep_ops[NUM_REP_TYPES];
	struct mlx5_vport_match_actions pet_vport_action;
	struct mlx5_pet_info pet_info;
	u8 inline_mode;
	enum devlink_eswitch_encap_mode encap;
	enum devlink_eswitch_ipsec_mode ipsec;
	struct ida vport_metadata_ida;
	unsigned int host_number; /* ECPF supports one external host */
	spinlock_t int_vports_lock; /* Protects int vports list */
	struct list_head int_vports; /* Uses offloads.vports.lock */
	bool int_vport_removing;
};

/* E-Switch MC FDB table hash node */
struct esw_mc_addr { /* SRIOV only */
	struct l2addr_node     node;
	struct mlx5_flow_handle *uplink_rule; /* Forward to uplink rule */
	u32                    refcnt;
};

struct mlx5_host_work {
	struct work_struct	work;
	struct mlx5_eswitch	*esw;
};

struct mlx5_esw_functions {
	struct mlx5_nb		nb;
	u16			num_vfs;
	bool			host_funcs_disabled;
};

enum {
	MLX5_ESWITCH_VPORT_MATCH_METADATA = BIT(0),
	MLX5_ESWITCH_REG_C1_LOOPBACK_ENABLED = BIT(1),
	MLX5_ESWITCH_PET_INSERT = BIT(2),
};

struct mlx5_smart_nic_vport {
	struct mlx5_eswitch    *esw;
	struct kobject          kobj;
	int                     vport;
};

struct mlx5_smart_nic_sysfs {
	struct kobject              *kobj;
	struct mlx5_smart_nic_vport *vport;
};

struct mlx5_vgroup {
	struct mlx5_core_dev *dev;
	struct mlxdevm_rate_group devm;
	u32		     group_id;
	u32		     num_vports;
	u32		     tsar_ix;
	/* TBD: TODO: After remove group sysfs, remove these two fields and always use from devm */
	u32		     max_rate;
	u32		     min_rate;
	u32		     bw_share;
	struct		     kobject kobj;
	struct		     list_head list;
};

struct mlx5_eswitch {
	struct mlx5_core_dev    *dev;
	struct mlx5_nb          nb;
	struct mlx5_eswitch_fdb fdb_table;
	/* legacy data structures */
	struct hlist_head       mc_table[MLX5_L2_ADDR_HASH_SIZE];
	struct esw_mc_addr mc_promisc;
	/* end of legacy */
	struct workqueue_struct *work_queue;
	struct xarray vports;
	u32 flags;
	int                     total_vports;
	int                     enabled_vports;
	struct rhashtable       vhca_map_ht;
	/* Synchronize between vport change events
	 * and async SRIOV admin state changes
	 */
	struct mutex            state_lock;

	/* Protects eswitch mode change that occurs via one or more
	 * user commands, i.e. sriov state change, devlink commands.
	 */
	struct mutex mode_lock;

	struct {
		bool            enabled;
		u32             root_tsar_ix;
		struct mlx5_vgroup *group0;
		struct list_head groups;
	} qos;

	struct mlx5_esw_offload offloads;
	atomic_t tc_refcnt;
	int                     mode;
	u16                     manager_vport;
	u16                     first_host_vport;
	struct {
		u32             large_group_num;
		u32             e2e_cache_size;
	}  params;
	struct mlx5_esw_functions esw_funcs;
	struct mlx5_smart_nic_sysfs smart_nic_sysfs;
	struct blocking_notifier_head n_head;
};

enum mlx5_mapped_obj_type {
	MLX5_MAPPED_OBJ_UNKNOWN,
	MLX5_MAPPED_OBJ_CHAIN,
	MLX5_MAPPED_OBJ_SAMPLE,
	MLX5_MAPPED_OBJ_INT_VPORT_METADATA,
};

struct mlx5_mapped_obj {
	enum mlx5_mapped_obj_type type;
	union {
		u32 chain;
		struct sample_obj {
			u32 group_id;
			u32 rate;
			u32 trunc_size;
		} sample;
		u32 int_vport_metadata;
	};
};

enum mlx5_esw_int_vport_type {
	MLX5_ESW_INT_VPORT_INGRESS,
	MLX5_ESW_INT_VPORT_EGRESS,
};

struct mlx5_esw_int_vport {
	enum mlx5_esw_int_vport_type type;
	int ifindex;
	u32 match_metadata;
	u32 mapping;
	struct list_head list;
	struct mlx5_flow_handle *rx_rule;
	refcount_t refcnt;
	struct completion res_ready;
	int compl_result;
	bool removing;
	struct rcu_head rcu_head;
};

void esw_offloads_disable(struct mlx5_eswitch *esw);
int esw_offloads_enable(struct mlx5_eswitch *esw);
void esw_offloads_cleanup_reps(struct mlx5_eswitch *esw);
int esw_offloads_init_reps(struct mlx5_eswitch *esw);
int mlx5_esw_offloads_pet_insert_set(struct mlx5_eswitch *esw, bool enable);
bool mlx5e_esw_offloads_pet_supported(const struct mlx5_eswitch *esw);

bool mlx5_esw_vport_match_metadata_supported(const struct mlx5_eswitch *esw);
int mlx5_esw_offloads_vport_metadata_set(struct mlx5_eswitch *esw, bool enable);
u32 mlx5_esw_match_metadata_alloc(struct mlx5_eswitch *esw);
void mlx5_esw_match_metadata_free(struct mlx5_eswitch *esw, u32 metadata);

int mlx5_esw_modify_vport_rate(struct mlx5_eswitch *esw, u16 vport_num,
			       u32 rate_mbps);

/* E-Switch API */
int mlx5_eswitch_init(struct mlx5_core_dev *dev);
void mlx5_eswitch_cleanup(struct mlx5_eswitch *esw);

#define MLX5_ESWITCH_IGNORE_NUM_VFS (-1)
int mlx5_eswitch_enable_locked(struct mlx5_eswitch *esw, int mode, int num_vfs);
int mlx5_eswitch_enable(struct mlx5_eswitch *esw, int num_vfs);
void mlx5_eswitch_disable_locked(struct mlx5_eswitch *esw, bool clear_vf);
void mlx5_eswitch_disable(struct mlx5_eswitch *esw, bool clear_vf);
int mlx5_eswitch_set_vport_mac(struct mlx5_eswitch *esw,
			       u16 vport, const u8 *mac);
int mlx5_eswitch_set_vport_state(struct mlx5_eswitch *esw,
				 u16 vport, int link_state);
int mlx5_eswitch_get_vport_from_vhca_id(struct mlx5_eswitch *esw, u16 vhca_id,
					u16 *vport);
int mlx5_eswitch_set_vport_vlan(struct mlx5_eswitch *esw,
				u16 vport, u16 vlan, u8 qos, __be16 vlan_proto);
int mlx5_eswitch_set_vport_spoofchk(struct mlx5_eswitch *esw,
				    u16 vport, bool spoofchk);
int mlx5_eswitch_set_vport_trust(struct mlx5_eswitch *esw,
				 u16 vport_num, bool setting);
int mlx5_eswitch_set_vport_rate(struct mlx5_eswitch *esw, u16 vport,
				u32 max_rate, u32 min_rate);
int mlx5_eswitch_set_vepa(struct mlx5_eswitch *esw, u8 setting);
int mlx5_eswitch_get_vepa(struct mlx5_eswitch *esw, u8 *setting);
int mlx5_eswitch_get_vport_config(struct mlx5_eswitch *esw,
				  u16 vport, struct ifla_vf_info *ivi);
int mlx5_eswitch_get_vport_stats(struct mlx5_eswitch *esw,
				 u16 vport,
				 struct ifla_vf_stats *vf_stats);
int mlx5_eswitch_get_vport_mac(struct mlx5_eswitch *esw,
			       u16 vport, u8 *mac);
int mlx5_eswitch_vport_update_group(struct mlx5_eswitch *esw, int vport_num,
				    u32 group_id, const char *group_name);
int mlx5_eswitch_set_vgroup_max_rate(struct mlx5_eswitch *esw,
				     int group_id, const char *group_name,
				     u32 max_rate);
int mlx5_eswitch_set_vgroup_min_rate(struct mlx5_eswitch *esw,
				     int group_id, const char *group_name,
				     u32 min_rate);
struct mlx5_vgroup *esw_create_vgroup(struct mlx5_eswitch *esw, u32 group_id,
				      const char *name);
void esw_destroy_vgroup(struct mlx5_eswitch *esw, struct mlx5_vgroup *group);

int mlx5_eswitch_enable_vport(struct mlx5_eswitch *esw,
			      u16 vport_num,
			      enum mlx5_eswitch_vport_event enable_events);
void mlx5_eswitch_disable_vport(struct mlx5_eswitch *esw,
				u16 vport_num);

struct ifla_vf_stats_backport {
	__u64 tx_broadcast;
	__u64 tx_multicast;
};

int mlx5_eswitch_get_vport_stats_backport(struct mlx5_eswitch *esw,
					  int vport,
					  struct ifla_vf_stats_backport *vf_stats_backport);
void mlx5_eswitch_del_send_to_vport_rule(struct mlx5_flow_handle *rule);
int mlx5_eswitch_add_vport_trunk_range(struct mlx5_eswitch *esw,
				       int vport, u16 start_vlan, u16 end_vlan);
int mlx5_eswitch_del_vport_trunk_range(struct mlx5_eswitch *esw,
				       int vport, u16 start_vlan, u16 end_vlan);

int mlx5_eswitch_modify_esw_vport_context(struct mlx5_core_dev *dev, u16 vport,
					  bool other_vport, void *in);

struct mlx5_flow_spec;
struct mlx5_esw_flow_attr;
struct mlx5_termtbl_handle;

bool
mlx5_eswitch_termtbl_required(struct mlx5_eswitch *esw,
			      struct mlx5_flow_attr *attr,
			      struct mlx5_flow_act *flow_act,
			      struct mlx5_flow_spec *spec);

struct mlx5_flow_handle *
mlx5_eswitch_add_termtbl_rule(struct mlx5_eswitch *esw,
			      struct mlx5_flow_table *ft,
			      struct mlx5_flow_spec *spec,
			      struct mlx5_esw_flow_attr *attr,
			      struct mlx5_flow_act *flow_act,
			      struct mlx5_flow_destination *dest,
			      int num_dest);

void
mlx5_eswitch_termtbl_put(struct mlx5_eswitch *esw,
			 struct mlx5_termtbl_handle *tt);

void
mlx5_eswitch_clear_rule_source_port(struct mlx5_eswitch *esw,
				    struct mlx5_flow_spec *spec,
				    struct mlx5_esw_flow_attr *attr);

struct mlx5_flow_handle *
mlx5_eswitch_add_offloaded_rule(struct mlx5_eswitch *esw,
				struct mlx5_flow_spec *spec,
				struct mlx5_flow_attr *attr);
struct mlx5_flow_handle *
mlx5_eswitch_add_fwd_rule(struct mlx5_eswitch *esw,
			  struct mlx5_flow_spec *spec,
			  struct mlx5_flow_attr *attr);
void
mlx5_eswitch_del_offloaded_rule(struct mlx5_eswitch *esw,
				struct mlx5_flow_handle *rule,
				struct mlx5_flow_attr *attr);
void
mlx5_eswitch_del_fwd_rule(struct mlx5_eswitch *esw,
			  struct mlx5_flow_handle *rule,
			  struct mlx5_flow_attr *attr);

struct mlx5_flow_handle *
mlx5_eswitch_create_vport_rx_rule(struct mlx5_eswitch *esw, u16 vport,
				  struct mlx5_flow_destination *dest);

enum {
	SET_VLAN_STRIP	= BIT(0),
	SET_VLAN_INSERT	= BIT(1)
};

enum mlx5_flow_match_level {
	MLX5_MATCH_NONE	= MLX5_INLINE_MODE_NONE,
	MLX5_MATCH_L2	= MLX5_INLINE_MODE_L2,
	MLX5_MATCH_L3	= MLX5_INLINE_MODE_IP,
	MLX5_MATCH_L4	= MLX5_INLINE_MODE_TCP_UDP,
};

/* current maximum for flow based vport multicasting */
#define MLX5_MAX_FLOW_FWD_VPORTS 2

enum {
	MLX5_ESW_DEST_ENCAP         = BIT(0),
	MLX5_ESW_DEST_ENCAP_VALID   = BIT(1),
	MLX5_ESW_DEST_CHAIN_WITH_SRC_PORT_CHANGE  = BIT(2),
};

enum {
	MLX5_ESW_ATTR_FLAG_VLAN_HANDLED  = BIT(0),
	MLX5_ESW_ATTR_FLAG_SLOW_PATH     = BIT(1),
	MLX5_ESW_ATTR_FLAG_NO_IN_PORT    = BIT(2),
	MLX5_ESW_ATTR_FLAG_SAMPLE        = BIT(3),
	MLX5_ESW_ATTR_FLAG_E2E_CACHE     = BIT(4),
};

struct mlx5_esw_flow_attr {
	struct mlx5_eswitch_rep *in_rep;
	struct mlx5_core_dev	*in_mdev;
	struct mlx5_core_dev    *counter_dev;
	struct mlx5_esw_int_vport *int_port;
	struct mlx5_esw_int_vport *dest_int_port;

	int split_count;
	int out_count;

	__be16	vlan_proto[MLX5_FS_VLAN_DEPTH];
	u16	vlan_vid[MLX5_FS_VLAN_DEPTH];
	u8	vlan_prio[MLX5_FS_VLAN_DEPTH];
	u8	total_vlan;
	struct {
		u32 flags;
		struct mlx5_eswitch_rep *rep;
		struct mlx5_pkt_reformat *pkt_reformat;
		struct mlx5_core_dev *mdev;
		struct mlx5_termtbl_handle *termtbl;
		int src_port_rewrite_act_id;
	} dests[MLX5_MAX_FLOW_FWD_VPORTS];
	struct mlx5_sample_attr *sample;
	bool	is_tunnel_flow;
	bool	src_port_rewrite_supported;
	u8      ip_version;
	u16     decap_vport;
	union {
		__be32 v4;
		struct in6_addr v6;
	} src_ip; /* Valid if decap_vport is not zero */
	union {
		__be32 v4;
		struct in6_addr v6;
	} dst_ip; /* Valid if decap_vport is not zero */
	u32 vni;
	struct mlx5_flow_table *fdb;
	struct mlx5_flow_table *dest_ft;
	struct mlx5_ct_attr ct_attr;
};

struct mlx5_nic_flow_attr {
	u32 flow_tag;
	u32 hairpin_tirn;
	struct mlx5_flow_table *hairpin_ft;
	u32 user_prio;
};

struct mlx5_flow_attr {
	u32 action;
	struct mlx5_fc *counter;
	struct mlx5_modify_hdr *modify_hdr;
	struct mlx5_ct_attr ct_attr;
	struct mlx5_pkt_reformat *decap_pkt_reformat;
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	u32 chain;
	u16 prio;
	u32 dest_chain;
	struct mlx5_flow_table *ft;
	struct mlx5_flow_table *dest_ft;
	u8 inner_match_level;
	u8 outer_match_level;
	u32 flags;
	union {
		struct mlx5_esw_flow_attr esw_attr[0];
		struct mlx5_nic_flow_attr nic_attr[0];
	};
};

int mlx5_devlink_eswitch_mode_set(struct devlink *devlink, u16 mode,
				  struct netlink_ext_ack *extack);
int mlx5_devlink_eswitch_mode_get(struct devlink *devlink, u16 *mode);
int mlx5_devlink_eswitch_inline_mode_set(struct devlink *devlink, u8 mode,
					 struct netlink_ext_ack *extack);
int mlx5_devlink_eswitch_inline_mode_get(struct devlink *devlink, u8 *mode);

int mlx5_eswitch_vport_modify_other_hca_cap_roce(struct mlx5_eswitch *esw,
						 struct mlx5_vport *vport, bool value);
int mlx5_eswitch_vport_get_other_hca_cap_roce(struct mlx5_eswitch *esw,
					      struct mlx5_vport *vport, bool *value);

int mlx5_devlink_eswitch_encap_mode_set(struct devlink *devlink,
					enum devlink_eswitch_encap_mode encap,
					struct netlink_ext_ack *extack);
int mlx5_devlink_eswitch_encap_mode_get(struct devlink *devlink,
					enum devlink_eswitch_encap_mode *encap);
int mlx5_devlink_eswitch_ipsec_mode_set(struct devlink *devlink,
					enum devlink_eswitch_ipsec_mode ipsec,
					struct netlink_ext_ack *extack);
int mlx5_devlink_eswitch_ipsec_mode_get(struct devlink *devlink,
					enum devlink_eswitch_ipsec_mode *ipsec);
int mlx5_devlink_port_function_hw_addr_get(struct devlink *devlink,
					   struct devlink_port *port,
					   u8 *hw_addr, int *hw_addr_len,
					   struct netlink_ext_ack *extack);
int mlx5_devlink_port_function_hw_addr_set(struct devlink *devlink,
					   struct devlink_port *port,
					   const u8 *hw_addr, int hw_addr_len,
					   struct netlink_ext_ack *extack);
int mlx5_devlink_rate_leaf_tx_share_set(struct devlink *devlink,
					struct devlink_port *port,
					u64 tx_share,
					struct netlink_ext_ack *extack);
int mlx5_devlink_rate_leaf_tx_max_set(struct devlink *devlink,
				      struct devlink_port *port,
				      u64 tx_max,
				      struct netlink_ext_ack *extack);
int mlx5_devlink_rate_leaf_group_set(struct devlink *devlink,
				     struct devlink_port *port,
				     const char *group,
				     struct netlink_ext_ack *extack);
int mlx5_devlink_rate_leaf_get(struct devlink *devlink,
			       struct devlink_port *port,
			       u64 *tx_max, u64 *tx_share, char **group,
			       struct netlink_ext_ack *extack);
int mlx5_devlink_rate_node_tx_max_set(struct devlink *devlink,
				      const char *group, u64 tx_max,
				      struct netlink_ext_ack *extack);
int mlx5_devlink_rate_node_tx_share_set(struct devlink *devlink,
					const char *group, u64 tx_share,
					struct netlink_ext_ack *extack);
int mlx5_devlink_rate_node_new(struct devlink *devlink, const char *group,
			       struct netlink_ext_ack *extack);
int mlx5_devlink_rate_node_del(struct devlink *devlink, const char *group,
			       struct netlink_ext_ack *extack);
void *mlx5_eswitch_get_uplink_priv(struct mlx5_eswitch *esw, u8 rep_type);

int mlx5_eswitch_add_vlan_action(struct mlx5_eswitch *esw,
				 struct mlx5_flow_attr *attr);
int mlx5_eswitch_del_vlan_action(struct mlx5_eswitch *esw,
				 struct mlx5_flow_attr *attr);
int __mlx5_eswitch_set_vport_vlan(struct mlx5_eswitch *esw, int vport,
				  u16 vlan, u8 qos, __be16 proto, u8 set_flags);

static inline bool mlx5_esw_qos_enabled(struct mlx5_eswitch *esw)
{
	return esw->qos.enabled;
}

static inline bool mlx5_eswitch_vlan_actions_supported(struct mlx5_core_dev *dev,
						       u8 vlan_depth)
{
	bool ret = MLX5_CAP_ESW_FLOWTABLE_FDB(dev, pop_vlan) &&
		   MLX5_CAP_ESW_FLOWTABLE_FDB(dev, push_vlan);

	if (vlan_depth == 1)
		return ret;

	return  ret && MLX5_CAP_ESW_FLOWTABLE_FDB(dev, pop_vlan_2) &&
		MLX5_CAP_ESW_FLOWTABLE_FDB(dev, push_vlan_2);
}

enum esw_vst_mode {
	ESW_VST_MODE_BASIC,
	ESW_VST_MODE_STEERING,
	ESW_VST_MODE_INSERT_ALWAYS,
};

static inline enum esw_vst_mode esw_get_vst_mode(struct mlx5_eswitch *esw)
{
	/*  vst mode precedence:
	 *  if vst steering mode is supported use it
	 *  if not, look for vst vport insert always support
	 *  if both not supported, we use basic vst, can't support QinQ
	 */
	if (MLX5_CAP_ESW_EGRESS_ACL(esw->dev, pop_vlan) &&
	    MLX5_CAP_ESW_INGRESS_ACL(esw->dev, push_vlan))
		return ESW_VST_MODE_STEERING;
	else if (MLX5_CAP_ESW(esw->dev, vport_cvlan_insert_always))
		return ESW_VST_MODE_INSERT_ALWAYS;
	else
		return ESW_VST_MODE_BASIC;
}

bool mlx5_esw_check_modes_match(struct mlx5_core_dev *dev0,
				struct mlx5_core_dev *dev1,
				int mode);

const u32 *mlx5_esw_query_functions(struct mlx5_core_dev *dev);

#define MLX5_DEBUG_ESWITCH_MASK BIT(3)

#define esw_info(__dev, format, ...)			\
	dev_info((__dev)->device, "E-Switch: " format, ##__VA_ARGS__)

#define esw_warn(__dev, format, ...)			\
	dev_warn((__dev)->device, "E-Switch: " format, ##__VA_ARGS__)

#define esw_debug(dev, format, ...)				\
	mlx5_core_dbg_mask(dev, MLX5_DEBUG_ESWITCH_MASK, format, ##__VA_ARGS__)

static inline bool mlx5_esw_allowed(const struct mlx5_eswitch *esw)
{
	return esw && MLX5_ESWITCH_MANAGER(esw->dev);
}

/* The returned number is valid only when the dev is eswitch manager. */
static inline u16 mlx5_eswitch_manager_vport(struct mlx5_core_dev *dev)
{
	return mlx5_core_is_ecpf_esw_manager(dev) ?
		MLX5_VPORT_ECPF : MLX5_VPORT_PF;
}

static inline bool
mlx5_esw_is_manager_vport(const struct mlx5_core_dev *dev, u16 vport_num)
{
	return MLX5_VPORT_MANAGER(dev) &&
	       dev->priv.eswitch->manager_vport == vport_num;
}

static inline u16 mlx5_eswitch_first_host_vport_num(struct mlx5_core_dev *dev)
{
	return mlx5_core_is_ecpf_esw_manager(dev) ?
		MLX5_VPORT_PF : MLX5_VPORT_FIRST_VF;
}

static inline bool mlx5_eswitch_is_funcs_handler(const struct mlx5_core_dev *dev)
{
	return mlx5_core_is_ecpf_esw_manager(dev);
}

/* SF vport numbers in device range from the esw_sf_base_id and log_max_esw_sf.
 * Below helpers perform conversion from SF vport index in software array
 * to vport number and vice versa.
 */
static inline u16 mlx5_eswitch_sf_vport_base_id(const struct mlx5_core_dev *dev)
{
	return MLX5_CAP_GEN(dev, sf_base_id);
}

static inline unsigned int
mlx5_esw_vport_to_devlink_port_index(const struct mlx5_core_dev *dev,
				     u16 vport_num)
{
	return (MLX5_CAP_GEN(dev, vhca_id) << 16) | vport_num;
}

static inline u16
mlx5_esw_devlink_port_index_to_vport_num(unsigned int dl_port_index)
{
	return dl_port_index & 0xffff;
}

/* TODO: This mlx5e_tc function shouldn't be called by eswitch */
void mlx5e_tc_clean_fdb_peer_flows(struct mlx5_eswitch *esw);

/* Each mark identifies eswitch vport type.
 * MLX5_ESW_VPT_HOST_FN is used to identify both PF and VF ports using
 * a single mark.
 * MLX5_ESW_VPT_VF identifies a SRIOV VF vport.
 * MLX5_ESW_VPT_SF identifies SF vport.
 */

#define MLX5_ESW_VPT_HOST_FN XA_MARK_0
#define MLX5_ESW_VPT_VF XA_MARK_1
#define MLX5_ESW_VPT_SF XA_MARK_2

#define mlx5_esw_for_each_vport(esw, index, vport) \
	xa_for_each(&((esw)->vports), index, vport)

#define mlx5_esw_for_each_entry_marked(xa, index, entry, last, filter)	\
	for (index = 0, entry = xa_find(xa, &index, last, filter); \
	     entry; entry = xa_find_after(xa, &index, last, filter))

#define mlx5_esw_for_each_vport_marked(esw, index, vport, last, filter)	\
	mlx5_esw_for_each_entry_marked(&((esw)->vports), index, vport, last, filter)

#define mlx5_esw_for_each_vf_vport(esw, index, vport, last)	\
	mlx5_esw_for_each_vport_marked(esw, index, vport, last, MLX5_ESW_VPT_VF)

#define mlx5_esw_for_each_host_func_vport(esw, index, vport, last)	\
	mlx5_esw_for_each_vport_marked(esw, index, vport, last, MLX5_ESW_VPT_HOST_FN)

struct mlx5_eswitch *mlx5_devlink_eswitch_get(struct devlink *devlink);
struct mlx5_vport *__must_check
mlx5_eswitch_get_vport(struct mlx5_eswitch *esw, u16 vport_num);

bool mlx5_eswitch_is_vf_vport(struct mlx5_eswitch *esw, u16 vport_num);
bool mlx5_esw_is_sf_vport(struct mlx5_eswitch *esw, u16 vport_num);

int mlx5_esw_funcs_changed_handler(struct notifier_block *nb, unsigned long type, void *data);

int
mlx5_eswitch_enable_pf_vf_vports(struct mlx5_eswitch *esw,
				 enum mlx5_eswitch_vport_event enabled_events);
void mlx5_eswitch_disable_pf_vf_vports(struct mlx5_eswitch *esw);

int
esw_vport_create_offloads_acl_tables(struct mlx5_eswitch *esw,
				     struct mlx5_vport *vport);
void
esw_vport_destroy_offloads_acl_tables(struct mlx5_eswitch *esw,
				      struct mlx5_vport *vport);

struct esw_vport_tbl_namespace {
	int max_fte;
	int max_num_groups;
	u32 flags;
};

struct mlx5_vport_tbl_attr {
	u32 chain;
	u16 prio;
	u16 vport;
	const struct esw_vport_tbl_namespace *vport_ns;
};

struct mlx5_flow_table *
esw_vport_tbl_get(struct mlx5_eswitch *esw, struct mlx5_vport_tbl_attr *attr);
void
esw_vport_tbl_put(struct mlx5_eswitch *esw, struct mlx5_vport_tbl_attr *attr);

struct mlx5_flow_handle *
esw_add_restore_rule(struct mlx5_eswitch *esw, u32 tag);

int esw_offloads_load_rep(struct mlx5_eswitch *esw, u16 vport_num);
void esw_offloads_unload_rep(struct mlx5_eswitch *esw, u16 vport_num);

int mlx5_esw_offloads_rep_load(struct mlx5_eswitch *esw, u16 vport_num);
void mlx5_esw_offloads_rep_unload(struct mlx5_eswitch *esw, u16 vport_num);

int mlx5_eswitch_load_vport(struct mlx5_eswitch *esw, u16 vport_num,
			    enum mlx5_eswitch_vport_event enabled_events);
void mlx5_eswitch_unload_vport(struct mlx5_eswitch *esw, u16 vport_num);

int mlx5_eswitch_load_vf_vports(struct mlx5_eswitch *esw, u16 num_vfs,
				enum mlx5_eswitch_vport_event enabled_events);
void mlx5_eswitch_unload_vf_vports(struct mlx5_eswitch *esw, u16 num_vfs);
int mlx5_devlink_eswitch_steering_mode_set(struct devlink *devlink,
					   enum devlink_eswitch_steering_mode mode);
int mlx5_devlink_eswitch_steering_mode_get(struct devlink *devlink,
					   enum devlink_eswitch_steering_mode *mode);
int mlx5_devlink_eswitch_vport_match_mode_set(struct devlink *devlink,
					      enum devlink_eswitch_vport_match_mode mode);
int mlx5_devlink_eswitch_vport_match_mode_get(struct devlink *devlink,
					      enum devlink_eswitch_vport_match_mode *mode);
struct mlx5_esw_int_vport *
mlx5_esw_get_int_vport_from_metadata(struct mlx5_eswitch *esw,
				     u32 metadata);
struct mlx5_esw_int_vport *
mlx5_esw_get_int_vport(struct mlx5_eswitch *esw,
		       struct net_device *netdev,
		       enum mlx5_esw_int_vport_type type);
void
mlx5_esw_put_int_vport(struct mlx5_eswitch *esw,
		       struct mlx5_esw_int_vport *int_vport);
void mlx5_esw_init_int_vport(struct mlx5_eswitch *esw);
void mlx5_esw_cleanup_int_vport(struct mlx5_eswitch *esw);
int mlx5_esw_offloads_devlink_port_register(struct mlx5_eswitch *esw, u16 vport_num);
void mlx5_esw_offloads_devlink_port_unregister(struct mlx5_eswitch *esw, u16 vport_num);
struct devlink_port *mlx5_esw_offloads_devlink_port(struct mlx5_eswitch *esw, u16 vport_num);

int mlx5_esw_devlink_sf_port_register(struct mlx5_eswitch *esw, struct devlink_port *dl_port,
				      u16 vport_num, u32 controller, u32 sfnum);
void mlx5_esw_devlink_sf_port_unregister(struct mlx5_eswitch *esw, u16 vport_num);

int mlx5_esw_offloads_sf_vport_enable(struct mlx5_eswitch *esw, struct devlink_port *dl_port,
				      u16 vport_num, u32 controller, u32 sfnum);
void mlx5_esw_offloads_sf_vport_disable(struct mlx5_eswitch *esw, u16 vport_num);
int mlx5_esw_sf_max_hpf_functions(struct mlx5_core_dev *dev, u16 *max_sfs, u16 *sf_base_id);

/**
 * mlx5_esw_event_info - Indicates eswitch mode changed/changing.
 *
 * @new_mode: New mode of eswitch.
 */
struct mlx5_esw_event_info {
	u16 new_mode;
};

int mlx5_esw_event_notifier_register(struct mlx5_eswitch *esw, struct notifier_block *n);
void mlx5_esw_event_notifier_unregister(struct mlx5_eswitch *esw, struct notifier_block *n);
bool mlx5e_esw_offloads_pet_enabled(const struct mlx5_eswitch *esw);
int mlx5e_esw_offloads_pet_setup(struct mlx5_eswitch *esw, struct mlx5_flow_table *ft);
void mlx5e_esw_offloads_pet_cleanup(struct mlx5_eswitch *esw);

void esw_vport_change_handle_locked(struct mlx5_vport *vport);

bool mlx5_esw_offloads_controller_valid(const struct mlx5_eswitch *esw, u32 controller);
bool mlx5_esw_host_functions_enabled(const struct mlx5_core_dev *dev);
#else  /* CONFIG_MLX5_ESWITCH */
/* eswitch API stubs */
static inline int  mlx5_eswitch_init(struct mlx5_core_dev *dev) { return 0; }
static inline void mlx5_eswitch_cleanup(struct mlx5_eswitch *esw) {}
static inline int mlx5_eswitch_enable(struct mlx5_eswitch *esw, int num_vfs) { return 0; }
static inline void mlx5_eswitch_disable(struct mlx5_eswitch *esw, bool clear_vf) {}
static inline bool mlx5_esw_check_modes_match(struct mlx5_core_dev *dev0,
					      struct mlx5_core_dev *dev1,
					      int mode) { return false; }
static inline bool mlx5_eswitch_is_funcs_handler(struct mlx5_core_dev *dev) { return false; }
static inline
int mlx5_eswitch_set_vport_state(struct mlx5_eswitch *esw, u16 vport, int link_state) { return 0; }
static inline const u32 *mlx5_esw_query_functions(struct mlx5_core_dev *dev)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline struct mlx5_flow_handle *
esw_add_restore_rule(struct mlx5_eswitch *esw, u32 tag)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline bool
mlx5_esw_is_manager_vport(const struct mlx5_core_dev *dev, u16 vport_num)
{
	return vport_num ? true : false;
}

static inline unsigned int
mlx5_esw_vport_to_devlink_port_index(const struct mlx5_core_dev *dev,
				     u16 vport_num)
{
	return vport_num;
}

static inline bool mlx5e_esw_offloads_pet_enabled(const struct mlx5_eswitch *esw)
{
	return false;
};

static inline bool mlx5_esw_host_functions_enabled(const struct mlx5_core_dev *dev)
{
	return true;
}
#endif /* CONFIG_MLX5_ESWITCH */

int mlx5_eswitch_compat_sysfs_init(struct net_device *netdev);
void mlx5_eswitch_compat_sysfs_cleanup(struct net_device *netdev);
#endif /* __MLX5_ESWITCH_H__ */
