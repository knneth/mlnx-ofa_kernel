/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_ESW_QOS_H__
#define __MLX5_ESW_QOS_H__

#ifdef CONFIG_MLX5_ESWITCH

#define MLX5_ESW_QOS_SYSFS_GROUP_MAX_ID 255
#define MLX5_ESW_QOS_NON_SYSFS_GROUP (MLX5_ESW_QOS_SYSFS_GROUP_MAX_ID + 1)
#include "net/mlxdevm.h"

/* Holds rate nodes associated with one or more E-Switches.
 * If cross-esw scheduling is supported, this is shared between all
 * E-Switches of a NIC.
 */
struct mlx5_qos_domain {
	/* Serializes access to all qos changes in the qos domain. */
	struct mutex lock;
	/* Whether this domain is shared with other E-Switches. */
	bool shared;
	/* The reference count is only used for shared qos domains. */
	refcount_t refcnt;
	/* List of all mlx5_esw_sched_nodes. */
	struct list_head nodes;
};

enum sched_node_type {
	SCHED_NODE_TYPE_VPORTS_TSAR,
	SCHED_NODE_TYPE_VPORT,
	SCHED_NODE_TYPE_VPORT_TC,
	SCHED_NODE_TYPE_VPORTS_TC_TSAR,
	SCHED_NODE_TYPE_TC_ARBITER_TSAR,
	SCHED_NODE_TYPE_VPORTS_AND_TC_ARBITERS_TSAR,
};

struct mlx5_esw_sched_node {
	u32 ix;
	struct mlx5_core_dev *dev;
	struct mlxdevm_rate_group devm;
	/* Bandwidth parameters. */
	u32 tsar_ix;
	u32 max_rate;
	u32 min_rate;
	/* A computed value indicating relative min_rate between node's members. */
	u32 bw_share;
	/* The parent node in the rate hierarchy. */
	struct mlx5_esw_sched_node *parent;
	/* Entry in the parent node's children list. */
	struct list_head entry;
	/* The type of this node in the rate hierarchy. */
	enum sched_node_type type;
	/* The eswitch this node belongs to. */
	struct mlx5_eswitch *esw;
	/* The children nodes of this node, empty list for leaf nodes.
	 * Can be from multiple eswitches.
	 */
	struct list_head children;
	/* Valid only if this node is associated with a vport. */
	struct mlx5_vport *vport;
	/* Valid only when this node represents a traffic class. */
	u8 tc;

	/* sysfs group related fields */
	struct kobject kobj;
	u32 group_id;
	u32 num_vports;
	struct completion free_group_comp;
	/* Valid only when this node is type of VPORTS_TC_TSAR */
	u32 user_bw_share;
};

static inline void esw_qos_lock(struct mlx5_eswitch *esw)
{
	mutex_lock(&esw->qos.domain->lock);
}

static inline void esw_qos_unlock(struct mlx5_eswitch *esw)
{
	mutex_unlock(&esw->qos.domain->lock);
}

static inline void esw_assert_qos_lock_held(struct mlx5_eswitch *esw)
{
	lockdep_assert_held(&esw->qos.domain->lock);
}

int mlx5_esw_qos_init(struct mlx5_eswitch *esw);
void mlx5_esw_qos_cleanup(struct mlx5_eswitch *esw);

int mlx5_esw_qos_set_vport_rate(struct mlx5_vport *evport,
				u32 max_rate, u32 min_rate);
bool mlx5_esw_qos_get_vport_rate(struct mlx5_vport *vport, u32 *max_rate, u32 *min_rate);
void mlx5_esw_qos_vport_disable(struct mlx5_vport *vport);

u32 mlx5_esw_qos_vport_get_sched_elem_ix(const struct mlx5_vport *vport);
struct mlx5_esw_sched_node *mlx5_esw_qos_vport_get_parent(const struct mlx5_vport *vport);
int mlx5_esw_qos_vport_tc_update_tc_arbitration_node(struct mlx5_vport *vport,
						     struct mlx5_esw_sched_node *node,
						     struct netlink_ext_ack *extack);
int esw_qos_vport_tc_disable(struct mlx5_vport *vport,
			     struct mlx5_esw_sched_node *node,
			     struct netlink_ext_ack *extack);
bool esw_qos_tc_arbitration_enabled_on_vport(struct mlx5_vport *vport);
int esw_qos_vport_tc_update_node(struct mlx5_vport *vport,
				 struct mlx5_esw_sched_node *new_tc_arbiter_node,
				 struct netlink_ext_ack *extack);

void mlx5_esw_qos_pre_cleanup(struct mlx5_core_dev *dev, int num_vfs);
int mlx5_esw_qos_vport_update_sysfs_group(struct mlx5_eswitch *esw, u32 group_id,
					  struct mlx5_vport *vport);
int mlx5_esw_qos_set_sysfs_group_max_rate(struct mlx5_eswitch *esw,
					  struct mlx5_esw_sched_node *group,
					  u32 max_rate);
int mlx5_esw_qos_set_sysfs_group_min_rate(struct mlx5_eswitch *esw,
					  struct mlx5_esw_sched_node *group,
					  u32 min_rate);
struct mlx5_esw_sched_node *
esw_qos_create_vports_sched_node(struct mlx5_eswitch *esw, u32 group_id,
				 struct netlink_ext_ack *extack);
int esw_qos_destroy_node(struct mlx5_esw_sched_node *node,
			 struct netlink_ext_ack *extack);
int esw_qos_set_node_max_rate(struct mlx5_esw_sched_node *node,
			       u32 max_rate, struct netlink_ext_ack *extack);
int esw_qos_set_node_min_rate(struct mlx5_esw_sched_node *node,
			       u32 min_rate, struct netlink_ext_ack *extack);
int
mlx5_esw_get_esw_and_vport(struct devlink *devlink, struct devlink_port *port,
			   struct mlx5_eswitch **esw, struct mlx5_vport **vport,
			   struct netlink_ext_ack *extack);
int esw_qos_vport_enable(struct mlx5_vport *vport,
			 u32 max_rate, u32 bw_share, struct netlink_ext_ack *extack);
int esw_qos_set_vport_min_rate(struct mlx5_vport *evport,
			       u32 min_rate, struct netlink_ext_ack *extack);
int esw_qos_set_vport_max_rate(struct mlx5_vport *evport,
			       u32 max_rate, struct netlink_ext_ack *extack);

int mlx5_esw_sysfs_rate_leaf_tc_bw_set(void *priv, u32 *tc_bw, struct netlink_ext_ack *extack);
int mlx5_esw_sysfs_rate_node_tc_bw_set(void *priv, u32 *tc_bw, struct netlink_ext_ack *extack);

int
esw_qos_destroy_vports_tc_nodes(struct mlx5_esw_sched_node *tc_arbiter_node, bool force,
				struct netlink_ext_ack *extack);
int mlx5_esw_devm_rate_leaf_tc_bw_set(void *priv, u32 *tc_bw, struct netlink_ext_ack *extack);
int mlx5_esw_devm_rate_node_tc_bw_set(struct mlx5_eswitch *esw, const char *group_name,
				      u32 *tc_bw, struct netlink_ext_ack *extack);
int mlx5_esw_qos_set_vport_tc_min_rate(struct mlx5_eswitch *esw, struct mlx5_vport *vport,
				       u64 tx_share, struct netlink_ext_ack *extack);
int mlx5_esw_rate_leaf_tx_max_set(struct mlx5_eswitch *esw, struct mlx5_vport *vport,
				  u64 tx_max, struct netlink_ext_ack *extack);

int esw_qos_vport_update_node(struct mlx5_vport *vport, struct mlx5_esw_sched_node *node,
			      struct netlink_ext_ack *extack);

#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS

int mlx5_esw_devlink_rate_leaf_tx_share_set(struct devlink_rate *rate_leaf, void *priv,
					    u64 tx_share, struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_leaf_tx_max_set(struct devlink_rate *rate_leaf, void *priv,
					  u64 tx_max, struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_leaf_tc_bw_set(struct devlink_rate *rate_node, void *priv,
					 u32 *tc_bw, struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_node_tc_bw_set(struct devlink_rate *rate_node, void *priv,
					 u32 *tc_bw, struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_node_tx_share_set(struct devlink_rate *rate_node, void *priv,
					    u64 tx_share, struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_node_tx_max_set(struct devlink_rate *rate_node, void *priv,
					  u64 tx_max, struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_node_new(struct devlink_rate *rate_node, void **priv,
				   struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_node_del(struct devlink_rate *rate_node, void *priv,
				   struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_parent_set(struct devlink_rate *devlink_rate,
				     struct devlink_rate *parent,
				     void *priv, void *parent_priv,
				     struct netlink_ext_ack *extack);

#endif /* HAVE_DEVLINK_HAS_RATE_FUNCTIONS */

#endif

#endif
