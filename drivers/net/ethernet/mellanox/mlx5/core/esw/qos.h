/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_ESW_QOS_H__
#define __MLX5_ESW_QOS_H__

#include <mlxdevm_ext.h>
#include <net/mlxdevm.h>

#ifdef CONFIG_MLX5_ESWITCH

#define MLX5_ESW_QOS_SYSFS_GROUP_MAX_ID 255
#define MLX5_ESW_QOS_NON_SYSFS_GROUP (MLX5_ESW_QOS_SYSFS_GROUP_MAX_ID + 1)

/* Holds rate nodes associated with an E-Switch. */
struct mlx5_qos_domain {
	/* Serializes access to all qos changes in the qos domain. */
	struct mutex lock;
	/* List of all mlx5_esw_sched_nodes. */
	struct list_head nodes;
};

enum sched_node_type {
	SCHED_NODE_TYPE_VPORTS_TSAR,
	SCHED_NODE_TYPE_VPORT,
	SCHED_NODE_TYPE_TC_ARBITER_TSAR,
	SCHED_NODE_TYPE_RATE_LIMITER,
	SCHED_NODE_TYPE_VPORT_TC,
	SCHED_NODE_TYPE_VPORTS_TC_TSAR,
};

struct mlx5_esw_sched_node {
	u32 ix;
	struct mlxdevm_rate_node devm;
	/* Bandwidth parameters. */
	u32 max_rate;
	u32 min_rate;
	/* A computed value indicating relative min_rate between node's children. */
	u32 bw_share;
	/* The parent node in the rate hierarchy. */
	struct mlx5_esw_sched_node *parent;
	/* Entry in the parent node's children list. */
	struct list_head entry;
	/* The type of this node in the rate hierarchy. */
	enum sched_node_type type;
	/* The eswitch this node belongs to. */
	struct mlx5_eswitch *esw;
	/* The children nodes of this node, empty list for leaf nodes. */
	struct list_head children;
	/* Valid only if this node is associated with a vport. */
	struct mlx5_vport *vport;
	/* Level in the hierarchy. The root node level is 1. */
	u8 level;
	/* Valid only when this node represents a traffic class. */
	u8 tc;
	/* Valid only for a TC arbiter node or vport TC arbiter. */
	u32 tc_bw[DEVLINK_RATE_TCS_MAX];

	/* sysfs group related fields */
	struct kobject kobj;
	u32 node_id;
	u32 num_vports;
	struct completion free_node_comp;
};

int mlx5_esw_qos_init(struct mlx5_eswitch *esw);
void mlx5_esw_qos_pre_cleanup(struct mlx5_core_dev *dev, int num_vfs);
void mlx5_esw_qos_cleanup(struct mlx5_eswitch *esw);

int
mlx5_esw_get_esw_and_vport(struct devlink *devlink, struct devlink_port *port,
			   struct mlx5_eswitch **esw, struct mlx5_vport **vport,
			   struct netlink_ext_ack *extack);

void mlx5_esw_qos_vport_disable(struct mlx5_vport *vport);
int mlx5_esw_qos_set_vport_min_rate(struct mlx5_vport *vport, u32 min_rate,
				    struct netlink_ext_ack *extack);
int mlx5_esw_qos_set_vport_max_rate(struct mlx5_vport *vport, u32 max_rate,
				    struct netlink_ext_ack *extack);
int esw_qos_set_node_min_rate(struct mlx5_esw_sched_node *node,
			      u32 min_rate, struct netlink_ext_ack *extack);
int esw_qos_sched_elem_config(struct mlx5_esw_sched_node *node, u32 max_rate, u32 bw_share,
			      struct netlink_ext_ack *extack);
void esw_qos_destroy_sched_node(struct mlx5_esw_sched_node *node,
				struct netlink_ext_ack *extack);

void esw_qos_lock(struct mlx5_eswitch *esw);
void esw_qos_unlock(struct mlx5_eswitch *esw);

static inline void esw_assert_qos_lock_held(struct mlx5_eswitch *esw)
{
	lockdep_assert_held(&esw->qos.domain->lock);
}

struct mlx5_esw_sched_node *
esw_qos_create_vports_sched_node(struct mlx5_eswitch *esw, u32 node_id,
				 struct netlink_ext_ack *extack);

int mlx5_esw_qos_set_vport_rate(struct mlx5_vport *evport, u32 max_rate, u32 min_rate);
bool mlx5_esw_qos_get_vport_rate(struct mlx5_vport *vport, u32 *max_rate, u32 *min_rate);
void mlx5_esw_qos_vport_disable(struct mlx5_vport *vport);

void mlx5_esw_qos_vport_qos_free(struct mlx5_vport *vport);
u32 mlx5_esw_qos_vport_get_sched_elem_ix(const struct mlx5_vport *vport);
struct mlx5_esw_sched_node *mlx5_esw_qos_vport_get_parent(const struct mlx5_vport *vport);

int mlx5_esw_qos_vport_update_sysfs_node(struct mlx5_eswitch *group_esw, u32 node_id,
					 struct mlx5_vport *vport);
int mlx5_esw_qos_set_sysfs_node_max_rate(struct mlx5_eswitch *esw,
					  struct mlx5_esw_sched_node *node,
					  u32 max_rate);
int mlx5_esw_qos_set_sysfs_node_min_rate(struct mlx5_eswitch *esw,
					 struct mlx5_esw_sched_node *node,
					 u32 min_rate);
void sysfs_esw_qos_destroy_node(struct mlx5_esw_sched_node *node,
				struct netlink_ext_ack *extack);

int mlx5_esw_devlink_rate_leaf_tx_share_set(struct devlink_rate *rate_leaf, void *priv,
					    u64 tx_share, struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_leaf_tx_max_set(struct devlink_rate *rate_leaf, void *priv,
					  u64 tx_max, struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_leaf_tc_bw_set(struct devlink_rate *rate_node,
					 void *priv,
					 u32 *tc_bw,
					 struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_node_tx_share_set(struct devlink_rate *rate_node, void *priv,
					    u64 tx_share, struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_node_tx_max_set(struct devlink_rate *rate_node, void *priv,
					  u64 tx_max, struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_node_new(struct devlink_rate *rate_node, void **priv,
				   struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_node_del(struct devlink_rate *rate_node, void *priv,
				   struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_leaf_parent_set(struct devlink_rate *devlink_rate,
					  struct devlink_rate *parent,
					  void *priv, void *parent_priv,
					  struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_node_parent_set(struct devlink_rate *devlink_rate,
					  struct devlink_rate *parent,
					  void *priv, void *parent_priv,
					  struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_node_tc_bw_set(struct devlink_rate *rate_node,
					 void *priv,
					 u32 *tc_bw,
					 struct netlink_ext_ack *extack);
int mlx5_esw_devm_rate_leaf_tc_bw_set(struct mlxdevm_rate *rate_leaf,
				      void *priv,
				      u32 *tc_bw,
				      struct netlink_ext_ack *extack);
#endif

#endif
