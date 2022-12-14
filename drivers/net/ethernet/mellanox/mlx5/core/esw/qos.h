/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_ESW_QOS_H__
#define __MLX5_ESW_QOS_H__

#ifdef CONFIG_MLX5_ESWITCH

#define MLX5_ESW_QOS_SYSFS_GROUP_MAX_ID 255
#define MLX5_ESW_QOS_NON_SYSFS_GROUP (MLX5_ESW_QOS_SYSFS_GROUP_MAX_ID + 1)
#include "net/mlxdevm.h"

struct mlx5_esw_rate_group {
	struct mlx5_core_dev *dev;
	struct mlxdevm_rate_group devm;
	u32 tsar_ix;
	u32 max_rate;
	u32 min_rate;
	u32 bw_share;
	struct list_head list;

	/* sysfs group related fields */
	struct kobject kobj;
	u32 group_id;
	u32 num_vports;
};

int mlx5_esw_qos_set_vport_rate(struct mlx5_eswitch *esw, struct mlx5_vport *evport,
				u32 max_rate, u32 min_rate);
void mlx5_esw_qos_vport_disable(struct mlx5_eswitch *esw, struct mlx5_vport *vport);

int mlx5_esw_qos_vport_update_sysfs_group(struct mlx5_eswitch *esw, int vport_num,
					  u32 group_id);
int mlx5_esw_qos_set_sysfs_group_max_rate(struct mlx5_eswitch *esw,
					  struct mlx5_esw_rate_group *group,
					  u32 max_rate);
int mlx5_esw_qos_set_sysfs_group_min_rate(struct mlx5_eswitch *esw,
					  struct mlx5_esw_rate_group *group,
					  u32 min_rate);
struct mlx5_esw_rate_group *
esw_qos_create_rate_group(struct mlx5_eswitch *esw, u32 group_id,
			  struct netlink_ext_ack *extack);
int esw_qos_destroy_rate_group(struct mlx5_eswitch *esw,
			       struct mlx5_esw_rate_group *group,
			       struct netlink_ext_ack *extack);
int esw_qos_set_group_max_rate(struct mlx5_eswitch *esw,
			       struct mlx5_esw_rate_group *group,
			       u32 max_rate, struct netlink_ext_ack *extack);
int esw_qos_set_group_min_rate(struct mlx5_eswitch *esw, struct mlx5_esw_rate_group *group,
			       u32 min_rate, struct netlink_ext_ack *extack);
int
mlx5_esw_get_esw_and_vport(struct devlink *devlink, struct devlink_port *port,
			   struct mlx5_eswitch **esw, struct mlx5_vport **vport,
			   struct netlink_ext_ack *extack);
int esw_qos_vport_enable(struct mlx5_eswitch *esw, struct mlx5_vport *vport,
			 u32 max_rate, u32 bw_share, struct netlink_ext_ack *extack);
int esw_qos_set_vport_min_rate(struct mlx5_eswitch *esw, struct mlx5_vport *evport,
			       u32 min_rate, struct netlink_ext_ack *extack);
int esw_qos_set_vport_max_rate(struct mlx5_eswitch *esw, struct mlx5_vport *evport,
			       u32 max_rate, struct netlink_ext_ack *extack);
#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS

int mlx5_esw_devlink_rate_leaf_tx_share_set(struct devlink_rate *rate_leaf, void *priv,
					    u64 tx_share, struct netlink_ext_ack *extack);
int mlx5_esw_devlink_rate_leaf_tx_max_set(struct devlink_rate *rate_leaf, void *priv,
					  u64 tx_max, struct netlink_ext_ack *extack);
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
