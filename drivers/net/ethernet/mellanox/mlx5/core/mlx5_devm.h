/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies Ltd. */

#ifndef MLX5_DEVM_H
#define MLX5_DEVM_H

#if IS_ENABLED(CONFIG_MLXDEVM)
#include <net/mlxdevm.h>
#include <linux/rwsem.h>

struct mlx5_devm_device {
	struct mlxdevm device;
	struct list_head port_list;
	struct mlx5_core_dev *dev;
	struct list_head list;
	struct rw_semaphore port_list_rwsem;
	struct xarray devm_sfs;
};

enum mlx5_devm_param_id {
	MLX5_DEVM_PARAM_ID_CPU_AFFINITY,
};

struct mlx5_devm_device *mlx5_devm_device_get(struct mlx5_core_dev *dev);
int mlx5_devm_register(struct mlx5_core_dev *dev);
void mlx5_devm_unregister(struct mlx5_core_dev *dev);
int mlx5_devm_affinity_get_param(struct mlx5_core_dev *dev, struct cpumask *mask);
int mlx5_devm_affinity_get_weight(struct mlx5_core_dev *dev);
void mlx5_devm_params_publish(struct mlx5_core_dev *dev);
void mlx5_devm_rate_nodes_destroy(struct mlx5_core_dev *dev);
bool mlx5_devm_is_devm_sf(struct mlx5_core_dev *dev, u32 sfnum);
void mlx5_devm_sfs_clean(struct mlx5_core_dev *dev);
void mlx5_devm_params_publish(struct mlx5_core_dev *dev);

#else
static inline int mlx5_devm_register(struct mlx5_core_dev *dev)
{
	return 0;
}

static inline void mlx5_devm_unregister(struct mlx5_core_dev *dev)
{
}
static inline bool
mlx5_devm_is_devm_sf(struct mlx5_core_dev *dev, u32 sfnum) { return false; }

static inline void mlx5_devm_params_publish(struct mlx5_core_dev *dev)
{
}

static inline void mlx5_devm_sfs_clean(struct mlx5_core_dev *dev)
{
}

static inline int
mlx5_devm_affinity_get_param(struct mlx5_core_dev *dev, struct cpumask *mask)
{
	return 0;
}

static inline int
mlx5_devm_affinity_get_weight(struct mlx5_core_dev *dev)
{
	return 0;
}

static inline void mlx5_devm_params_publish(struct mlx5_core_dev *dev)
{
}
#endif

#ifdef CONFIG_MLX5_ESWITCH
int mlx5_devm_sf_port_new(struct mlxdevm *devm_dev,
			  const struct mlxdevm_port_new_attrs *attrs,
			  struct netlink_ext_ack *extack,
			  unsigned int *new_port_index);
int mlx5_devm_sf_port_del(struct mlxdevm *devm_dev,
			  unsigned int port_index,
			  struct netlink_ext_ack *extack);
int mlx5_devm_sf_port_fn_state_get(struct mlxdevm_port *port,
				   enum mlxdevm_port_fn_state *state,
				   enum mlxdevm_port_fn_opstate *opstate,
				   struct netlink_ext_ack *extack);
int mlx5_devm_sf_port_fn_state_set(struct mlxdevm_port *port,
				   enum mlxdevm_port_fn_state state,
				   struct netlink_ext_ack *extack);
int mlx5_devm_sf_port_fn_hw_addr_get(struct mlxdevm_port *port,
				     u8 *hw_addr, int *hw_addr_len,
				     struct netlink_ext_ack *extack);
int mlx5_devm_sf_port_function_trust_get(struct mlxdevm_port *port,
					 bool *trusted,
					 struct netlink_ext_ack *extack);
int mlx5_devm_sf_port_fn_hw_addr_set(struct mlxdevm_port *port,
				     const u8 *hw_addr, int hw_addr_len,
				     struct netlink_ext_ack *extack);
int mlx5_devm_sf_port_function_trust_set(struct mlxdevm_port *port,
					 bool trusted,
					 struct netlink_ext_ack *extack);
int mlx5_devm_sf_port_fn_cap_get(struct mlxdevm_port *port,
				 struct mlxdevm_port_fn_cap *cap,
				 struct netlink_ext_ack *extack);
int mlx5_devm_sf_port_fn_cap_set(struct mlxdevm_port *port,
				 const struct mlxdevm_port_fn_cap *cap,
				 struct netlink_ext_ack *extack);
int mlx5_devm_rate_leaf_get(struct mlxdevm_port *port,
			    u64 *tx_max, u64 *tx_share, char **group,
			    struct netlink_ext_ack *extack);
int mlx5_devm_rate_leaf_tx_max_set(struct mlxdevm_port *port,
				   u64 tx_max, struct netlink_ext_ack *extack);
int mlx5_devm_rate_leaf_tx_share_set(struct mlxdevm_port *port,
				     u64 tx_share, struct netlink_ext_ack *extack);
int mlx5_devm_rate_leaf_group_set(struct mlxdevm_port *port,
				  const char *group, struct netlink_ext_ack *extack);
int mlx5_devm_rate_node_tx_share_set(struct mlxdevm *devm_dev, const char *group_name,
				     u64 tx_share, struct netlink_ext_ack *extack);
int mlx5_devm_rate_node_tx_max_set(struct mlxdevm *devm_dev, const char *group_name,
				   u64 tx_max, struct netlink_ext_ack *extack);
int mlx5_devm_rate_node_del(struct mlxdevm *devm_dev, const char *group_name,
			    struct netlink_ext_ack *extack);
int mlx5_devm_rate_node_new(struct mlxdevm *devm_dev, const char *group_name,
			    struct netlink_ext_ack *extack);
#endif
#endif
