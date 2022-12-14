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
};

enum mlx5_devm_param_id {
	MLX5_DEVM_PARAM_ID_CPU_AFFINITY,
};

struct mlx5_devm_device *mlx5_devm_device_get(struct mlx5_core_dev *dev);
int mlx5_devm_register(struct mlx5_core_dev *dev);
void mlx5_devm_unregister(struct mlx5_core_dev *dev);
void mlx5_devm_affinity_get_param(struct mlx5_core_dev *dev);
void mlx5_devm_params_publish(struct mlx5_core_dev *dev);

#else
static inline int mlx5_devm_register(struct mlx5_core_dev *dev)
{
	return 0;
}

static inline void mlx5_devm_unregister(struct mlx5_core_dev *dev)
{
}

static inline void mlx5_devm_affinity_get_param(struct mlx5_core_dev *dev)
{
}

static inline void mlx5_devm_params_publish(struct mlx5_core_dev *dev)
{
}
#endif
#endif
