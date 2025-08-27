/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies Ltd. */

#ifndef MLX5_DEVM_H
#define MLX5_DEVM_H

#if IS_ENABLED(CONFIG_MLXDEVM)
#include <net/mlxdevm.h>
#include <linux/rwsem.h>
#include <devl_internal.h>
#include "mlx5_devm_driver_params.h"
#include "eswitch.h"

struct mlx5_devm_device {
	struct mlxdevm device;
	struct mlx5_core_dev *dev;
	struct list_head list;
	struct xarray devm_sfs;
};

enum mlx5_mlxdevm_resource_id {
	MLX5_DEVM_RES_MAX_LOCAL_SFS = 1,
	MLX5_DEVM_RES_MAX_EXTERNAL_SFS,

	__MLX5_DEVM_ID_RES_MAX,
	MLX5_DEVM_ID_RES_MAX = __MLX5_DEVM_ID_RES_MAX - 1,
};

struct mlx5_devm_device *mlx5_devm_device_get(struct mlx5_core_dev *dev);
struct mlx5_core_dev *mlx5_devm_core_dev_get(struct mlxdevm *devm_dev);
int mlx5_devm_register(struct mlx5_core_dev *dev);
void mlx5_devm_unregister(struct mlx5_core_dev *dev);
#if 0
int mlx5_devm_traps_register(struct mlxdevm *mlxdevm);
void mlx5_devm_traps_unregister(struct mlxdevm *mlxdevm);
#endif
int mlx5_devm_params_register(struct mlxdevm *mlxdevm);
void mlx5_devm_params_unregister(struct mlxdevm *mlxdevm);
int mlx5_devm_affinity_get_param(struct mlx5_core_dev *dev, struct cpumask *mask);
int mlx5_devm_affinity_get_weight(struct mlx5_core_dev *dev);
void mlx5_devm_params_publish(struct mlx5_core_dev *dev);
void mlx5_devm_rate_nodes_destroy(struct mlx5_core_dev *dev);
bool mlx5_devm_is_devm_sf(struct mlx5_core_dev *dev, u32 sfnum);
void mlx5_devm_sfs_clean(struct mlx5_core_dev *dev);
int mlx5_pf_vf_devm_port_init(struct mlx5_eswitch *esw, struct mlx5_vport *vport);
int mlx5_sf_devm_port_init(struct mlx5_eswitch *esw, struct mlx5_vport *vport,
			   u32 controller, u32 sfnum);
void mlx5_devm_port_cleanup(struct mlx5_eswitch *esw, struct mlx5_vport *vport);

#else
static inline int mlx5_devm_register(struct mlx5_core_dev *dev)
{
	return 0;
}

static inline void mlx5_devm_unregister(struct mlx5_core_dev *dev)
{
}

static int mlx5_devm_traps_register(struct mlxdevm *mlxdevm)
{
	return 0;
}

static void mlx5_devm_traps_unregister(struct mlxdevm *mlxdevm)
{
}

static int mlx5_devm_params_register(struct mlxdevm *mlxdevm)
{
	return 0;
}

static void mlx5_devm_params_unregister(struct mlxdevm *mlxdevm)
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

static void mlx5_devm_rate_nodes_destroy(struct mlx5_core_dev *dev)
{
}

static int mlx5_pf_vf_devm_port_init(struct mlx5_eswitch *esw, struct mlx5_vport *vport)
{
	return 0;
}

int mlx5_sf_devm_port_init(struct mlx5_eswitch *esw, struct mlx5_vport *vport,
			   u32 controller, u32 sfnum)
{
	return 0;
}

static void mlx5_devm_port_cleanup(struct mlx5_eswitch *esw, struct mlx5_vport *vport);
{
}
#endif
#endif
