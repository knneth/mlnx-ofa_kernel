/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies Ltd. */

#ifndef MLX5_ESW_DEVM_H
#define MLX5_ESW_DEVM_H

#include <linux/netdevice.h>
#include <linux/mlx5/driver.h>
#include "mlx5_devm.h"

#if IS_ENABLED(CONFIG_MLXDEVM)
int mlx5_devm_port_register(struct mlx5_eswitch *esw, struct mlx5_vport *vport);
void mlx5_devm_port_unregister(struct mlx5_vport *vport);
#else
static inline int mlx5_devm_sf_port_register(struct mlx5_core_dev *dev, u16 vport_num,
			       u32 contoller, u32 sfnum, struct devlink_port *dl_port)
{
	return 0;
}

static inline void mlx5_devm_sf_port_unregister(struct mlx5_core_dev *dev, u16 vport_num)
{
}

#endif

#endif
