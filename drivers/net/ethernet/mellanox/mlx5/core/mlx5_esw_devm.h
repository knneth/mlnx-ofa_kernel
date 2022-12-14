/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies Ltd. */

#ifndef MLX5_ESW_DEVM_H
#define MLX5_ESW_DEVM_H

#include <linux/netdevice.h>
#include <linux/mlx5/driver.h>
#include "mlx5_devm.h"

#if IS_ENABLED(CONFIG_MLXDEVM)
struct mlx5_devm_port {
	struct mlxdevm_port port;
	struct list_head list;
	unsigned int port_index;
	u32 sfnum;
	u16 vport_num;
};

int mlx5_devm_sf_port_register(struct mlx5_core_dev *dev, u16 vport_num,
			       u32 contoller, u32 sfnum);
void mlx5_devm_sf_port_unregister(struct mlx5_core_dev *dev, u16 vport_num);
void mlx5_devm_sf_port_type_eth_set(struct mlx5_core_dev *dev, u16 vport_num,
				    struct net_device *ndev);
u32 mlx5_devm_sf_vport_to_sfnum(struct mlx5_core_dev *dev, u16 vport_num);
u32 mlx5_devm_sf_vport_to_controller(struct mlx5_core_dev *dev, u16 vport_num);
#else
static inline int mlx5_devm_sf_port_register(struct mlx5_core_dev *dev,
					     u32 controller,
					     u16 vport_num, u32 sfnum)
{
	return 0;
}

static inline void mlx5_devm_sf_port_unregister(struct mlx5_core_dev *dev, u16 vport_num)
{
}

static inline void mlx5_devm_sf_port_type_eth_set(struct mlx5_core_dev *dev, u16 vport_num,
						  struct net_device *ndev)
{
}
#endif

#endif
