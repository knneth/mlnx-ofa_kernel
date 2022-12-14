/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies Ltd */

#ifndef __MLX5_SF_CFG_DRV_H__
#define __MLX5_SF_CFG_DRV_H__

#ifdef CONFIG_MLX5_SF_CFG
int mlx5_sf_cfg_driver_register(void);
void mlx5_sf_cfg_driver_unregister(void);
#else
static inline int mlx5_sf_cfg_driver_register(void)
{
	return 0;
}

static inline void mlx5_sf_cfg_driver_unregister(void)
{
}

#endif

#endif
