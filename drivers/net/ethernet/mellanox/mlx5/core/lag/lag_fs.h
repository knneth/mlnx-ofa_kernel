// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES.

#ifndef __MLX5_LAG_FS_H__
#define __MLX5_LAG_FS_H__

#include "lag.h"
#include "lib/fs_ttc.h"

struct lag_tracker;

struct mlx5_lag_definer {
	struct mlx5_flow_definer *definer;
	struct mlx5_flow_table *ft;
	struct mlx5_flow_group *fg;
	struct mlx5_flow_handle *rules[MLX5_MAX_PORTS];
};

struct mlx5_lag_ttc {
	struct mlx5_ttc_table *ttc;
	struct mlx5_lag_definer *definers[MLX5_NUM_TT];
};

struct mlx5_lag_steering {
	DECLARE_BITMAP(tt_map, MLX5_NUM_TT);
	bool   tunnel;
	struct mlx5_lag_ttc outer;
	struct mlx5_lag_ttc inner;
};

#ifdef CONFIG_MLX5_ESWITCH

int mlx5_lag_modify_port_selection(struct mlx5_lag *ldev, u8 port1, u8 port2);
void mlx5_lag_destroy_port_selection(struct mlx5_lag *ldev);
int mlx5_lag_create_port_selection(struct mlx5_lag *ldev,
				   struct lag_tracker *tracker);

#else /* CONFIG_MLX5_ESWITCH */
static inline int mlx5_lag_create_port_selection(struct mlx5_lag *ldev,
						 struct lag_tracker *tracker)
{
	return 0;
}

static inline int mlx5_lag_modify_port_selection(struct mlx5_lag *ldev, u8 port1,
						 u8 port2)
{
	return 0;
}

static inline void mlx5_lag_destroy_port_selection(struct mlx5_lag *ldev) {}
#endif /* CONFIG_MLX5_ESWITCH */
#endif /* __MLX5_LAG_FS_H__ */
