/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies. */

#ifndef __MLX5_FLOW_METERS_H__
#define __MLX5_FLOW_METERS_H__

#include "en/aso.h"

struct mlx5e_flow_meter_aso_obj {
	struct list_head entry;
	int base_id;
	int total_meters;

	unsigned long meters_map[0]; /* must be at the last of this struct */
};

struct mlx5e_flow_meters {
	struct mlx5e_aso *aso;
	int log_granularity;

	struct mutex sync_lock; /* protect flow meter operations */
	struct list_head partial_list;
	struct list_head full_list;
};

struct mlx5e_flow_meter_aso_obj *mlx5e_alloc_flow_meter(struct mlx5_core_dev *mdev,
							u32 *obj_id, int *idx);
void mlx5e_free_flow_meter(struct mlx5_core_dev *mdev,
			   struct mlx5e_flow_meter_aso_obj *meters_obj,
			   u32 obj_id, int idx);
int mlx5e_aso_send_flow_meter_aso(struct mlx5_core_dev *mdev, u32 obj_id,
				  u32 meter_id, int xps, u64 rate, u64 burst);

int mlx5e_flow_meters_init(struct mlx5e_priv *priv);
void mlx5e_flow_meters_cleanup(struct mlx5e_priv *priv);

#endif /* __MLX5_FLOW_METERS_H__ */
