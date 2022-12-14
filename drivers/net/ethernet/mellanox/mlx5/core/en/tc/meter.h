/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_EN_FLOW_METER_H__
#define __MLX5_EN_FLOW_METER_H__

struct mlx5e_flow_meters;
struct mlx5_flow_attr;

struct mlx5e_flow_meter_aso_obj {
	struct list_head entry;
	int base_id;
	int total_meters;

	unsigned long meters_map[0]; /* must be at the end of this struct */
};

struct mlx5e_flow_meter_handle {
	struct mlx5e_flow_meters *flow_meters;
	struct mlx5e_flow_meter_aso_obj *meters_obj;
	u32 obj_id;
	u8 idx;

	int refcnt;
	struct hlist_node hlist;
	struct mlx5_flow_meter_params params;
};

struct mlx5e_meter_attr {
	struct mlx5_flow_meter_params params;
	struct mlx5e_flow_meter_handle *meter;
};

int mlx5e_aso_send_flow_meter_aso(struct mlx5_core_dev *mdev,
				  struct mlx5e_flow_meter_handle *meter,
				  struct mlx5_flow_meter_params *meter_params);

struct mlx5e_flow_meter_handle *mlx5e_alloc_flow_meter(struct mlx5_core_dev *dev);
void mlx5e_free_flow_meter(struct mlx5_core_dev *dev,
			   struct mlx5e_flow_meter_handle *meter);

int
mlx5e_flow_meter_send(struct mlx5_core_dev *mdev,
		      struct mlx5e_flow_meter_handle *meter,
		      struct mlx5_flow_meter_params *meter_params);

struct mlx5e_flow_meter_handle *
mlx5e_tc_meter_get(struct mlx5_core_dev *mdev, struct mlx5_flow_meter_params *params);
void
mlx5e_tc_meter_put(struct mlx5_core_dev *mdev, struct mlx5e_flow_meter_handle *meter);

struct mlx5_flow_table *
mlx5e_tc_meter_get_post_meter_ft(struct mlx5e_flow_meters *flow_meters);

struct mlx5e_flow_meters *
mlx5e_flow_meters_init(struct mlx5e_priv *priv,
		       enum mlx5_flow_namespace_type ns_type,
		       struct mlx5e_post_act *post_action);
void
mlx5e_flow_meters_cleanup(struct mlx5e_flow_meters *flow_meters);

#endif /* __MLX5_EN_FLOW_METER_H__ */
