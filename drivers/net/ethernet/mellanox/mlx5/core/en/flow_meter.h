/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_EN_FLOW_METERS_H__
#define __MLX5_EN_FLOW_METERS_H__

#include "aso.h"

#define MLX5E_MAX_METERS_PER_RULE 3

#define packet_color_to_reg { \
	.mfield = MLX5_ACTION_IN_FIELD_METADATA_REG_C_5, \
	.moffset = 0, \
	.mlen = 1, \
	.soffset = MLX5_BYTE_OFF(fte_match_param, \
				 misc_parameters_2.metadata_reg_c_5) + 3, \
}

struct mlx5e_flow_meters;

struct mlx5e_flow_meter_aso_obj {
	struct list_head entry;
	int base_id;
	int total_meters;

	unsigned long meters_map[0]; /* must be at the end of this struct */
};

struct mlx5_meter_handle {
	struct mlx5e_flow_meters *flow_meters;
	struct mlx5e_flow_meter_aso_obj *meters_obj;
	u32 obj_id;
	u8 idx;

	int refcnt;
	struct hlist_node hlist;
	struct mlx5_flow_meter_params params;
};

struct mlx5_flow_attr;

struct mlx5_meter_attr {
	union {
		struct mlx5_post_action_handle *post_action;
		struct mlx5_meter_handle *handle;
	} meters[MLX5E_MAX_METERS_PER_RULE];
	struct mlx5_post_action_handle *last_post_action;
	struct mlx5_flow_attr *pre_attr;
};

int mlx5e_aso_send_flow_meter_aso(struct mlx5_core_dev *mdev,
				  struct mlx5_meter_handle *meter,
				  struct mlx5_flow_meter_params *meter_params);

struct mlx5_meter_handle *mlx5e_alloc_flow_meter(struct mlx5_core_dev *dev);
void mlx5e_free_flow_meter(struct mlx5_core_dev *dev,
			   struct mlx5_meter_handle *meter);

struct mlx5_meter_handle *
mlx5e_get_flow_meter(struct mlx5_core_dev *mdev, struct mlx5_flow_meter_params *params);
void mlx5e_put_flow_meter(struct mlx5_core_dev *mdev, struct mlx5_meter_handle *meter);

struct mlx5_post_action_handle *
mlx5e_fill_flow_meter_post_action(struct mlx5e_priv *priv,
				  struct mlx5_flow_attr *attr,
				  struct mlx5_post_action_handle *last);
void mlx5e_free_flow_meter_post_action(struct mlx5e_priv *priv,
				       struct mlx5_flow_attr *attr);
struct mlx5_flow_handle *
mlx5e_tc_meter_offload(struct mlx5_core_dev *mdev,
		       struct mlx5_flow_spec *spec, struct mlx5_flow_attr *attr);
void mlx5e_tc_meter_unoffload(struct mlx5_core_dev *mdev, struct mlx5_flow_handle *rule,
			      struct mlx5_flow_attr *attr);

struct mlx5e_flow_meters *
mlx5e_flow_meters_init(struct mlx5e_priv *priv, enum mlx5_flow_namespace_type ns_type);
void mlx5e_flow_meters_cleanup(struct mlx5e_flow_meters *flow_meters);

#endif /* __MLX5_EN_FLOW_METERS_H__ */
