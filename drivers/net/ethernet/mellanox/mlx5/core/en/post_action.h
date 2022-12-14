/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_POST_ACTION_H__
#define __MLX5_POST_ACTION_H__

struct mlx5_flow_attr;
struct mlx5e_priv;
struct mlx5e_tc_mod_hdr_acts;

struct mlx5_post_action *
mlx5_post_action_init(struct mlx5_fs_chains *chains, struct mlx5_core_dev *dev,
		      enum mlx5_flow_namespace_type ns_type);

void
mlx5_post_action_destroy(struct mlx5_post_action *post_action);

struct mlx5_post_action_handle *
mlx5_post_action_add(struct mlx5e_priv *priv, struct mlx5_post_action *post_action,
		     struct mlx5_flow_attr *attr);

void
mlx5_post_action_del(struct mlx5e_priv *priv, struct mlx5_post_action *post_action,
		     struct mlx5_post_action_handle *handle);

struct mlx5_flow_table *
mlx5_post_action_get_ft(struct mlx5_post_action *post_action);

int
mlx5_post_action_set_handle(struct mlx5_core_dev *dev,
			    struct mlx5_post_action_handle *handle,
			    struct mlx5e_tc_mod_hdr_acts *acts);

#endif /* __MLX5_POST_ACTION_H__ */
