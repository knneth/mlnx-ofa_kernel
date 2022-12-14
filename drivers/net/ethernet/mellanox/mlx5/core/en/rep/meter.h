/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 NVIDIA Corporation. */

#ifndef __MLX5_EN_REP_METER_H__
#define __MLX5_EN_REP_METER_H__

#include "en_rep.h"

void
mlx5_rep_destroy_miss_meter(struct mlx5_core_dev *dev, struct mlx5e_rep_priv *rep_priv);
int
mlx5_rep_set_miss_meter(struct mlx5_core_dev *dev, struct mlx5e_rep_priv *rep_priv,
			u16 vport, u64 rate, u64 burst);
int mlx5_rep_get_miss_meter_data(struct mlx5_core_dev *dev, struct mlx5e_rep_priv *rep_priv,
				 int data_type, u64 *data);

#endif
