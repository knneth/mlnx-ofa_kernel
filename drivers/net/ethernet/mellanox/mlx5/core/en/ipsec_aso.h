/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies. */

#include "en.h"
#include "en_accel/ipsec.h"

#ifndef __MLX5_EN_IPSEC_ASO_H__
#define __MLX5_EN_IPSEC_ASO_H__

struct mlx5e_ipsec_aso;

enum {
	MLX5E_IPSEC_FLAG_ARM_SOFT = BIT(0),
	MLX5E_IPSEC_FLAG_SET_SOFT = BIT(1),
	MLX5E_IPSEC_FLAG_SET_CNT_BIT31  = BIT(3),
	MLX5E_IPSEC_FLAG_CLEAR_SOFT = BIT(4),
	MLX5E_IPSEC_FLAG_ARM_ESN_EVENT = BIT(5),
};

enum {
	MLX5E_IPSEC_ASO_SOFT_ARM = BIT(0),
	MLX5E_IPSEC_ASO_HARD_ARM = BIT(1),
	MLX5E_IPSEC_ASO_REMOVE_FLOW_ENABLE = BIT(2),
	MLX5E_IPSEC_ASO_ESN_ARM = BIT(3),
};

struct mlx5e_ipsec_aso_in {
	u32 comparator;
	u32 obj_id;
	u8 flags;
	u8 mode;
};

struct mlx5e_ipsec_aso_out {
	u32 mode_param;
	u32 hard_cnt;
	u32 soft_cnt;
	u8 event_arm;
};

struct mlx5e_ipsec_aso *mlx5e_ipsec_aso_init(struct mlx5_core_dev *mdev);
void mlx5e_ipsec_aso_cleanup(struct mlx5e_ipsec_aso *aso);
int mlx5e_ipsec_aso_query(struct mlx5e_ipsec_aso *aso, struct mlx5e_ipsec_aso_in *in,
			  struct mlx5e_ipsec_aso_out *out);
int mlx5e_ipsec_aso_set(struct mlx5e_ipsec_aso *aso, struct mlx5e_ipsec_aso_in *in,
			struct mlx5e_ipsec_aso_out *out);
#endif
