/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies. */

#include "en.h"
#include "en_accel/ipsec.h"
#include "aso.h"

#ifndef __MLX5_EN_IPSEC_ASO_H__
#define __MLX5_EN_IPSEC_ASO_H__

struct mlx5e_ipsec_aso {
	struct mlx5e_aso *aso;
	struct mlx5_core_mkey mkey;
	dma_addr_t dma_addr;
	void *ctx;
	size_t size;
};

enum {
	MLX5_IPSEC_ASO_REMOVE_FLOW_PKT_CNT_OFFSET,
	MLX5_IPSEC_ASO_REMOVE_FLOW_SOFT_LFT_OFFSET,
};

int mlx5e_ipsec_aso_query(struct mlx5e_priv *priv, u32 obj_id,
			  u32 *hard_cnt, u32 *soft_cnt,
			  u8 *event_arm, u32 *mode_param);
int mlx5e_ipsec_aso_set(struct mlx5e_priv *priv, u32 obj_id, u8 flags,
			u32 comparator, u32 *hard_cnt, u32 *soft_cnt,
			u8 *event_arm, u32 *mode_param);

int mlx5e_ipsec_aso_setup(struct mlx5e_priv *priv);
void mlx5e_ipsec_aso_cleanup(struct mlx5e_priv *priv);
#endif
