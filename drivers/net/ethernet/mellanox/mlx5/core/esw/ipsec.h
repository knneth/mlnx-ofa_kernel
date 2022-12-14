/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2020 Mellanox Technologies. */

#ifndef __ML5_ESW_IPSEC_H__
#define __ML5_ESW_IPSEC_H__

#include "eswitch.h"

enum mlx5_esw_ipsec_table_type {
	MLX5_ESW_IPSEC_FT_RX_CRYPTO,
	MLX5_ESW_IPSEC_FT_RX_DECAP,
	MLX5_ESW_IPSEC_FT_TX_CRYPTO,
};

#if IS_ENABLED(CONFIG_MLX5_EN_IPSEC)
int mlx5_esw_ipsec_create(struct mlx5_eswitch *esw);
void mlx5_esw_ipsec_destroy(struct mlx5_eswitch *esw);
struct mlx5_flow_table *mlx5_esw_ipsec_get_table(struct mlx5_eswitch *esw, enum mlx5_esw_ipsec_table_type type);
int mlx5_esw_ipsec_get_refcnt(struct mlx5_eswitch *esw);
void mlx5_esw_ipsec_put_refcnt(struct mlx5_eswitch *esw);
bool mlx5_esw_ipsec_try_hold(struct mlx5_eswitch *esw);
void mlx5_esw_ipsec_release(struct mlx5_eswitch *esw);
#else /* CONFIG_MLX5_EN_IPSEC */

static inline struct mlx5_flow_table *mlx5_esw_ipsec_get_table(struct mlx5_eswitch *esw,
							       enum mlx5_esw_ipsec_table_type type)
{
	return NULL;
}
static inline int mlx5_esw_ipsec_create(struct mlx5_eswitch *esw) { return 0; }
static inline void mlx5_esw_ipsec_destroy(struct mlx5_eswitch *esw) {}
static inline int mlx5_esw_ipsec_get_refcnt(struct mlx5_eswitch *esw) { return -EOPNOTSUPP; }
static inline void mlx5_esw_ipsec_put_refcnt(struct mlx5_eswitch *esw) { return; }
static inline bool mlx5_esw_ipsec_try_hold(struct mlx5_eswitch *esw) { return true; }
static inline void mlx5_esw_ipsec_release(struct mlx5_eswitch *esw) { return; }
#endif /* CONFIG_MLX5_EN_IPSEC */

#endif /* __ML5_ESW_IPSEC_H__ */
