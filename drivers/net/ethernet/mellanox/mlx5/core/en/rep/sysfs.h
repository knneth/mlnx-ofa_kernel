/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 NVIDIA Corporation. */

#ifndef __MLX5_EN_REP_SYSFS_H__
#define __MLX5_EN_REP_SYSFS_H__

#include "en_rep.h"

void mlx5_rep_sysfs_init(struct mlx5e_rep_priv *rpriv);
void mlx5_rep_sysfs_cleanup(struct mlx5e_rep_priv *rpriv);

#endif
