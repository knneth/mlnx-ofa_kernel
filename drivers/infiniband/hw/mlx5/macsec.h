/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. */

#ifndef __MLX5_MACSEC_H__
#define __MLX5_MACSEC_H__

#include <rdma/ib_cache.h>
#include <rdma/ib_addr.h>
#include "mlx5_ib.h"

#ifdef CONFIG_MLX5_EN_MACSEC
#include <net/macsec.h>

struct mlx5_reserved_gids;

int add_gid_macsec_operations(const struct ib_gid_attr *attr);
void del_gid_macsec_operations(const struct ib_gid_attr *attr);
int macsec_alloc_gids(struct mlx5_ib_dev *dev);
void macsec_dealloc_gids(struct mlx5_ib_dev *dev);
#else
static inline int add_gid_macsec_operations(const struct ib_gid_attr *attr) { return 0; }
static inline void del_gid_macsec_operations(const struct ib_gid_attr *attr) {}
static inline int macsec_alloc_gids(struct mlx5_ib_dev *dev) { return 0; }
static inline void macsec_dealloc_gids(struct mlx5_ib_dev *dev) {}
#endif
#endif /* __MLX5_MACSEC_H__ */
