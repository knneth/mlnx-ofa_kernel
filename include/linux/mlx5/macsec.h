/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. */

#ifndef MLX5_MACSEC_H
#define MLX5_MACSEC_H

#ifdef CONFIG_MLX5_EN_MACSEC
int mlx5e_macsec_add_roce_rule(struct net_device *ndev, const struct sockaddr *addr, u16 gid_idx);
void mlx5e_macsec_del_roce_rule(struct net_device *ndev, u16 gid_idx);
#endif
#endif /* MLX5_MACSEC_H */
