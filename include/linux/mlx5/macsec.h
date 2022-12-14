/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2022 Mellanox Technologies. */

#ifndef MLX5_MACSEC_H
#define MLX5_MACSEC_H

int mlx5e_macsec_fs_add_roce_rule(struct net_device *ndev, const struct sockaddr *addr);

#endif /* MLX5_MACSEC_H */
