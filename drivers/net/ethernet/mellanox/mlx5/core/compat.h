/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2020 Mellanox Technologies */

#ifndef __MLX5_COMPAT__
#define __MLX5_COMPAT__

#ifdef CONFIG_MLX5_ESWITCH
#if defined(HAVE_SWITCHDEV_OPS) || defined(HAVE_SWITCHDEV_H_COMPAT)
int mlx5e_attr_get(struct net_device *dev, struct switchdev_attr *attr);
#endif
void mlx5e_rep_set_sysfs_attr(struct net_device *netdev);
int mlx5e_vport_rep_load_compat(struct mlx5e_priv *priv);
int mlx5e_vport_rep_unload_compat(struct mlx5e_priv *priv);
#else
void mlx5e_rep_set_sysfs_attr(struct net_device *netdev) {}
#endif /* CONFIG_MLX5_ESWITCH */

#endif /* __MLX5_COMPAT__ */
