/* SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause) */
/*
 * Copyright (c) 2018 Mellanox Technologies. All rights reserved.
 */

#ifndef _MLX5_DEVCOM_
#define _MLX5_DEVCOM_

bool mlx5_devcom_comp_is_ready(struct mlx5_devcom_comp_dev *devcom);
bool mlx5_devcom_for_each_peer_begin(struct mlx5_devcom_comp_dev *devcom);
void mlx5_devcom_for_each_peer_end(struct mlx5_devcom_comp_dev *devcom);
void *mlx5_devcom_get_next_peer_data(struct mlx5_devcom_comp_dev *devcom,
				     struct mlx5_devcom_comp_dev **pos);

#define mlx5_devcom_for_each_peer_entry(devcom, data, pos)                    \
	for (pos = NULL, data = mlx5_devcom_get_next_peer_data(devcom, &pos); \
	     data;                                                            \
	     data = mlx5_devcom_get_next_peer_data(devcom, &pos))

#endif /* _MLX5_DEVCOM_ */
