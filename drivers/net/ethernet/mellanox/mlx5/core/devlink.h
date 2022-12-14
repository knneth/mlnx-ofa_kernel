/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2019, Mellanox Technologies */

#ifndef __MLX5_DEVLINK_H__
#define __MLX5_DEVLINK_H__

#include <net/devlink.h>
#include "eswitch.h"

struct mlx5_core_dev;

struct devlink *mlx5_core_to_devlink(struct mlx5_core_dev *dev);

#endif /* __MLX5_DEVLINK_H__ */
