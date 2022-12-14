/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2019, Mellanox Technologies */

#include "mlx5_core.h"
#include "eswitch.h"
#include "meddev/sf.h"

struct devlink *mlx5_core_to_devlink(struct mlx5_core_dev *dev)
{
	struct mlx5_sf *sf;

	if (!mlx5_core_is_sf(dev))
		return priv_to_devlink(dev);

	sf = container_of(dev, struct mlx5_sf, dev);
	return priv_to_devlink(sf);
}

