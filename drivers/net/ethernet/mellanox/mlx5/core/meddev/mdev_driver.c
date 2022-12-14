// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018-19 Mellanox Technologies

#include <linux/module.h>
#include <net/devlink.h>
#include <linux/mdev.h>

#include "mlx5_core.h"
#include "meddev/sf.h"

static int mlx5_meddev_probe(struct device *dev)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);

	return mlx5_sf_load(sf);
}

static void mlx5_meddev_remove(struct device *dev)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);

	mlx5_sf_unload(sf);
}

static struct mdev_driver mlx5_meddev_driver = {
	.name	= KBUILD_MODNAME,
	.probe	= mlx5_meddev_probe,
	.remove	= mlx5_meddev_remove,
};

int mlx5_meddev_register_driver(void)
{
	return mdev_register_driver(&mlx5_meddev_driver, THIS_MODULE);
}

void mlx5_meddev_unregister_driver(void)
{
	mdev_unregister_driver(&mlx5_meddev_driver);
}
