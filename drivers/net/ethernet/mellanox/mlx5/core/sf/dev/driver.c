// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2020 Mellanox Technologies Ltd */

#include <linux/mlx5/driver.h>
#include <linux/mlx5/device.h>
#include <linux/mlx5/eswitch.h>
#include "mlx5_core.h"
#include "mlx5_devm.h"
#include "dev.h"
#include "devlink.h"
#include "cfg_driver.h"

static int mlx5_sf_dev_probe(struct auxiliary_device *adev, const struct auxiliary_device_id *id)
{
	struct mlx5_sf_dev *sf_dev = container_of(adev, struct mlx5_sf_dev, adev);
	struct mlx5_core_dev *mdev;
	struct devlink *devlink;
	int err;

	devlink = mlx5_devlink_alloc(&adev->dev);
	if (!devlink)
		return -ENOMEM;

	mdev = devlink_priv(devlink);
	mdev->device = &adev->dev;
	mdev->pdev = sf_dev->parent_mdev->pdev;
	mdev->bar_addr = sf_dev->bar_base_addr;
	mdev->iseg_base = sf_dev->bar_base_addr;
	mdev->coredev_type = MLX5_COREDEV_SF;
	mdev->priv.parent_mdev = sf_dev->parent_mdev;
	mdev->priv.adev_idx = adev->id;
	sf_dev->mdev = mdev;

	/* Only local SFs do light probe */
	if (MLX5_ESWITCH_MANAGER(sf_dev->parent_mdev) &&
	    !mlx5_devm_is_devm_sf(sf_dev->parent_mdev, sf_dev->sfnum))
		mlx5_dev_set_lightweight(mdev);

	err = mlx5_mdev_init(mdev, MLX5_DEFAULT_PROF);
	if (err) {
		mlx5_core_warn(mdev, "mlx5_mdev_init on err=%d\n", err);
		goto mdev_err;
	}

#ifdef CONFIG_MLX5_SF_CFG
	mdev->disable_en = sf_dev->disable_netdev;
	mdev->disable_fc = sf_dev->disable_fc;
	mdev->cmpl_eq_depth = sf_dev->cmpl_eq_depth;
	mdev->async_eq_depth = sf_dev->async_eq_depth;
	mdev->max_cmpl_eq_count = sf_dev->max_cmpl_eqs;
#endif

	mdev->iseg = ioremap(mdev->iseg_base, sizeof(*mdev->iseg));
	if (!mdev->iseg) {
		mlx5_core_warn(mdev, "remap error\n");
		err = -ENOMEM;
		goto remap_err;
	}

	if (MLX5_ESWITCH_MANAGER(sf_dev->parent_mdev))
		err = mlx5_init_one_light(mdev);
	else
		err = mlx5_init_one(mdev);
	if (err) {
		mlx5_core_warn(mdev, "mlx5_init_one err=%d\n", err);
		goto init_one_err;
	}
	devlink_register(devlink);
	return 0;

init_one_err:
	iounmap(mdev->iseg);
remap_err:
	mlx5_mdev_uninit(mdev);
mdev_err:
	mlx5_devlink_free(devlink);
	return err;
}

static void mlx5_sf_dev_remove(struct auxiliary_device *adev)
{
	struct mlx5_sf_dev *sf_dev = container_of(adev, struct mlx5_sf_dev, adev);
	struct devlink *devlink = priv_to_devlink(sf_dev->mdev);

	mlx5_drain_health_wq(sf_dev->mdev);
	set_bit(MLX5_BREAK_FW_WAIT, &sf_dev->mdev->intf_state);
	devlink_unregister(devlink);
	if (mlx5_dev_is_lightweight(sf_dev->mdev))
		mlx5_uninit_one_light(sf_dev->mdev);
	else
		mlx5_uninit_one(sf_dev->mdev);

	/* health work might still be active, and it needs pci bar in
	 * order to know the NIC state. Therefore, drain the health WQ
	 * before removing the pci bars
	 */
	iounmap(sf_dev->mdev->iseg);
	mlx5_mdev_uninit(sf_dev->mdev);
	mlx5_devlink_free(devlink);
}

static void mlx5_sf_dev_shutdown(struct auxiliary_device *adev)
{
	struct mlx5_sf_dev *sf_dev = container_of(adev, struct mlx5_sf_dev, adev);

	mlx5_unload_one(sf_dev->mdev, false);
}

static const struct auxiliary_device_id mlx5_sf_dev_id_table[] = {
	{ .name = MLX5_ADEV_NAME "." MLX5_SF_DEV_ID_NAME, },
	{ },
};

MODULE_DEVICE_TABLE(auxiliary, mlx5_sf_dev_id_table);

static struct auxiliary_driver mlx5_sf_driver = {
	.name = MLX5_SF_DEV_ID_NAME,
	.probe = mlx5_sf_dev_probe,
	.remove = mlx5_sf_dev_remove,
	.shutdown = mlx5_sf_dev_shutdown,
	.id_table = mlx5_sf_dev_id_table,
};

int mlx5_sf_driver_register(void)
{
	int err;

	err = mlx5_sf_cfg_driver_register();
	if (err)
		return err;

	err = auxiliary_driver_register(&mlx5_sf_driver);
	if (err)
		goto err;
	return 0;
err:
	mlx5_sf_cfg_driver_unregister();
	return err;
}

void mlx5_sf_driver_unregister(void)
{
	auxiliary_driver_unregister(&mlx5_sf_driver);
	mlx5_sf_cfg_driver_unregister();
}
