// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include <linux/mlx5/driver.h>
#include <net/devlink.h>
#include <net/mlxdevm.h>

#include "sh_devlink.h"

static const struct devlink_ops mlx5_shd_ops = {
};

static const struct mlxdevm_ops mlx5_devm_shd_ops = {
};

int mlx5_shd_init(struct mlx5_core_dev *dev)
{
	u8 *vpd_data __free(kfree) = NULL;
	struct pci_dev *pdev = dev->pdev;
	unsigned int vpd_size, kw_len;
	struct mlxdevm *shd_mlxdevm;
	struct devlink *devlink;
	char *sn, *end;
	int start;
	int err;

	if (!mlx5_core_is_pf(dev))
		return 0;

	vpd_data = pci_vpd_alloc(pdev, &vpd_size);
	if (IS_ERR(vpd_data)) {
		err = PTR_ERR(vpd_data);
		return err == -ENODEV ? 0 : err;
	}
	start = pci_vpd_find_ro_info_keyword(vpd_data, vpd_size, "V3", &kw_len);
	if (start < 0) {
		/* Fall-back to SN for older devices. */
		start = pci_vpd_find_ro_info_keyword(vpd_data, vpd_size,
						     PCI_VPD_RO_KEYWORD_SERIALNO, &kw_len);
		if (start < 0)
			return 0; /* No usable serial number found, ignore. */
	}
	sn = kstrndup(vpd_data + start, kw_len, GFP_KERNEL);
	if (!sn)
		return -ENOMEM;
	/* Firmware may return spaces at the end of the string, strip it. */
	end = strchrnul(sn, ' ');
	*end = '\0';

	/* Get or create shared devlink instance */
	devlink = devlink_shd_get(sn, &mlx5_shd_ops, 0, pdev->dev.driver);
	if (!devlink) {
		kfree(sn);
		return -ENOMEM;
	}
	dev->shd = devlink;

	/* Get or create the shared mlxdevm instance, twinned to the shared
	 * devlink instance (dev->shd).
	 */
	shd_mlxdevm = mlxdevm_shd_get(sn, &mlx5_devm_shd_ops, 0,
				      pdev->dev.driver, dev->shd);
	kfree(sn);
	if (!shd_mlxdevm) {
		devlink_shd_put(dev->shd);
		dev->shd = NULL;
		return -ENOMEM;
	}
	dev->mlxdevm_res.shd_mlxdevm = shd_mlxdevm;

	return 0;
}

void mlx5_shd_uninit(struct mlx5_core_dev *dev)
{
	if (dev->mlxdevm_res.shd_mlxdevm) {
		mlxdevm_shd_put(dev->mlxdevm_res.shd_mlxdevm);
		dev->mlxdevm_res.shd_mlxdevm = NULL;
	}

	if (!dev->shd)
		return;

	devlink_shd_put(dev->shd);
	dev->shd = NULL;
}
