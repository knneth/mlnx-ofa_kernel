// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018-19 Mellanox Technologies

#include <net/devlink.h>
#include <linux/mdev.h>

#include "mlx5_core.h"

static ssize_t
max_mdevs_show(struct kobject *kobj, struct device *dev, char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct mlx5_core_dev *coredev;

	coredev = pci_get_drvdata(pdev);

	return sprintf(buf, "%d\n", mlx5_core_max_sfs(coredev));
}

static ssize_t
max_mdevs_store(struct kobject *kobj, struct device *dev,
		const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct mlx5_core_dev *coredev;
	u16 new_max_sfs;
	int ret;

	coredev = pci_get_drvdata(pdev);

	if (kstrtou16(buf, 10, &new_max_sfs))
		return -EINVAL;

	ret = mlx5_sf_set_max_sfs(coredev, new_max_sfs);
	if (ret)
		return ret;
	return count;
}
static MDEV_TYPE_ATTR_RW(max_mdevs);

static ssize_t
available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct mlx5_core_dev *coredev;

	coredev = pci_get_drvdata(pdev);
	return sprintf(buf, "%d\n", mlx5_get_free_sfs(coredev));
}
static MDEV_TYPE_ATTR_RO(available_instances);

static struct attribute *mdev_dev_attrs[] = {
	&mdev_type_attr_max_mdevs.attr,
	&mdev_type_attr_available_instances.attr,
	NULL,
};

static struct attribute_group mdev_mgmt_group = {
	.name  = "local",
	.attrs = mdev_dev_attrs,
};

static struct attribute_group *mlx5_meddev_groups[] = {
	&mdev_mgmt_group,
	NULL,
};

static int mlx5_meddev_create(struct kobject *kobj, struct mdev_device *meddev)
{
	struct mlx5_core_dev *parent_coredev;
	struct device *parent_dev;
	struct device *dev;
	struct mlx5_sf *sf;

	parent_dev = mdev_parent_dev(meddev);
	parent_coredev = mlx5_get_core_dev(parent_dev);
	if (!parent_coredev)
		return -ENODEV;

	dev = mdev_dev(meddev);
	sf = mlx5_alloc_sf(parent_coredev, dev);
	if (IS_ERR(sf))
		return PTR_ERR(sf);

	mdev_set_drvdata(meddev, sf);
	return 0;
}

static int mlx5_meddev_remove(struct mdev_device *meddev)
{
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);
	struct mlx5_core_dev *parent_coredev;

	parent_coredev = pci_get_drvdata(to_pci_dev(mdev_parent_dev(meddev)));
	mlx5_free_sf(parent_coredev, sf);
	return 0;
}

static ssize_t
mac_addr_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);
	u8 mac[ETH_ALEN];
	int ret;

	ret = mlx5_sf_get_mac(sf, mac);
	if (ret)
		return ret;

	ret = sprintf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
		      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return ret;
}

static ssize_t
mac_addr_store(struct device *dev, struct device_attribute *attr,
	       const char *buf, size_t len)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);
	u8 mac[ETH_ALEN];
	int ret;

	/* length must be account for 00:00:00:00:00:00 and NULL terminator */
	if (len != 18)
		return -EINVAL;

	ret = sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		     &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	if (ret != 6)
		return -EINVAL;

	ret = mlx5_sf_set_mac(sf, mac);
	return ret ? ret : len;
}
static DEVICE_ATTR_RW(mac_addr);

static ssize_t
netdev_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);
	struct net_device *ndev;
	int ret;

	ndev = mlx5_sf_get_netdev(sf);
	if (IS_ERR(ndev))
		return PTR_ERR(ndev);

	ret = sprintf(buf, "%s\n", ndev->name);
	dev_put(ndev);
	return ret;
}
static DEVICE_ATTR_RO(netdev);

static struct attribute *mlx5_meddev_dev_attrs[] = {
	&dev_attr_mac_addr.attr,
	&dev_attr_netdev.attr,
	NULL,
};

static const struct attribute_group mlx5_meddev_dev_group = {
	.name  = "devlink-compat-config",
	.attrs = mlx5_meddev_dev_attrs,
};

static const struct attribute_group *mlx5_meddev_attr_groups[] = {
	&mlx5_meddev_dev_group,
	NULL
};

static const struct mdev_parent_ops mlx5_meddev_ops = {
	.create = mlx5_meddev_create,
	.remove = mlx5_meddev_remove,
	.supported_type_groups = mlx5_meddev_groups,
	.mdev_attr_groups = mlx5_meddev_attr_groups
};

int mlx5_meddev_init(struct mlx5_core_dev *dev)
{
	if (!dev->priv.sf_table)
		return 0;

	return mdev_register_device(dev->device, &mlx5_meddev_ops);
}

void mlx5_meddev_cleanup(struct mlx5_core_dev *dev)
{
	if (!dev->priv.sf_table)
		return;

	mdev_unregister_device(dev->device);
}
