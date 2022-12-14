// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Mellanox Technologies

#include <net/devlink.h>
#include <linux/mdev.h>
#include <linux/refcount.h>

#include "mlx5_core.h"
#include "meddev/sf.h"
#include "eswitch.h"

struct mlx5_mdev_table {
	struct mlx5_sf_table sf_table;
	/* Synchronizes with mdev table cleanup check and mdev creation. */
	struct rw_semaphore cleanup_rwsem;
	bool cleanup_started;
};

static ssize_t
max_mdevs_show(struct kobject *kobj, struct device *dev, char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct mlx5_core_dev *coredev;
	struct mlx5_mdev_table *table;
	u16 max_sfs;

	coredev = pci_get_drvdata(pdev);
	table = coredev->priv.eswitch->mdev_table;
	max_sfs = mlx5_core_max_sfs(coredev, &table->sf_table);

	return sprintf(buf, "%d\n", max_sfs);
}

static ssize_t
max_mdevs_store(struct kobject *kobj, struct device *dev,
		const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct mlx5_core_dev *coredev;
	struct mlx5_mdev_table *table;
	u16 new_max_sfs;
	int ret;

	coredev = pci_get_drvdata(pdev);

	if (kstrtou16(buf, 10, &new_max_sfs))
		return -EINVAL;

	table = coredev->priv.eswitch->mdev_table;
	ret = mlx5_sf_set_max_sfs(coredev, &table->sf_table, new_max_sfs);
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
	struct mlx5_mdev_table *table;
	u16 free_sfs;

	coredev = pci_get_drvdata(pdev);
	table = coredev->priv.eswitch->mdev_table;
	free_sfs = mlx5_get_free_sfs(coredev, &table->sf_table);
	return sprintf(buf, "%d\n", free_sfs);
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
	struct mlx5_mdev_table *table;
	struct device *parent_dev;
	struct device *dev;
	struct mlx5_sf *sf;
	int ret = 0;

	parent_dev = mdev_parent_dev(meddev);
	parent_coredev = mlx5_get_core_dev(parent_dev);
	if (!parent_coredev)
		return -ENODEV;

	table = parent_coredev->priv.eswitch->mdev_table;
	/* Publish that mdev creation is in progress, hence wait for it
	 * to complete, while changing eswitch mode.
	 */
	down_read(&table->cleanup_rwsem);
	if (table->cleanup_started) {
		ret = -ENODEV;
		goto sf_err;
	}

	dev = mdev_dev(meddev);
	sf = mlx5_sf_alloc(parent_coredev, &table->sf_table, dev);
	if (IS_ERR(sf)) {
		ret = PTR_ERR(sf);
		goto sf_err;
	}

	mdev_set_drvdata(meddev, sf);
sf_err:
	up_read(&table->cleanup_rwsem);
	return ret;
}

static int mlx5_meddev_remove(struct mdev_device *meddev)
{
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);
	struct mlx5_core_dev *parent_coredev;
	struct mlx5_mdev_table *table;

	parent_coredev = pci_get_drvdata(to_pci_dev(mdev_parent_dev(meddev)));
	table = parent_coredev->priv.eswitch->mdev_table;
	mlx5_sf_free(parent_coredev, &table->sf_table, sf);
	return 0;
}

static ssize_t
roce_disable_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);
	bool val;
	int ret;

	ret = mlx5_sf_hca_cap_roce_get(sf, &val);
	if (ret)
		return ret;

	return sprintf(buf, "%d\n", val);
}

static ssize_t
roce_disable_store(struct device *dev, struct device_attribute *attr,
		   const char *buf, size_t len)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);
	int ret;
	bool val;

	ret = kstrtobool(buf, &val);
	if (ret)
		return -EINVAL;

	ret = mlx5_sf_hca_cap_roce_set(sf, val);
	return ret ? ret : len;
}
static DEVICE_ATTR_RW(roce_disable);

static ssize_t
uc_list_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);
	u32 val;
	int ret;

	ret = mlx5_sf_hca_cap_uc_list_get(sf, &val);
	if (ret)
		return ret;

	return sprintf(buf, "%u\n", val);
}

static ssize_t
uc_list_store(struct device *dev, struct device_attribute *attr,
	      const char *buf, size_t len)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);
	u32 val;
	int ret;

	if (kstrtouint(buf, 0, &val))
		return -EINVAL;

	if (val > 32)
		return -EINVAL;

	ret = mlx5_sf_hca_cap_uc_list_set(sf, val);
	return ret ? ret : len;
}
static DEVICE_ATTR_RW(uc_list);

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

	ret = sprintf(buf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
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

static ssize_t
disable_en_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);

	return sprintf(buf, "%d\n", !!sf->disable_en);
}

static ssize_t
disable_en_store(struct device *dev, struct device_attribute *attr,
		 const char *buf, size_t len)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);
	int val;

	if (kstrtoint(buf, 10, &val))
		return -EINVAL;

	if (val < 0 && val > 1)
		return -EINVAL;

	sf->disable_en = val;

	return len;
}
static DEVICE_ATTR_RW(disable_en);

static ssize_t
max_cmpl_eq_count_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);

	return sprintf(buf, "%d\n", sf->max_cmpl_eq_count);
}

static ssize_t
max_cmpl_eq_count_store(struct device *dev, struct device_attribute *attr,
			const char *buf, size_t len)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);
	int val;

	if (kstrtoint(buf, 10, &val))
		return -EINVAL;

	if (val < 1 && val > 8)
		return -EINVAL;

	sf->max_cmpl_eq_count = val;
	return len;
}
static DEVICE_ATTR_RW(max_cmpl_eq_count);

static ssize_t
cmpl_eq_depth_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);

	return sprintf(buf, "%d\n", sf->cmpl_eq_depth);
}

static bool is_eq_depth_valid(int val)
{
	return (val >= 2 && val <= 4096);
}

static ssize_t
cmpl_eq_depth_store(struct device *dev, struct device_attribute *attr,
		    const char *buf, size_t len)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);
	int val;

	if (kstrtoint(buf, 10, &val))
		return -EINVAL;

	if (!is_eq_depth_valid(val))
		return -EINVAL;

	sf->cmpl_eq_depth = val;
	return len;
}
static DEVICE_ATTR_RW(cmpl_eq_depth);

static ssize_t
async_eq_depth_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);

	return sprintf(buf, "%d\n", sf->async_eq_depth);
}

static ssize_t
async_eq_depth_store(struct device *dev, struct device_attribute *attr,
		    const char *buf, size_t len)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);
	int val;

	if (kstrtoint(buf, 10, &val))
		return -EINVAL;

	if (!is_eq_depth_valid(val))
		return -EINVAL;

	sf->async_eq_depth = val;
	return len;
}
static DEVICE_ATTR_RW(async_eq_depth);

static ssize_t
disable_fc_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);

	return sprintf(buf, "%d\n", !!sf->disable_fc);
}

static ssize_t
disable_fc_store(struct device *dev, struct device_attribute *attr,
		 const char *buf, size_t len)
{
	struct mdev_device *meddev = mdev_from_dev(dev);
	struct mlx5_sf *sf = mdev_get_drvdata(meddev);
	int val;

	if (kstrtoint(buf, 10, &val))
		return -EINVAL;

	if (val < 0 && val > 1)
		return -EINVAL;

	sf->disable_fc = val;

	return len;
}
static DEVICE_ATTR_RW(disable_fc);

static struct attribute *mlx5_meddev_dev_attrs[] = {
	&dev_attr_mac_addr.attr,
	&dev_attr_netdev.attr,
	&dev_attr_disable_en.attr,
	&dev_attr_roce_disable.attr,
	&dev_attr_uc_list.attr,
	&dev_attr_max_cmpl_eq_count.attr,
	&dev_attr_cmpl_eq_depth.attr,
	&dev_attr_async_eq_depth.attr,
	&dev_attr_disable_fc.attr,
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

void mlx5_meddev_init(struct mlx5_core_dev *dev)
{
	struct mlx5_mdev_table *table;
	int ret;

	if (!mlx5_core_is_sf_supported(dev))
		return;

	table = kzalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return;

	ret = mlx5_sf_table_init(dev, &table->sf_table);
	if (ret)
		goto table_err;

	init_rwsem(&table->cleanup_rwsem);
	dev->priv.eswitch->mdev_table = table;
	ret = mdev_register_device(dev->device, &mlx5_meddev_ops);
	if (!ret)
		return;

	dev->priv.eswitch->mdev_table = NULL;
	mlx5_sf_table_cleanup(dev, &table->sf_table);
table_err:
	kfree(table);
}

void mlx5_meddev_cleanup(struct mlx5_core_dev *dev)
{
	struct mlx5_mdev_table *table;

	if (!mlx5_core_is_sf_supported(dev))
		return;

	table = dev->priv.eswitch->mdev_table;
	if (!table)
		return;

	/* At this point no new creation can be in progress. Hence it is safe
	 * to unregister and destroy the table.
	 */
	mdev_unregister_device(dev->device);
	dev->priv.eswitch->mdev_table = NULL;
	mlx5_sf_table_cleanup(dev, &table->sf_table);
	kfree(table);
}

/* Check if meddev cleanup can be done or not.
 * If possible to cleanup, mark that cleanup will be in progress
 * so that no new creation can happen.
 */
bool mlx5_medev_can_and_mark_cleanup(struct mlx5_core_dev *dev)
{
	struct mlx5_mdev_table *table;

	if (!mlx5_core_is_sf_supported(dev))
		return true;

	table = dev->priv.eswitch->mdev_table;
	if (!table)
		return true;

	down_write(&table->cleanup_rwsem);

	if (mlx5_get_free_sfs(dev, &table->sf_table) !=
	    mlx5_core_max_sfs(dev, &table->sf_table)) {
		up_write(&table->cleanup_rwsem);
		return false;
	}
	table->cleanup_started = true;
	up_write(&table->cleanup_rwsem);
	return true;
}
