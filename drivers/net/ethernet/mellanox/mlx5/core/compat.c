// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2019 Mellanox Technologies. */

#include <linux/mlx5/driver.h>
#include "devlink.h"
#include "eswitch.h"
#include "en.h"
#include "en_rep.h"
#include "en/rep/tc.h"

bool mlx5_is_roce_init_enabled(struct mlx5_core_dev *dev)
{
#if defined(HAVE_DEVLINK_PARAM) && defined(HAVE_DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE)
	struct devlink *devlink = priv_to_devlink(dev);
	union devlink_param_value val;

	devlink_param_driverinit_value_get(devlink,
			DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE,
			&val);
	return val.vbool;
#else
	return dev->roce.enabled && MLX5_CAP_GEN(dev, roce);
#endif
}
EXPORT_SYMBOL(mlx5_is_roce_init_enabled);

#ifdef CONFIG_MLX5_ESWITCH
#if defined(HAVE_SWITCHDEV_OPS) || defined(HAVE_SWITCHDEV_H_COMPAT)
int mlx5e_attr_get(struct net_device *dev, struct switchdev_attr *attr)
{
	int err = 0;

	if (!netif_device_present(dev))
		return -EOPNOTSUPP;

	switch (attr->id) {
#ifndef HAVE_NDO_GET_PORT_PARENT_ID
	case SWITCHDEV_ATTR_ID_PORT_PARENT_ID:
		err = mlx5e_rep_get_port_parent_id(dev, &attr->u.ppid);
		break;
#endif
	default:
		return -EOPNOTSUPP;
	}

	return err;
}
#endif

#ifdef HAVE_SWITCHDEV_H_COMPAT
static inline int dev_isalive(const struct net_device *dev)
{
	return dev->reg_state <= NETREG_REGISTERED;
}

static ssize_t phys_port_name_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = to_net_dev(dev);
	ssize_t ret = -EINVAL;

	if (!rtnl_trylock())
		return restart_syscall();

	if (dev_isalive(netdev)) {
		char name[IFNAMSIZ];

		ret = mlx5e_rep_get_phys_port_name(netdev, name, sizeof(name));
		if (!ret)
			ret = sprintf(buf, "%s\n", name);
	}
	rtnl_unlock();

	return ret;
}

ssize_t phys_switch_id_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = to_net_dev(dev);
	ssize_t ret = -EINVAL;

	if (!rtnl_trylock())
		return restart_syscall();

	if (dev_isalive(netdev)) {
		struct switchdev_attr attr = {
			.orig_dev = netdev,
			.id = SWITCHDEV_ATTR_ID_PORT_PARENT_ID,
			.flags = SWITCHDEV_F_NO_RECURSE,
		};

		ret = mlx5e_attr_get(netdev, &attr);
		if (!ret)
			ret = sprintf(buf, "%*phN\n", attr.u.ppid.id_len,
				      attr.u.ppid.id);
	}
	rtnl_unlock();

	return ret;
}

static DEVICE_ATTR(phys_port_name, S_IRUGO, phys_port_name_show, NULL);
static DEVICE_ATTR(phys_switch_id, S_IRUGO, phys_switch_id_show, NULL);

static struct attribute *rep_sysfs_attrs[] = {
	&dev_attr_phys_port_name.attr,
	&dev_attr_phys_switch_id.attr,
	NULL,
};

static struct attribute_group rep_sysfs_attr_group = {
	.attrs = rep_sysfs_attrs,
};
#endif /* HAVE_SWITCHDEV_H_COMPAT */

void mlx5e_rep_set_sysfs_attr(struct net_device *netdev)
{
	if (!netdev)
		return;

#ifdef HAVE_SWITCHDEV_H_COMPAT
	if (!netdev->sysfs_groups[0])
		netdev->sysfs_groups[0] = &rep_sysfs_attr_group;
#endif
}

int mlx5e_vport_rep_load_compat(struct mlx5e_priv *priv)
{
	struct net_device *netdev = priv->netdev;
#if IS_ENABLED(CONFIG_MLX5_CLS_ACT) && defined(HAVE_TC_SETUP_CB_EGDEV_REGISTER)
	struct mlx5e_rep_priv *uplink_rpriv;
#ifdef HAVE_TC_BLOCK_OFFLOAD
	struct mlx5e_priv *upriv;
#endif
	int err;

	uplink_rpriv = mlx5_eswitch_get_uplink_priv(priv->mdev->priv.eswitch,
						    REP_ETH);
#ifdef HAVE_TC_BLOCK_OFFLOAD
	upriv = netdev_priv(uplink_rpriv->netdev);
	err = tc_setup_cb_egdev_register(netdev, mlx5e_rep_setup_tc_cb_egdev,
					 upriv);
#else
	err = tc_setup_cb_egdev_register(netdev, mlx5e_rep_setup_tc_cb,
					 uplink_rpriv->netdev);
#endif
	if (err)
		return err;
#endif

	mlx5e_rep_set_sysfs_attr(netdev);
	return 0;
}

void mlx5e_vport_rep_unload_compat(struct mlx5e_priv *priv)
{
#if IS_ENABLED(CONFIG_MLX5_CLS_ACT) && defined(HAVE_TC_SETUP_CB_EGDEV_REGISTER)
	struct net_device *netdev = priv->netdev;
	struct mlx5e_rep_priv *uplink_rpriv;
#ifdef HAVE_TC_BLOCK_OFFLOAD
	struct mlx5e_priv *upriv;
#endif

	uplink_rpriv = mlx5_eswitch_get_uplink_priv(priv->mdev->priv.eswitch,
						    REP_ETH);
#ifdef HAVE_TC_BLOCK_OFFLOAD
	upriv = netdev_priv(uplink_rpriv->netdev);
	tc_setup_cb_egdev_unregister(netdev, mlx5e_rep_setup_tc_cb_egdev,
				     upriv);
#else
	tc_setup_cb_egdev_unregister(netdev, mlx5e_rep_setup_tc_cb,
				     uplink_rpriv->netdev);
#endif

#endif
}
#endif /* CONFIG_MLX5_ESWITCH */
