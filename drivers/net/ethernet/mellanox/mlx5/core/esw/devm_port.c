// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021 Mellanox Technologies Ltd. */

#include <linux/mlx5/driver.h>
#include <net/mlxdevm.h>
#include "eswitch.h"
#include "mlx5_esw_devm.h"

int mlx5_devm_sf_port_register(struct mlx5_core_dev *dev, u16 vport_num,
			       u32 controller, u32 sfnum)
{
	struct mlx5_devm_device *devm_dev;
	struct mlxdevm_port_attrs attrs;
	struct mlx5_devm_port *port;
	unsigned int dl_port_index;
	u16 pfnum;
	int ret;

	devm_dev = mlx5_devm_device_get(dev);
	if (!devm_dev)
		return -ENODEV;
	port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (!port)
		return -ENOMEM;
	pfnum = PCI_FUNC(dev->pdev->devfn);
	dl_port_index = mlx5_esw_vport_to_devlink_port_index(dev, vport_num);
	port->sfnum = sfnum;
	port->port_index = dl_port_index;
	port->vport_num = vport_num;

	attrs.flavour = MLXDEVM_PORT_FLAVOUR_PCI_SF;
	attrs.pci_sf.controller = controller;
	attrs.pci_sf.sf = sfnum;
	attrs.pci_sf.pf = pfnum;
	mlxdevm_port_attr_set(&port->port, &attrs);

	ret = mlxdevm_port_register(&devm_dev->device, &port->port, dl_port_index);
	if (ret)
		goto port_err;

	down_write(&devm_dev->port_list_rwsem);
	list_add_tail(&port->list, &devm_dev->port_list);
	up_write(&devm_dev->port_list_rwsem);

	return 0;

port_err:
	kfree(port);
	return ret;
}

void mlx5_devm_sf_port_unregister(struct mlx5_core_dev *dev, u16 vport_num)
{
	struct mlx5_devm_device *devm_dev;
	struct mlx5_devm_port *port;
	bool found = false;

	devm_dev = mlx5_devm_device_get(dev);
	if (!devm_dev)
		return;

	down_write(&devm_dev->port_list_rwsem);
	list_for_each_entry(port, &devm_dev->port_list, list) {
		if (port->vport_num != vport_num)
			continue;
		/* found the port */
		list_del(&port->list);
		found = true;
		break;
	}
	up_write(&devm_dev->port_list_rwsem);

	WARN_ON(!found);
	mlxdevm_port_unregister(&devm_dev->device, &port->port);
	kfree(port);
}

void mlx5_devm_sf_port_type_eth_set(struct mlx5_core_dev *dev, u16 vport_num,
				    struct net_device *ndev)
{
	struct mlx5_devm_device *devm_dev;
	struct mlx5_devm_port *port;

	devm_dev = mlx5_devm_device_get(dev);
	if (!devm_dev)
		return;

	down_read(&devm_dev->port_list_rwsem);
	list_for_each_entry(port, &devm_dev->port_list, list) {
		if (port->vport_num != vport_num)
			continue;
		/* found the port */
		mlxdevm_port_type_eth_set(&port->port, ndev);
		up_read(&devm_dev->port_list_rwsem);
		return;
	}
	up_read(&devm_dev->port_list_rwsem);
}

u32 mlx5_devm_sf_vport_to_sfnum(struct mlx5_core_dev *dev, u16 vport_num)
{
	struct mlx5_devm_device *devm_dev;
	struct mlx5_devm_port *port;
	u32 sfnum = 0;

	devm_dev = mlx5_devm_device_get(dev);
	if (!devm_dev)
		return -EOPNOTSUPP;

	down_read(&devm_dev->port_list_rwsem);
	list_for_each_entry(port, &devm_dev->port_list, list) {
		if (port->vport_num == vport_num) {
			/* found the port */
			sfnum = port->sfnum;
			break;
		}
	}
	up_read(&devm_dev->port_list_rwsem);
	return sfnum;
}

u32 mlx5_devm_sf_vport_to_controller(struct mlx5_core_dev *dev, u16 vport_num)
{
	struct mlx5_devm_device *devm_dev;
	struct mlx5_devm_port *port;
	u32 controller = 0;

	devm_dev = mlx5_devm_device_get(dev);
	if (!devm_dev)
		return 0;

	down_read(&devm_dev->port_list_rwsem);
	list_for_each_entry(port, &devm_dev->port_list, list) {
		if (port->vport_num == vport_num) {
			/* found the port */
			controller = port->port.attrs.pci_sf.controller;
			break;
		}
	}
	up_read(&devm_dev->port_list_rwsem);
	return controller;
}
