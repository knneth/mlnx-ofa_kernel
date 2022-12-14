// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2020 Mellanox Technologies Ltd. */

#include <linux/mlx5/driver.h>
#include "eswitch.h"
#include "mlx5_esw_devm.h"

static void
mlx5_esw_get_port_parent_id(struct mlx5_core_dev *dev, struct netdev_phys_item_id *ppid)
{
	u64 parent_id;

	parent_id = mlx5_query_nic_system_image_guid(dev);
	ppid->id_len = sizeof(parent_id);
	memcpy(ppid->id, &parent_id, sizeof(parent_id));
}

static bool mlx5_esw_devlink_port_supported(struct mlx5_eswitch *esw, u16 vport_num)
{
	return vport_num == MLX5_VPORT_UPLINK ||
	       (mlx5_core_is_ecpf(esw->dev) && vport_num == MLX5_VPORT_PF) ||
	       mlx5_eswitch_is_vf_vport(esw, vport_num);
}

static struct devlink_port *mlx5_esw_dl_port_alloc(struct mlx5_eswitch *esw, u16 vport_num)
{
	struct mlx5_core_dev *dev = esw->dev;
	struct devlink_port_attrs attrs = {};
	struct netdev_phys_item_id ppid = {};
	struct devlink_port *dl_port;
	u32 controller_num = 0;
	bool external;
	u16 pfnum;

	dl_port = kzalloc(sizeof(*dl_port), GFP_KERNEL);
	if (!dl_port)
		return NULL;

	mlx5_esw_get_port_parent_id(dev, &ppid);
	pfnum = mlx5_get_dev_index(dev);
	external = mlx5_core_is_ecpf_esw_manager(dev);
	if (external)
		controller_num = dev->priv.eswitch->offloads.host_number + 1;

	if (vport_num == MLX5_VPORT_UPLINK) {
		attrs.flavour = DEVLINK_PORT_FLAVOUR_PHYSICAL;
		attrs.phys.port_number = pfnum;
		memcpy(attrs.switch_id.id, ppid.id, ppid.id_len);
		attrs.switch_id.id_len = ppid.id_len;
		devlink_port_attrs_set(dl_port, &attrs);
	} else if (vport_num == MLX5_VPORT_PF) {
		memcpy(dl_port->attrs.switch_id.id, ppid.id, ppid.id_len);
		dl_port->attrs.switch_id.id_len = ppid.id_len;
		devlink_port_attrs_pci_pf_set(dl_port, controller_num, pfnum, external);
	} else if (mlx5_eswitch_is_vf_vport(esw, vport_num)) {
		memcpy(dl_port->attrs.switch_id.id, ppid.id, ppid.id_len);
		dl_port->attrs.switch_id.id_len = ppid.id_len;
		devlink_port_attrs_pci_vf_set(dl_port, controller_num, pfnum,
					      vport_num - 1, external);
	}
	return dl_port;
}

static void mlx5_esw_dl_port_free(struct devlink_port *dl_port)
{
	kfree(dl_port);
}

int mlx5_esw_offloads_devlink_port_register(struct mlx5_eswitch *esw, u16 vport_num)
{
	struct mlx5_core_dev *dev = esw->dev;
	struct devlink_port *dl_port;
	unsigned int dl_port_index;
	struct mlx5_vport *vport;
	struct devlink *devlink;
	int err;

	if (!mlx5_esw_devlink_port_supported(esw, vport_num))
		return 0;

	vport = mlx5_eswitch_get_vport(esw, vport_num);
	if (IS_ERR(vport))
		return PTR_ERR(vport);

	dl_port = mlx5_esw_dl_port_alloc(esw, vport_num);
	if (!dl_port)
		return -ENOMEM;

	devlink = priv_to_devlink(dev);
	dl_port_index = mlx5_esw_vport_to_devlink_port_index(dev, vport_num);
	err = devlink_port_register(devlink, dl_port, dl_port_index);
	if (err)
		goto reg_err;

#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
	err = devlink_rate_leaf_create(dl_port, vport);
	if (err)
		goto rate_err;
#endif

	vport->dl_port = dl_port;
	return 0;

#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
rate_err:
	devlink_port_unregister(dl_port);
#endif
reg_err:
	mlx5_esw_dl_port_free(dl_port);
	return err;
}

void mlx5_esw_offloads_devlink_port_unregister(struct mlx5_eswitch *esw, u16 vport_num)
{
	struct mlx5_vport *vport;

	if (!mlx5_esw_devlink_port_supported(esw, vport_num))
		return;

	vport = mlx5_eswitch_get_vport(esw, vport_num);
	if (IS_ERR(vport))
		return;

#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
	if (vport->dl_port->devlink_rate) {
		if (refcount_read(&esw->qos.refcnt))
			mlx5_esw_qos_vport_update_group(esw, vport, NULL, NULL);
		devlink_rate_leaf_destroy(vport->dl_port);
	}
#endif

	devlink_port_unregister(vport->dl_port);
	mlx5_esw_dl_port_free(vport->dl_port);
	vport->dl_port = NULL;
}

struct devlink_port *mlx5_esw_offloads_devlink_port(struct mlx5_eswitch *esw, u16 vport_num)
{
	struct mlx5_vport *vport;

	vport = mlx5_eswitch_get_vport(esw, vport_num);
	return IS_ERR(vport) ? ERR_CAST(vport) : vport->dl_port;
}

#if IS_ENABLED(CONFIG_MLXDEVM)
int mlx5_esw_devlink_sf_port_register(struct mlx5_eswitch *esw, struct devlink_port *dl_port,
				      u16 vport_num, u32 controller, u32 sfnum)
{
	return mlx5_devm_sf_port_register(esw->dev, vport_num, controller, sfnum);
}
#else
int mlx5_esw_devlink_sf_port_register(struct mlx5_eswitch *esw, struct devlink_port *dl_port,
				      u16 vport_num, u32 controller, u32 sfnum)
{
	int err;

	devlink_port_attrs_pci_sf_set(dl_port, controller, pfnum, sfnum, !!controller);

#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
	err = devlink_rate_leaf_create(dl_port, vport);
	if (err)
		return err;
#endif

	return -EOPNOTSUPP;
}
#endif

#if IS_ENABLED(CONFIG_MLXDEVM)
void mlx5_esw_devlink_sf_port_unregister(struct mlx5_eswitch *esw, u16 vport_num)
{
	mlx5_devm_sf_port_unregister(esw->dev, vport_num);
}
#else
void mlx5_esw_devlink_sf_port_unregister(struct mlx5_eswitch *esw, u16 vport_num)
{
#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
	struct mlx5_vport *vport;

	vport = mlx5_eswitch_get_vport(esw, vport_num);
	if (IS_ERR(vport))
		return;

	if (vport->dl_port->devlink_rate) {
		mlx5_esw_qos_vport_update_group(esw, vport, NULL, NULL);
		devlink_rate_leaf_destroy(vport->dl_port);
	}
#endif
}
#endif
