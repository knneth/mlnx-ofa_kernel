/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies Ltd */

#include "eswitch.h"

#define MLX5_DEVM_GROUP_ID 0xFFFF

static int
mlx5_esw_get_esw_and_vport(struct devlink *devlink, struct devlink_port *port,
			   struct mlx5_eswitch **esw, struct mlx5_vport **vport,
			   struct netlink_ext_ack *extack)
{
	u16 vport_num;

	*esw = mlx5_devlink_eswitch_get(devlink);
	if (IS_ERR(*esw)) {
		NL_SET_ERR_MSG_MOD(extack, "Esw not found");
		return PTR_ERR(*esw);
	}

	vport_num = mlx5_esw_devlink_port_index_to_vport_num(port->index);
	*vport = mlx5_eswitch_get_vport(*esw, vport_num);
	if (IS_ERR(*vport)) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to get vport");
		return PTR_ERR(*vport);
	}

	return 0;
}

int mlx5_devlink_rate_leaf_tx_share_set(struct devlink *devlink,
					struct devlink_port *port,
					u64 tx_share,
					struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw;
	struct mlx5_vport *vport;
	u32 max_tx_rate;
	int err;

	err = mlx5_esw_get_esw_and_vport(devlink, port, &esw, &vport, extack);
	if (err)
		return err;

	mutex_lock(&esw->state_lock);
	max_tx_rate = vport->qos.max_rate;
	mutex_unlock(&esw->state_lock);

	if (max_tx_rate && tx_share > max_tx_rate) {
		NL_SET_ERR_MSG_MOD(extack, "tx_max is less than tx_share\n");
		return -EINVAL;
	}

	return mlx5_eswitch_set_vport_rate(esw, vport->vport, max_tx_rate, (u32)tx_share);
}

int mlx5_devlink_rate_leaf_tx_max_set(struct devlink *devlink,
				      struct devlink_port *port,
				      u64 tx_max,
				      struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw;
	struct mlx5_vport *vport;
	u32 min_tx_rate;
	int err;

	err = mlx5_esw_get_esw_and_vport(devlink, port, &esw, &vport, extack);
	if (err)
		return err;

	mutex_lock(&esw->state_lock);
	min_tx_rate = vport->qos.min_rate;
	mutex_unlock(&esw->state_lock);

	if (tx_max && min_tx_rate > tx_max) {
		NL_SET_ERR_MSG_MOD(extack, "tx_max is less than tx_share\n");
		return -EINVAL;
	}

	return mlx5_eswitch_set_vport_rate(esw, vport->vport, (u32)tx_max, min_tx_rate);
}

int mlx5_devlink_rate_leaf_group_set(struct devlink *devlink,
				     struct devlink_port *port,
				     const char *group,
				     struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw;
	struct mlx5_vport *vport;
	int err;

	err = mlx5_esw_get_esw_and_vport(devlink, port, &esw, &vport, extack);
	if (err)
		return err;

	if (strlen(group))
		return mlx5_eswitch_vport_update_group(esw, vport->vport,
						       MLX5_DEVM_GROUP_ID, group);
	else
		/* if string is empty, set parent to group0 */
		return mlx5_eswitch_vport_update_group(esw, vport->vport, 0, NULL);
}

int mlx5_devlink_rate_leaf_get(struct devlink *devlink,
			       struct devlink_port *port,
			       u64 *tx_max, u64 *tx_share, char **group,
			       struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw;
	struct mlx5_vport *vport;
	int err;

	err = mlx5_esw_get_esw_and_vport(devlink, port, &esw, &vport, extack);
	if (err)
		return err;

	mutex_lock(&esw->state_lock);
	if (!vport->enabled) {
		NL_SET_ERR_MSG_MOD(extack, "Eswitch vport is disabled");
		err = -EOPNOTSUPP;
		goto out;
	}

	*tx_max = vport->qos.max_rate;
	*tx_share = vport->qos.min_rate;
	*group = vport->qos.group->devm.name;

out:
	mutex_unlock(&esw->state_lock);
	return err;
}

int mlx5_devlink_rate_node_tx_share_set(struct devlink *devlink,
					const char *group, u64 tx_share,
					struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw;

	esw = mlx5_devlink_eswitch_get(devlink);
	if (IS_ERR(esw)) {
		NL_SET_ERR_MSG_MOD(extack, "Esw not found");
		return PTR_ERR(esw);
	}

	return mlx5_eswitch_set_vgroup_min_rate(esw, MLX5_DEVM_GROUP_ID, group, tx_share);
}

int mlx5_devlink_rate_node_tx_max_set(struct devlink *devlink,
				      const char *group, u64 tx_max,
				      struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw;

	esw = mlx5_devlink_eswitch_get(devlink);
	if (IS_ERR(esw)) {
		NL_SET_ERR_MSG_MOD(extack, "Esw not found");
		return PTR_ERR(esw);
	}

	return mlx5_eswitch_set_vgroup_max_rate(esw, MLX5_DEVM_GROUP_ID, group, tx_max);
}

int mlx5_devlink_rate_node_del(struct devlink *devlink, const char *group,
			       struct netlink_ext_ack *extack)
{
	struct mlx5_vport *evport;
	struct mlx5_eswitch *esw;
	struct mlx5_vgroup *tmp;
	bool found = false;
	unsigned long i;
	int err = 0;

	esw = mlx5_devlink_eswitch_get(devlink);
	if (IS_ERR(esw)) {
		NL_SET_ERR_MSG_MOD(extack, "Esw not found");
		return PTR_ERR(esw);
	}

	mutex_lock(&esw->state_lock);
	list_for_each_entry(tmp, &esw->qos.groups, list) {
		if (!tmp->devm.name)
			continue;

		if (!strcmp(tmp->devm.name, group)) {
			found = true;
			break;
		}
	}

	if (!found) {
		NL_SET_ERR_MSG_MOD(extack, "Eswitch delete QoS group not found");
		err = -ENOENT;
		goto out;
	}

	mlx5_esw_for_each_vport(esw, i, evport) {
		if (!evport->enabled || evport->qos.group != tmp)
			continue;
		NL_SET_ERR_MSG_MOD(extack, "Cannot delete group. Child vports exist");
		err = -EBUSY;
		goto out;
	}

	esw_destroy_vgroup(esw, tmp);

out:
	mutex_unlock(&esw->state_lock);
	return err;
}

int mlx5_devlink_rate_node_new(struct devlink *devlink, const char *group,
			       struct netlink_ext_ack *extack)
{
	struct mlx5_vgroup *vgroup;
	struct mlx5_eswitch *esw;
	int err = 0;

	esw = mlx5_devlink_eswitch_get(devlink);
	if (IS_ERR(esw)) {
		NL_SET_ERR_MSG_MOD(extack, "Esw not found");
		return PTR_ERR(esw);
	}

	mutex_lock(&esw->state_lock);
	vgroup = esw_create_vgroup(esw, MLX5_DEVM_GROUP_ID, group);
	if (IS_ERR(vgroup)) {
		NL_SET_ERR_MSG_MOD(extack, "Eswitch fail to create QoS group");
		err = PTR_ERR(vgroup);
	}

	mutex_unlock(&esw->state_lock);
	return err;
}
