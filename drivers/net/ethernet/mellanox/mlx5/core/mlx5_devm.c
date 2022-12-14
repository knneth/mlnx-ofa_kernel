// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021 Mellanox Technologies Ltd. */

#include <linux/log2.h>
#include "mlx5_core.h"
#include "fs_core.h"
#include "eswitch.h"
#include "sf/dev/dev.h"
#include "sf/sf.h"
#include "sf/mlx5_ifc_vhca_event.h"
#include <uapi/mlxdevm/mlxdevm_netlink.h>
#include "mlx5_devm.h"
#include "mlx5_esw_devm.h"
#include "mlx5_irq.h"
#include "esw/qos.h"

static LIST_HEAD(dev_head);
/* The mutex below protects the dev_head list */
static DEFINE_MUTEX(mlx5_mlxdevm_mutex);

/**
 * Functions to translate between mlxdevm function states and devlink fn states,
 * for use by shim layer
 */
static enum devlink_port_fn_state mlxdevm_to_devlink_state(enum mlxdevm_port_fn_state state)
{
	switch (state) {
	case MLXDEVM_PORT_FN_STATE_ACTIVE:
		return DEVLINK_PORT_FN_STATE_ACTIVE;
	case MLXDEVM_PORT_FN_STATE_INACTIVE:
	default:
		return DEVLINK_PORT_FN_STATE_INACTIVE;
	}
}

static enum mlxdevm_port_fn_opstate devlink_to_mlxdevm_opstate(enum devlink_port_fn_opstate state)
{
	switch (state) {
	case DEVLINK_PORT_FN_OPSTATE_ATTACHED:
		return MLXDEVM_PORT_FN_OPSTATE_ATTACHED;
	case DEVLINK_PORT_FN_OPSTATE_DETACHED:
	default:
		return MLXDEVM_PORT_FN_OPSTATE_DETACHED;
	}
}

static enum mlxdevm_port_fn_state devlink_to_mlxdevm_state(enum devlink_port_fn_state state)
{
	switch (state) {
	case DEVLINK_PORT_FN_STATE_ACTIVE:
		return MLXDEVM_PORT_FN_STATE_ACTIVE;
	case DEVLINK_PORT_FN_STATE_INACTIVE:
	default:
		return MLXDEVM_PORT_FN_STATE_INACTIVE;
	}
}

struct mlx5_devm_device *mlx5_devm_device_get(struct mlx5_core_dev *dev)
{
	struct mlx5_devm_device *mdevm;

	/* find the mlxdevm device associated with this core dev */
	mutex_lock(&mlx5_mlxdevm_mutex);
	list_for_each_entry(mdevm, &dev_head, list) {
		if (mdevm->dev == dev) {
			mutex_unlock(&mlx5_mlxdevm_mutex);
			return mdevm;
		}
	}
	mutex_unlock(&mlx5_mlxdevm_mutex);
	return NULL;
}

static enum devlink_port_flavour devm2devlink_flavour(enum mlxdevm_port_flavour devm_flv)
{
	/* return a real port flavour only if pci_sf */
	switch (devm_flv) {
	case MLXDEVM_PORT_FLAVOUR_PCI_SF:
		return DEVLINK_PORT_FLAVOUR_PCI_SF;
	default:
		return DEVLINK_PORT_FLAVOUR_PHYSICAL;
	}
	return DEVLINK_PORT_FLAVOUR_PHYSICAL;
}

static void dm_new_attrs2devl_new_attrs(const struct mlxdevm_port_new_attrs *new_devm,
					struct devlink_port_new_attrs *new_devlink)
{
	memset(new_devlink, 0, sizeof(*new_devlink));
	new_devlink->flavour = devm2devlink_flavour(new_devm->flavour);
	new_devlink->port_index = new_devm->port_index;
	new_devlink->controller = new_devm->controller;
	new_devlink->sfnum = new_devm->sfnum;
	new_devlink->pfnum = new_devm->pfnum;
	new_devlink->port_index_valid = new_devm->port_index_valid;
	new_devlink->controller_valid = new_devm->controller_valid;
	new_devlink->sfnum_valid = new_devm->sfnum_valid;
}

static struct devlink *mlxdevm_to_devlink(struct mlxdevm *devm)
{
	return priv_to_devlink(container_of(devm, struct mlx5_devm_device, device)->dev);
}

int mlx5_devm_sf_port_new(struct mlxdevm *devm_dev,
			  const struct mlxdevm_port_new_attrs *attrs,
			  struct netlink_ext_ack *extack,
			  unsigned int *new_port_index)
{
	struct devlink_port_new_attrs devl_attrs;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(devm_dev);
	dm_new_attrs2devl_new_attrs(attrs, &devl_attrs);
	return mlx5_devlink_sf_port_new(devlink, &devl_attrs, extack, new_port_index);
}

int mlx5_devm_sf_port_del(struct mlxdevm *devm_dev,
			  unsigned int port_index,
			  struct netlink_ext_ack *extack)
{
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(devm_dev);
	return mlx5_devlink_sf_port_del(devlink, port_index, extack);
}

int mlx5_devm_sf_port_fn_state_get(struct mlxdevm_port *port,
				   enum mlxdevm_port_fn_state *state,
				   enum mlxdevm_port_fn_opstate *opstate,
				   struct netlink_ext_ack *extack)
{
	enum devlink_port_fn_opstate dl_opstate;
	enum devlink_port_fn_state dl_state;
	struct devlink_port devport;
	struct devlink *devlink;
	int ret;

	devlink = mlxdevm_to_devlink(port->devm);
	memset(&devport, 0, sizeof(devport));
	devport.devlink = devlink;
	devport.index = port->index;

	ret = mlx5_devlink_sf_port_fn_state_get(&devport, &dl_state, &dl_opstate, extack);
	if (!ret) {
		*state = devlink_to_mlxdevm_state(dl_state);
		*opstate = devlink_to_mlxdevm_opstate(dl_opstate);
	}
	return ret;
}

int mlx5_devm_sf_port_fn_state_set(struct mlxdevm_port *port,
				   enum mlxdevm_port_fn_state state,
				   struct netlink_ext_ack *extack)
{
	enum devlink_port_fn_state dl_state;
	struct devlink_port devport;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(port->devm);
	memset(&devport, 0, sizeof(devport));
	devport.devlink = devlink;
	devport.index = port->index;
	dl_state = mlxdevm_to_devlink_state(state);
	return mlx5_devlink_sf_port_fn_state_set(&devport, dl_state, extack);
}

int mlx5_devm_sf_port_fn_hw_addr_get(struct mlxdevm_port *port,
				     u8 *hw_addr, int *hw_addr_len,
				     struct netlink_ext_ack *extack)
{
	struct devlink_port devport;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(port->devm);
	memset(&devport, 0, sizeof(devport));
	devport.devlink = devlink;
	devport.index = port->index;

	return mlx5_devlink_port_function_hw_addr_get(&devport, hw_addr,
						      hw_addr_len, extack);
}

int mlx5_devm_sf_port_function_trust_get(struct mlxdevm_port *port,
					 bool *trusted,
					 struct netlink_ext_ack *extack)
{
	struct devlink_port devport;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(port->devm);
	memset(&devport, 0, sizeof(devport));
	devport.index = port->index;
	return mlx5_devlink_port_function_trust_get(devlink, &devport,
						    trusted, extack);
}

int mlx5_devm_sf_port_fn_hw_addr_set(struct mlxdevm_port *port,
				     const u8 *hw_addr, int hw_addr_len,
				     struct netlink_ext_ack *extack)
{
	struct devlink_port devport;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(port->devm);
	memset(&devport, 0, sizeof(devport));
	devport.devlink = devlink;
	devport.index = port->index;
	return mlx5_devlink_port_function_hw_addr_set(&devport, hw_addr,
						      hw_addr_len, extack);
}

int mlx5_devm_sf_port_function_trust_set(struct mlxdevm_port *port,
					 bool trusted,
					 struct netlink_ext_ack *extack)
{
	struct devlink_port devport;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(port->devm);
	memset(&devport, 0, sizeof(devport));
	devport.index = port->index;
	return mlx5_devlink_port_function_trust_set(devlink, &devport,
						    trusted, extack);
}

static
struct mlx5_core_dev *mlx5_devm_core_dev_get(struct mlxdevm *devm_dev)
{
	struct mlx5_devm_device *mlx5_devm;

	mlx5_devm = container_of(devm_dev, struct mlx5_devm_device, device);
	return mlx5_devm->dev;
}

int mlx5_devm_sf_port_fn_cap_get(struct mlxdevm_port *port,
				 struct mlxdevm_port_fn_cap *cap,
				 struct netlink_ext_ack *extack)
{
	int query_out_sz = MLX5_ST_SZ_BYTES(query_hca_cap_out);
	struct mlx5_core_dev *parent_dev;
	struct mlx5_devm_port *mlx5_port;
	struct devlink *devlink;
	unsigned int port_index;
	void *query_ctx;
	void *hca_caps;
	u16 hw_fn_id;
	int ret;

	query_ctx = kzalloc(query_out_sz, GFP_KERNEL);
	if (!query_ctx)
		return -ENOMEM;

	parent_dev = mlx5_devm_core_dev_get(port->devm);

	mlx5_port = container_of(port, struct mlx5_devm_port, port);
	port_index = mlx5_port->port_index;

	devlink = mlxdevm_to_devlink(port->devm);
	ret = mlx5_sf_index_to_hw_id(devlink, &hw_fn_id, port_index, extack);
	if (ret)
		goto out_free;

	ret = mlx5_core_other_function_get_caps(parent_dev, hw_fn_id, query_ctx);
	if (ret)
		goto out_free;

	hca_caps = MLX5_ADDR_OF(query_hca_cap_out, query_ctx, capability);
	if (MLX5_GET(cmd_hca_cap, hca_caps, roce))
		cap->roce = MLXDEVM_PORT_FN_CAP_ROCE_ENABLE;
	else
		cap->roce = MLXDEVM_PORT_FN_CAP_ROCE_DISABLE;
	cap->roce_cap_valid = true;

	cap->max_uc_list = 1 << MLX5_GET(cmd_hca_cap, hca_caps, log_max_current_uc_list);
	cap->uc_list_cap_valid = true;

out_free:
	kfree(query_ctx);
	return ret;
}

int mlx5_devm_sf_port_fn_cap_set(struct mlxdevm_port *port,
				 const struct mlxdevm_port_fn_cap *cap,
				 struct netlink_ext_ack *extack)
{
	int query_out_sz = MLX5_ST_SZ_BYTES(query_hca_cap_out);
	struct mlx5_core_dev *parent_dev;
	struct mlx5_devm_port *mlx5_port;
	struct devlink *devlink;
	unsigned int port_index;
	u8 cap_ilog2_val;
	void *query_ctx;
	void *hca_caps;
	u16 hw_fn_id;
	int ret;

	query_ctx = kzalloc(query_out_sz, GFP_KERNEL);
	if (!query_ctx)
		return -ENOMEM;

	parent_dev = mlx5_devm_core_dev_get(port->devm);

	mlx5_port = container_of(port, struct mlx5_devm_port, port);
	port_index = mlx5_port->port_index;

	devlink = mlxdevm_to_devlink(port->devm);
	ret = mlx5_sf_index_to_hw_id(devlink, &hw_fn_id, port_index, extack);
	if (ret)
		goto out_free;

	ret = mlx5_core_other_function_get_caps(parent_dev, hw_fn_id, query_ctx);
	if (ret)
		goto out_free;

	hca_caps = MLX5_ADDR_OF(query_hca_cap_out, query_ctx, capability);
	if (cap->roce_cap_valid) {
		if (cap->roce == MLXDEVM_PORT_FN_CAP_ROCE_ENABLE)
			MLX5_SET(cmd_hca_cap, hca_caps, roce, true);
		else
			MLX5_SET(cmd_hca_cap, hca_caps, roce, false);
	}
	if (cap->uc_list_cap_valid) {
		/* At least one unicast mac is needed */
		if (cap->max_uc_list == 0) {
			NL_SET_ERR_MSG_MOD(extack, "max_uc_macs value can not be 0.");
			ret = -EOPNOTSUPP;
			goto out_free;
		}
		/* Check if its power of 2 or not */
		if (cap->max_uc_list & (cap->max_uc_list - 1)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Only power of 2 values are supported for max_uc_macs.");
			ret = -EOPNOTSUPP;
			goto out_free;
		}
		cap_ilog2_val = ilog2(cap->max_uc_list);
		/* PRM has only 5 bits for it */
		if (cap_ilog2_val > 31) {
			NL_SET_ERR_MSG_MOD(extack, "max_uc_macs value is too large.");
			ret = -EOPNOTSUPP;
			goto out_free;
		}
		MLX5_SET(cmd_hca_cap, hca_caps, log_max_current_uc_list, cap_ilog2_val);
	}
	ret = mlx5_core_other_function_set_caps(parent_dev, hca_caps, hw_fn_id);

out_free:
	kfree(query_ctx);
	return ret;
}

static struct mlx5_esw_rate_group *
esw_qos_find_devm_group(struct mlx5_eswitch *esw, const char *group)
{
	struct mlx5_esw_rate_group *tmp;

	if (!refcount_read(&esw->qos.refcnt))
		return NULL;

	list_for_each_entry(tmp, &esw->qos.groups, list) {
		if (tmp->devm.name && !strcmp(tmp->devm.name, group))
			return tmp;
	}

	return NULL;
}

static
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
	if (vport->qos.group)
		*group = vport->qos.group->devm.name;

out:
	mutex_unlock(&esw->state_lock);
	return err;
}

int mlx5_devm_rate_leaf_get(struct mlxdevm_port *port,
			    u64 *tx_max, u64 *tx_share, char **group,
			    struct netlink_ext_ack *extack)
{
	struct devlink_port devport;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(port->devm);
	memset(&devport, 0, sizeof(devport));
	devport.index = port->index;

	return mlx5_devlink_rate_leaf_get(devlink, &devport,
					  tx_max, tx_share, group, extack);
}

static
int mlx5_devlink_rate_leaf_tx_max_set(struct devlink *devlink,
				      struct devlink_port *port,
				      u64 tx_max,
				      struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw;
	struct mlx5_vport *vport;
	int err;

	err = mlx5_esw_get_esw_and_vport(devlink, port, &esw, &vport, extack);
	if (err)
		return err;

	if (!mlx5_esw_allowed(esw))
		return -EPERM;

	mutex_lock(&esw->state_lock);
	err = esw_qos_vport_enable(esw, vport, 0, 0, extack);
	if (err)
		goto unlock;

	err = esw_qos_set_vport_max_rate(esw, vport, tx_max, extack);
unlock:
	mutex_unlock(&esw->state_lock);
	return err;
}

int mlx5_devm_rate_leaf_tx_max_set(struct mlxdevm_port *port,
				   u64 tx_max, struct netlink_ext_ack *extack)
{
	struct devlink_port devport;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(port->devm);
	memset(&devport, 0, sizeof(devport));
	devport.index = port->index;
	return mlx5_devlink_rate_leaf_tx_max_set(devlink, &devport, tx_max, extack);
}

static
int mlx5_devlink_rate_leaf_tx_share_set(struct devlink *devlink,
					struct devlink_port *port,
					u64 tx_share,
					struct netlink_ext_ack *extack)
{
	struct mlx5_vport *vport;
	struct mlx5_eswitch *esw;
	int err;

	err = mlx5_esw_get_esw_and_vport(devlink, port, &esw, &vport, extack);
	if (err)
		return err;

	if (!mlx5_esw_allowed(esw))
		return -EPERM;

	mutex_lock(&esw->state_lock);
	err = esw_qos_vport_enable(esw, vport, 0, 0, extack);
	if (err)
		goto unlock;

	err = esw_qos_set_vport_min_rate(esw, vport, tx_share, extack);
unlock:
	mutex_unlock(&esw->state_lock);
	return err;
}

int mlx5_devm_rate_leaf_tx_share_set(struct mlxdevm_port *port,
				     u64 tx_share, struct netlink_ext_ack *extack)
{
	struct devlink_port devport;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(port->devm);
	memset(&devport, 0, sizeof(devport));
	devport.index = port->index;
	return mlx5_devlink_rate_leaf_tx_share_set(devlink, &devport, tx_share, extack);
}

static
int mlx5_devlink_rate_leaf_group_set(struct devlink *devlink,
				     struct devlink_port *port,
				     const char *group_name,
				     struct netlink_ext_ack *extack)
{
	struct mlx5_esw_rate_group *curr_group, *new_group;
	struct mlx5_eswitch *esw;
	struct mlx5_vport *vport;
	int err;

	err = mlx5_esw_get_esw_and_vport(devlink, port, &esw, &vport, extack);
	if (err)
		return err;

	curr_group = vport->qos.group;
	if (!strlen(group_name)) {
		err = mlx5_esw_qos_vport_update_group(vport->dev->priv.eswitch,
						      vport, NULL, extack);
		if (!err && curr_group && curr_group->devm.name)
			curr_group->num_vports--;
		return err;
	}

	new_group = esw_qos_find_devm_group(esw, group_name);
	if (!new_group)
		return -EINVAL;

	err = mlx5_esw_qos_vport_update_group(vport->dev->priv.eswitch, vport, new_group, extack);
	if (!err) {
		new_group->num_vports++;
		if (curr_group && curr_group->devm.name)
			curr_group->num_vports--;
	}
	return err;
}

int mlx5_devm_rate_leaf_group_set(struct mlxdevm_port *port,
				  const char *group, struct netlink_ext_ack *extack)
{
	struct devlink_port devport;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(port->devm);
	memset(&devport, 0, sizeof(devport));
	devport.index = port->index;
	return mlx5_devlink_rate_leaf_group_set(devlink, &devport, group, extack);
}

int mlx5_devm_rate_node_tx_share_set(struct mlxdevm *devm_dev, const char *group_name,
				     u64 tx_share, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_rate_group *group;
	struct mlx5_core_dev *dev;
	struct mlx5_eswitch *esw;
	struct devlink *devlink;
	int err;

	devlink = mlxdevm_to_devlink(devm_dev);
	dev = devlink_priv(devlink);
	esw = dev->priv.eswitch;

	mutex_lock(&esw->state_lock);
	group = esw_qos_find_devm_group(esw, group_name);
	if (!group) {
		NL_SET_ERR_MSG_MOD(extack, "Can't find node");
		err = -ENODEV;
		goto unlock;
	}
	err = esw_qos_set_group_min_rate(esw, group, tx_share, extack);
	if (!err)
		group->devm.tx_share = tx_share;
unlock:
	mutex_unlock(&esw->state_lock);
	return err;
}

int mlx5_devm_rate_node_tx_max_set(struct mlxdevm *devm_dev, const char *group_name,
				   u64 tx_max, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_rate_group *group;
	struct mlx5_core_dev *dev;
	struct mlx5_eswitch *esw;
	struct devlink *devlink;
	int err;

	devlink = mlxdevm_to_devlink(devm_dev);
	dev = devlink_priv(devlink);
	esw = dev->priv.eswitch;

	mutex_lock(&esw->state_lock);
	group = esw_qos_find_devm_group(esw, group_name);
	if (!group) {
		NL_SET_ERR_MSG_MOD(extack, "Can't find node");
		err = -ENODEV;
		goto unlock;
	}
	err = esw_qos_set_group_max_rate(esw, group, tx_max, extack);
	if (!err)
		group->devm.tx_max = tx_max;
unlock:
	mutex_unlock(&esw->state_lock);
	return err;
}

int mlx5_devm_rate_node_new(struct mlxdevm *devm_dev, const char *group_name,
			    struct netlink_ext_ack *extack)
{
	struct mlx5_esw_rate_group *group;
	struct devlink *devlink;
	struct mlx5_eswitch *esw;
	int err = 0;

	devlink = mlxdevm_to_devlink(devm_dev);

	esw = mlx5_devlink_eswitch_get(devlink);
	if (IS_ERR(esw))
		return PTR_ERR(esw);

	mutex_lock(&esw->state_lock);
	if (esw->mode != MLX5_ESWITCH_OFFLOADS) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Rate node creation supported only in switchdev mode");
		err = -EOPNOTSUPP;
		goto unlock;
	}

	group = esw_qos_create_rate_group(esw, MLX5_ESW_QOS_NON_SYSFS_GROUP, extack);
	if (IS_ERR(group)) {
		err = PTR_ERR(group);
		goto unlock;
	}

	group->devm.name = kstrdup(group_name, GFP_KERNEL);
	err = mlxdevm_rate_group_register(devm_dev,
					  &group->devm);

unlock:
	mutex_unlock(&esw->state_lock);
	return err;
}

int mlx5_devm_rate_node_del(struct mlxdevm *devm_dev, const char *group_name,
			    struct netlink_ext_ack *extack)
{
	struct mlx5_esw_rate_group *group;
	struct mlx5_eswitch *esw;
	struct devlink *devlink;
	int err;

	devlink = mlxdevm_to_devlink(devm_dev);

	esw = mlx5_devlink_eswitch_get(devlink);
	if (IS_ERR(esw))
		return PTR_ERR(esw);

	mutex_lock(&esw->state_lock);

	group = esw_qos_find_devm_group(esw, group_name);
	if (!group) {
		NL_SET_ERR_MSG_MOD(extack, "Can't find node");
		err = -ENODEV;
		goto unlock;
	}
	if (group->num_vports) {
		err = -EBUSY;
		NL_SET_ERR_MSG_MOD(extack, "Node has children. Cannot delete node.");
		goto unlock;
	}
	mlxdevm_rate_group_unregister(devm_dev,
				      &group->devm);
	kfree(group->devm.name);
	err = esw_qos_destroy_rate_group(esw, group, extack);
unlock:
	mutex_unlock(&esw->state_lock);
	return err;
}

static const struct mlxdevm_ops mlx5_devm_ops = {
#ifdef CONFIG_MLX5_ESWITCH
	.port_fn_hw_addr_set = mlx5_devm_sf_port_fn_hw_addr_set,
	.port_fn_hw_addr_get = mlx5_devm_sf_port_fn_hw_addr_get,
	.port_new = mlx5_devm_sf_port_new,
	.port_del = mlx5_devm_sf_port_del,
	.port_fn_state_get = mlx5_devm_sf_port_fn_state_get,
	.port_fn_state_set = mlx5_devm_sf_port_fn_state_set,
	.port_fn_cap_get = mlx5_devm_sf_port_fn_cap_get,
	.port_fn_cap_set = mlx5_devm_sf_port_fn_cap_set,
	.rate_leaf_tx_max_set = mlx5_devm_rate_leaf_tx_max_set,
	.rate_leaf_tx_share_set = mlx5_devm_rate_leaf_tx_share_set,
	.rate_leaf_group_set = mlx5_devm_rate_leaf_group_set,
	.rate_leaf_get = mlx5_devm_rate_leaf_get,
	.rate_node_tx_max_set = mlx5_devm_rate_node_tx_max_set,
	.rate_node_tx_share_set = mlx5_devm_rate_node_tx_share_set,
	.rate_node_new = mlx5_devm_rate_node_new,
	.rate_node_del = mlx5_devm_rate_node_del,
	.port_fn_trust_set = mlx5_devm_sf_port_function_trust_set,
	.port_fn_trust_get = mlx5_devm_sf_port_function_trust_get,
#endif
};

static int mlx5_devm_cpu_affinity_validate(struct mlxdevm *devm, u32 id,
					   union mlxdevm_param_value val,
					   struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = mlx5_devm_core_dev_get(devm);
	u16 *arr = val.vu16arr.data;
	int max_eqs_sf;
	int i;

	if (!mlx5_irq_table_have_dedicated_sfs_irqs(mlx5_irq_table_get(dev))) {
		NL_SET_ERR_MSG_MOD(extack, "SF doesn’t have dedicated IRQs");
		return -EOPNOTSUPP;
	}

	for (i = 0; i < val.vu16arr.array_len; i++) {
		if (arr[i] > nr_cpu_ids || arr[i] >= num_present_cpus()) {
			NL_SET_ERR_MSG_MOD(extack, "Some CPUs aren't present");
			return -ERANGE;
		}
		if (!cpu_online(arr[i])) {
			NL_SET_ERR_MSG_MOD(extack, "Some CPUs aren't online");
			return -EINVAL;
		}
	}

	max_eqs_sf = min_t(int, MLX5_COMP_EQS_PER_SF,
			   mlx5_irq_table_get_sfs_vec(mlx5_irq_table_get(dev)));
	if (i > max_eqs_sf) {
		NL_SET_ERR_MSG_MOD(extack, "SF doesn't have enught IRQs");
		return -EINVAL;
	}
	return 0;
}

int mlx5_devm_affinity_get_param(struct mlx5_core_dev *dev, struct cpumask *mask)
{
	struct mlx5_devm_device *mdevn_dev = mlx5_devm_device_get(dev);
	union mlxdevm_param_value val;
	u16 *arr = val.vu16arr.data;
	int err;
	int i;

	err = mlxdevm_param_driverinit_value_get(&mdevn_dev->device,
						 MLX5_DEVM_PARAM_ID_CPU_AFFINITY,
						 &val);
	if (err)
		goto err;
	for (i = 0; i < val.vu16arr.array_len; i++)
		cpumask_set_cpu(arr[i], mask);
	return 0;
err:
	mlx5_core_dbg(dev, "mlxdevm can't get param cpu_affinity. use default policy\n");
	return err;
}

static const struct mlxdevm_param mlx5_devm_params[] = {
	MLXDEVM_PARAM_DRIVER(MLX5_DEVM_PARAM_ID_CPU_AFFINITY, "cpu_affinity",
			     MLXDEVM_PARAM_TYPE_ARRAY_U16,
			     BIT(MLXDEVM_PARAM_CMODE_DRIVERINIT), NULL, NULL,
			     mlx5_devm_cpu_affinity_validate),
};

static void mlx5_devm_set_params_init_values(struct mlxdevm *devm)
{
	struct mlx5_core_dev *dev = mlx5_devm_core_dev_get(devm);
	union mlxdevm_param_value value;
	u16 *arr = value.vu16arr.data;
	cpumask_var_t dev_mask;
	int i = 0;
	int cpu;

	if (!zalloc_cpumask_var(&dev_mask, GFP_KERNEL))
		        return;

	mlx5_core_affinity_get(dev, dev_mask);

	memset(value.vu16arr.data, 0, sizeof(value.vu16arr.data));
	for_each_cpu(cpu, dev_mask) {
		arr[i] = cpu;
		i++;
	}
	value.vu16arr.array_len = i;
	mlxdevm_param_driverinit_value_set(devm, MLX5_DEVM_PARAM_ID_CPU_AFFINITY, value);
	free_cpumask_var(dev_mask);
}

void mlx5_devm_params_publish(struct mlx5_core_dev *dev)
{
	struct mlx5_devm_device *mdevm_dev = mlx5_devm_device_get(dev);

	if (!mlx5_core_is_sf(dev))
		return;

	mlx5_devm_set_params_init_values(&mdevm_dev->device);
	mlxdevm_params_publish(&mdevm_dev->device);
}

int mlx5_devm_register(struct mlx5_core_dev *dev)
{
	struct mlx5_devm_device *mdevm_dev;
	int err;

	mdevm_dev = kzalloc(sizeof(*mdevm_dev), GFP_KERNEL);
	if (!mdevm_dev)
		return -ENOMEM;

	mdevm_dev->dev = dev;
	mdevm_dev->device.ops = &mlx5_devm_ops;
	mdevm_dev->device.device = dev->device;
	INIT_LIST_HEAD(&mdevm_dev->port_list);
	init_rwsem(&mdevm_dev->port_list_rwsem);
	mutex_lock(&mlx5_mlxdevm_mutex);
	list_add(&mdevm_dev->list, &dev_head);
	mutex_unlock(&mlx5_mlxdevm_mutex);
	err = mlxdevm_register(&mdevm_dev->device);
	if (err)
		goto reg_err;

	if (mlx5_core_is_sf(dev))
		err = mlxdevm_params_register(&mdevm_dev->device, mlx5_devm_params,
					      ARRAY_SIZE(mlx5_devm_params));
	if (err)
		goto params_reg_err;

	return 0;

params_reg_err:
	mlxdevm_unregister(&mdevm_dev->device);
reg_err:
	mutex_lock(&mlx5_mlxdevm_mutex);
	list_del(&mdevm_dev->list);
	mutex_unlock(&mlx5_mlxdevm_mutex);
	kfree(mdevm_dev);
	return err;
}

void mlx5_devm_unregister(struct mlx5_core_dev *dev)
{
	struct mlx5_devm_device *mdevm;

	mdevm = mlx5_devm_device_get(dev);
	if (!mdevm)
		return;

	if (mlx5_core_is_sf(dev))
		mlxdevm_params_unregister(&mdevm->device, mlx5_devm_params,
					  ARRAY_SIZE(mlx5_devm_params));

	mlxdevm_unregister(&mdevm->device);

	mutex_lock(&mlx5_mlxdevm_mutex);
	list_del(&mdevm->list);
	mutex_unlock(&mlx5_mlxdevm_mutex);
	kfree(mdevm);
}

void mlx5_devm_rate_nodes_destroy(struct mlx5_core_dev *dev)
{
	struct mlx5_devm_device *mdevm;

	mdevm = mlx5_devm_device_get(dev);
	if (!mdevm)
		return;
	mlxdevm_rate_nodes_destroy(&mdevm->device);
}
