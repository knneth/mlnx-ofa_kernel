// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
//
/* Copyright (c) 2021 Mellanox Technologies Ltd. */

#include <linux/log2.h>
#include "mlx5_core.h"
#include "fs_core.h"
#include "eswitch.h"
#include "sf/dev/dev.h"
#include "sf/sf.h"
#include "sf/mlx5_ifc_vhca_event.h"
#include <uapi/linux/mlxdevm.h>
#include "mlx5_devm.h"
#include "mlx5_esw_devm.h"
#include "esw/qos.h"
#include "mlx5_irq.h"

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

void mlx5_devm_sfs_clean(struct mlx5_core_dev *dev)
{
	struct mlx5_devm_device *mdevm = mlx5_devm_device_get(dev);
	unsigned long index;
	void *entry;

	if (!mdevm)
		return;

	xa_for_each(&mdevm->devm_sfs, index, entry)
		xa_erase(&mdevm->devm_sfs, index);
}

bool mlx5_devm_is_devm_sf(struct mlx5_core_dev *dev, u32 sfnum)
{
	struct mlx5_devm_device *mdevm;
	unsigned long index;
	void *entry;

	mdevm = mlx5_devm_device_get(dev);
	if (!mdevm)
		return false;

	xa_for_each(&mdevm->devm_sfs, index, entry) {
		if (xa_to_value(entry) == sfnum) {
			return true;
		}
	}

	return false;
}

static int mlx5_devm_sf_port_new(struct mlxdevm *devm_dev,
				 const struct mlxdevm_port_new_attrs *attrs,
				 struct netlink_ext_ack *extack,
				 unsigned int *new_port_index)
{
	struct devlink_port_new_attrs devl_attrs;
	struct mlx5_devm_device *mdevm_dev;
	struct devlink_port *devport;
	struct devlink *devlink;
	int ret;

	devlink = mlxdevm_to_devlink(devm_dev);
	dm_new_attrs2devl_new_attrs(attrs, &devl_attrs);

	devl_lock(devlink);
	ret = mlx5_devlink_sf_port_new(devlink, &devl_attrs, extack, &devport);
	devl_unlock(devlink);

	if (ret)
		return ret;

	*new_port_index = devport->index;
        mdevm_dev = container_of(devm_dev, struct mlx5_devm_device, device);
        return xa_insert(&mdevm_dev->devm_sfs, *new_port_index,
                         xa_mk_value(attrs->sfnum), GFP_KERNEL);
}

static int mlx5_devm_sf_port_del(struct mlxdevm *devm_dev,
			  unsigned int port_index,
			  struct netlink_ext_ack *extack)
{
	struct mlx5_devm_device *mdevm_dev;
	struct mlxdevm_port *port;
	struct devlink *devlink;
	int ret;

	mdevm_dev = container_of(devm_dev, struct mlx5_devm_device, device);
	xa_erase(&mdevm_dev->devm_sfs, port_index);

	devlink = mlxdevm_to_devlink(devm_dev);

	port = mlxdevm_port_get_by_index(devm_dev, port_index);
	if (!port)
		return -ENODEV;

	devl_lock(devlink);
	ret = mlx5_devlink_sf_port_del(devlink, port->dl_port, extack);
	devl_unlock(devlink);
	return ret;
}

static int mlx5_devm_sf_port_fn_state_get(struct mlxdevm_port *port,
				   enum mlxdevm_port_fn_state *state,
				   enum mlxdevm_port_fn_opstate *opstate,
				   struct netlink_ext_ack *extack)
{
	enum devlink_port_fn_opstate dl_opstate;
	enum devlink_port_fn_state dl_state;
	struct devlink_port devport;
	struct devlink *devlink;
	int ret;

	devlink = mlxdevm_to_devlink(port->mlxdevm);
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

static int mlx5_devm_sf_port_fn_state_set(struct mlxdevm_port *port,
				   enum mlxdevm_port_fn_state state,
				   struct netlink_ext_ack *extack)
{
	enum devlink_port_fn_state dl_state;

	dl_state = mlxdevm_to_devlink_state(state);
	return mlx5_devlink_sf_port_fn_state_set(port->dl_port, dl_state, extack);
}

static int mlx5_devm_sf_port_fn_hw_addr_get(struct mlxdevm_port *port,
				     u8 *hw_addr, int *hw_addr_len,
				     struct netlink_ext_ack *extack)
{
	return mlx5_devlink_port_fn_hw_addr_get(port->dl_port, hw_addr,
						hw_addr_len, extack);
}

static int mlx5_devm_sf_port_function_trust_get(struct mlxdevm_port *port,
						bool *trusted,
						struct netlink_ext_ack *extack)
{
	struct devlink_port devport;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(port->mlxdevm);
	memset(&devport, 0, sizeof(devport));
	devport.index = port->index;
	return mlx5_devlink_port_function_trust_get(devlink, &devport,
						    trusted, extack);
}

static int mlx5_devm_is_sf_active(struct mlxdevm_port *port, struct netlink_ext_ack *extack)
{
	enum mlxdevm_port_fn_opstate opstate;
	enum mlxdevm_port_fn_state state;
	int err;

	err = mlx5_devm_sf_port_fn_state_get(port, &state, &opstate, extack);
	if (err)
		return err;
	return state;
}

static int mlx5_devm_sf_port_fn_hw_addr_set(struct mlxdevm_port *port,
				     const u8 *hw_addr, int hw_addr_len,
				     struct netlink_ext_ack *extack)
{
	return mlx5_devlink_port_fn_hw_addr_set(port->dl_port, hw_addr,
						hw_addr_len, extack);
}

static int mlx5_devm_sf_port_function_trust_set(struct mlxdevm_port *port,
						bool trusted,
						struct netlink_ext_ack *extack)
{
	struct devlink_port devport;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(port->mlxdevm);
	memset(&devport, 0, sizeof(devport));
	devport.index = port->index;

	if (mlx5_devm_is_sf_active(port, extack)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SF must be inactive in order to set trust mode");
		return -EINVAL;
	}
	return mlx5_devlink_port_function_trust_set(devlink, &devport,
						    trusted, extack);
}

static int mlx5_devm_port_function_max_io_eqs_set(struct mlxdevm_port *port,
						  u32 max_io_eqs,
						  struct netlink_ext_ack *extack)
{
	if (mlx5_devm_is_sf_active(port, extack)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SF must be inactive in order to set max_io_eqs");
		return -EINVAL;
	}
	return mlx5_devlink_port_fn_max_io_eqs_set(port->dl_port, max_io_eqs, extack);
}

static int mlx5_devm_port_function_max_io_eqs_get(struct mlxdevm_port *port,
						  u32 *max_io_eqs,
						  struct netlink_ext_ack *extack)
{
	return mlx5_devlink_port_fn_max_io_eqs_get(port->dl_port, max_io_eqs, extack);
}

static
struct mlx5_core_dev *mlx5_devm_core_dev_get(struct mlxdevm *devm_dev)
{
	struct mlx5_devm_device *mlx5_devm;

	mlx5_devm = container_of(devm_dev, struct mlx5_devm_device, device);
	return mlx5_devm->dev;
}

static int mlx5_devm_sf_port_fn_uc_list_get(struct mlxdevm_port *port,
					struct mlxdevm_port_fn_ext_uc_list *uc_list,
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

	parent_dev = mlx5_devm_core_dev_get(port->mlxdevm);

	mlx5_port = container_of(port, struct mlx5_devm_port, port);
	port_index = mlx5_port->port_index;

	devlink = mlxdevm_to_devlink(port->mlxdevm);
	mlx5_sf_index_to_hw_id(devlink, &hw_fn_id, port->dl_port);

	ret = mlx5_vport_get_other_func_general_cap(parent_dev, hw_fn_id, query_ctx);
	if (ret)
		goto out_free;

	hca_caps = MLX5_ADDR_OF(query_hca_cap_out, query_ctx, capability);

	uc_list->max_uc_list = 1 << MLX5_GET(cmd_hca_cap, hca_caps, log_max_current_uc_list);
	uc_list->uc_list_cap_valid = true;

out_free:
	kfree(query_ctx);
	return ret;
}

static int mlx5_devm_sf_port_fn_uc_list_set(struct mlxdevm_port *port,
					    struct mlxdevm_port_fn_ext_uc_list *uc_list,
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

	parent_dev = mlx5_devm_core_dev_get(port->mlxdevm);

	mlx5_port = container_of(port, struct mlx5_devm_port, port);
	port_index = mlx5_port->port_index;

	devlink = mlxdevm_to_devlink(port->mlxdevm);
	mlx5_sf_index_to_hw_id(devlink, &hw_fn_id, port->dl_port);

	ret = mlx5_vport_get_other_func_cap(parent_dev, hw_fn_id, query_ctx,
					    MLX5_CAP_GENERAL);
	if (ret)
		goto out_free;

	hca_caps = MLX5_ADDR_OF(query_hca_cap_out, query_ctx, capability);
	if (uc_list->uc_list_cap_valid) {
		if (mlx5_devm_is_sf_active(port, extack)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "SF must be inactive in order to set max_uc_macs");
			ret = -EINVAL;
			goto out_free;
		}
		/* At least one unicast mac is needed */
		if (uc_list->max_uc_list == 0) {
			NL_SET_ERR_MSG_MOD(extack, "max_uc_macs value can not be 0.");
			ret = -EOPNOTSUPP;
			goto out_free;
		}
		/* Check if its power of 2 or not */
		if (uc_list->max_uc_list & (uc_list->max_uc_list - 1)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Only power of 2 values are supported for max_uc_macs.");
			ret = -EOPNOTSUPP;
			goto out_free;
		}
		cap_ilog2_val = ilog2(uc_list->max_uc_list);
		/* PRM has only 5 bits for it */
		if (cap_ilog2_val > 31) {
			NL_SET_ERR_MSG_MOD(extack, "max_uc_macs value is too large.");
			ret = -EOPNOTSUPP;
			goto out_free;
		}
		MLX5_SET(cmd_hca_cap, hca_caps, log_max_current_uc_list, cap_ilog2_val);
	}
	ret = mlx5_vport_set_other_func_cap(parent_dev, hca_caps, hw_fn_id,
					    MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE);

out_free:
	kfree(query_ctx);
	return ret;
}

static int mlx5_devm_sf_port_fn_roce_set(struct mlxdevm_port *mlxdevm_port, bool enable,
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

	parent_dev = mlx5_devm_core_dev_get(mlxdevm_port->mlxdevm);

	mlx5_port = container_of(mlxdevm_port, struct mlx5_devm_port, port);
	port_index = mlx5_port->port_index;

	devlink = mlxdevm_to_devlink(mlxdevm_port->mlxdevm);
	mlx5_sf_index_to_hw_id(devlink, &hw_fn_id, mlxdevm_port->dl_port);

	ret = mlx5_vport_get_other_func_cap(parent_dev, hw_fn_id, query_ctx,
					    MLX5_CAP_GENERAL);
	if (ret) {
		NL_SET_ERR_MSG_MOD(extack, "Failed getting HCA caps");
		goto out_free;
	}

	hca_caps = MLX5_ADDR_OF(query_hca_cap_out, query_ctx, capability);
	MLX5_SET(cmd_hca_cap, hca_caps, roce, enable);
	ret = mlx5_vport_set_other_func_cap(parent_dev, hca_caps, hw_fn_id,
					    MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE);
	if (ret)
		NL_SET_ERR_MSG_MOD(extack, "Failed setting HCA roce cap");

out_free:
	kfree(query_ctx);
	return ret;
}

static int mlx5_devm_sf_port_fn_roce_get(struct mlxdevm_port *mlxdevm_port, bool *is_enable,
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

	parent_dev = mlx5_devm_core_dev_get(mlxdevm_port->mlxdevm);

	mlx5_port = container_of(mlxdevm_port, struct mlx5_devm_port, port);
	port_index = mlx5_port->port_index;

	devlink = mlxdevm_to_devlink(mlxdevm_port->mlxdevm);
	mlx5_sf_index_to_hw_id(devlink, &hw_fn_id, mlxdevm_port->dl_port);

	ret = mlx5_vport_get_other_func_general_cap(parent_dev, hw_fn_id, query_ctx);
	if (ret)
		goto out_free;

	hca_caps = MLX5_ADDR_OF(query_hca_cap_out, query_ctx, capability);
	*is_enable = MLX5_GET(cmd_hca_cap, hca_caps, roce);

out_free:
	kfree(query_ctx);
	return ret;
}

static int mlx5_devm_rate_leaf_tx_max_set(struct mlxdevm_rate *rate_leaf, void *priv,
					  u64 tx_max, struct netlink_ext_ack *extack)
{
	return mlx5_esw_devlink_rate_leaf_tx_max_set(NULL, priv, tx_max, extack);
}

static int mlx5_devm_rate_leaf_tx_share_set(struct mlxdevm_rate *rate_leaf, void *priv,
					    u64 tx_share, struct netlink_ext_ack *extack)
{
	return mlx5_esw_devlink_rate_leaf_tx_share_set(NULL, priv, tx_share, extack);
}

static int mlx5_devm_rate_leaf_parent_set(struct mlxdevm_rate *mlxdevm_rate,
					  struct mlxdevm_rate *parent,
					  void *priv, void *parent_priv,
					  struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node;
	struct mlx5_vport *vport = priv;

	if (!parent)
		return mlx5_esw_qos_vport_update_parent(vport, NULL, extack);
	node = parent_priv;
	return mlx5_esw_qos_vport_update_parent(vport, node, extack);
}

static int mlx5_devm_rate_node_tx_share_set(struct mlxdevm_rate *rate_node, void *priv,
					    u64 tx_share, struct netlink_ext_ack *extack)
{
	return mlx5_esw_devlink_rate_node_tx_share_set(NULL, priv, tx_share, extack);
}

static int mlx5_devm_rate_node_tx_max_set(struct mlxdevm_rate *rate_node, void *priv,
					  u64 tx_max, struct netlink_ext_ack *extack)
{
	return mlx5_esw_devlink_rate_node_tx_max_set(NULL, priv, tx_max, extack);
}

static int mlx5_devm_rate_node_new(struct mlxdevm_rate *rate_node, void **priv,
				   struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node;
	struct mlx5_eswitch *esw;
	struct devlink *devlink;
	int err = 0;

	devlink = mlxdevm_to_devlink(rate_node->mlxdevm);

	esw = mlx5_devlink_eswitch_get(devlink);
	if (IS_ERR(esw))
		return PTR_ERR(esw);

	esw_qos_lock(esw);
	if (esw->mode != MLX5_ESWITCH_OFFLOADS) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Rate node creation supported only in switchdev mode");
		err = -EOPNOTSUPP;
		goto unlock;
	}

	node = esw_qos_create_vports_sched_node(esw, MLX5_ESW_QOS_NON_SYSFS_GROUP, extack);
	if (IS_ERR(node)) {
		err = PTR_ERR(node);
		goto unlock;
	}
	
	*priv = node;
unlock:
	esw_qos_unlock(esw);
	return err;
}

static int mlx5_devm_rate_node_del(struct mlxdevm_rate *rate_node, void *priv,
				   struct netlink_ext_ack *extack)
{
	return mlx5_esw_devlink_rate_node_del(NULL, priv, extack);
}

/* Both mlx5_devm_ops and mlx5_devm_ports_ops are aligned with upstream devlink
 * version 6.12 callbacks. Need to keep struct updated with devlink
 */
static const struct mlxdevm_ops mlx5_devm_ops = {
#ifdef CONFIG_MLX5_ESWITCH
	.port_new = mlx5_devm_sf_port_new,
	.rate_leaf_tx_max_set = mlx5_devm_rate_leaf_tx_max_set,
	.rate_leaf_tx_share_set = mlx5_devm_rate_leaf_tx_share_set,
	.rate_leaf_parent_set = mlx5_devm_rate_leaf_parent_set,
	.rate_node_tx_max_set = mlx5_devm_rate_node_tx_max_set,
	.rate_node_tx_share_set = mlx5_devm_rate_node_tx_share_set,
	.rate_node_new = mlx5_devm_rate_node_new,
	.rate_node_del = mlx5_devm_rate_node_del,
#endif
};

static const struct mlxdevm_port_ops mlx5_devm_port_ops = {
	.port_fn_hw_addr_set = mlx5_devm_sf_port_fn_hw_addr_set,
	.port_fn_hw_addr_get = mlx5_devm_sf_port_fn_hw_addr_get,
	.port_del = mlx5_devm_sf_port_del,
	.port_fn_state_get = mlx5_devm_sf_port_fn_state_get,
	.port_fn_state_set = mlx5_devm_sf_port_fn_state_set,
	.port_fn_max_io_eqs_get = mlx5_devm_port_function_max_io_eqs_get,
	.port_fn_max_io_eqs_set = mlx5_devm_port_function_max_io_eqs_set,
	.port_fn_trust_set = mlx5_devm_sf_port_function_trust_set,
	.port_fn_trust_get = mlx5_devm_sf_port_function_trust_get,
	.port_fn_ext_uc_list_set = mlx5_devm_sf_port_fn_uc_list_set,
	.port_fn_ext_uc_list_get = mlx5_devm_sf_port_fn_uc_list_get,
	.port_fn_roce_set = mlx5_devm_sf_port_fn_roce_set,
	.port_fn_roce_get= mlx5_devm_sf_port_fn_roce_get,
};

static int mlx5_devm_cpu_affinity_validate(struct mlxdevm *devm, u32 id,
					   union mlxdevm_param_value val,
					   struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = mlx5_devm_core_dev_get(devm);
	u16 *arr = val.vu16arr.data;
	int max_eqs_sf;
	int i;

	if (!mlx5_have_dedicated_irqs(dev)) {
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
	struct mlx5_devm_device *mdevm = mlx5_devm_device_get(dev);
	union mlxdevm_param_value val;
	u16 *arr = val.vu16arr.data;
	int err;
	int i;

	if (!mdevm)
		return -ENODEV;
	err = devm_param_driverinit_value_get(&mdevm->device,
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

int mlx5_devm_affinity_get_weight(struct mlx5_core_dev *dev)
{
	struct mlx5_devm_device *mdevm = mlx5_devm_device_get(dev);
	union mlxdevm_param_value val;
	int err;

	if (!mdevm)
		return 0;
	err = devm_param_driverinit_value_get(&mdevm->device,
					      MLX5_DEVM_PARAM_ID_CPU_AFFINITY,
					      &val);
	if (err)
		return 0;
	return val.vu16arr.array_len;
}

static const struct mlxdevm_param mlx5_devm_params[] = {
	MLXDEVM_PARAM_DRIVER(MLX5_DEVM_PARAM_ID_CPU_AFFINITY, "cpu_affinity",
			     MLXDEVM_PARAM_TYPE_ARRAY_U16,
			     BIT(MLXDEVM_PARAM_CMODE_DRIVERINIT), NULL, NULL,
			     mlx5_devm_cpu_affinity_validate),
};

/* EQs are created only when rdma or net-dev is creating a CQ.
 * Hence, the initial affinity shown to the user is empty (0)
 */
static void mlx5_devm_set_params_init_values(struct mlxdevm *devm)
{
	union mlxdevm_param_value value;

	memset(value.vu16arr.data, 0, sizeof(value.vu16arr.data));
	value.vu16arr.array_len = 0;
	devm_param_driverinit_value_set(devm, MLX5_DEVM_PARAM_ID_CPU_AFFINITY, value);
}

void mlx5_devm_params_publish(struct mlx5_core_dev *dev)
{
	struct mlx5_devm_device *mdevm = mlx5_devm_device_get(dev);

	if (!mdevm || !mlx5_core_is_sf(dev))
		return;
	mlx5_devm_set_params_init_values(&mdevm->device);
}

int mlx5_devm_register(struct mlx5_core_dev *dev)
{
	struct mlx5_devm_device *mdevm_dev;
	int was_registered = 0;
	int err;

	mdevm_dev = kzalloc(sizeof(*mdevm_dev), GFP_KERNEL);
	if (!mdevm_dev)
		return -ENOMEM;

	mdevm_dev->dev = dev;
	mdevm_dev->device.ops = &mlx5_devm_ops;
	mdevm_dev->device.dev = dev->device;
	INIT_LIST_HEAD(&mdevm_dev->port_list);
	init_rwsem(&mdevm_dev->port_list_rwsem);
	mutex_lock(&mlx5_mlxdevm_mutex);
	list_add(&mdevm_dev->list, &dev_head);
	mutex_unlock(&mlx5_mlxdevm_mutex);
	err = mlxdevm_register(&mdevm_dev->device);
	if (err)
		goto reg_err;
	was_registered = 1;

	if (mlx5_core_is_sf(dev))
		err = mlxdevm_params_register(&mdevm_dev->device, mlx5_devm_params,
					      ARRAY_SIZE(mlx5_devm_params));
	if (err)
		goto params_reg_err;

	xa_init(&mdevm_dev->devm_sfs);
	return 0;

params_reg_err:
	mlxdevm_unregister(&mdevm_dev->device);
reg_err:
	mutex_lock(&mlx5_mlxdevm_mutex);
	list_del(&mdevm_dev->list);
	mutex_unlock(&mlx5_mlxdevm_mutex);
	if (was_registered)
		mlxdevm_put(&mdevm_dev->device);
	return err;
}

void mlx5_devm_unregister(struct mlx5_core_dev *dev)
{
	struct mlx5_devm_device *mdevm;

	mdevm = mlx5_devm_device_get(dev);
	if (!mdevm)
		return;

	xa_destroy(&mdevm->devm_sfs);
	if (mlx5_core_is_sf(dev))
		mlxdevm_params_unregister(&mdevm->device, mlx5_devm_params,
					  ARRAY_SIZE(mlx5_devm_params));

	mlxdevm_unregister(&mdevm->device);

	mutex_lock(&mlx5_mlxdevm_mutex);
	list_del(&mdevm->list);
	mutex_unlock(&mlx5_mlxdevm_mutex);
	mlxdevm_put(&mdevm->device);
}

int mlx5_devm_sf_port_register(struct mlx5_core_dev *dev, struct mlx5_vport *vport,
			       u32 controller, u32 sfnum, struct devlink_port *dl_port)
{
	struct mlx5_devm_device *devm_dev;
	struct mlxdevm_port_attrs attrs = {};
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
	pfnum = mlx5_get_dev_index(dev);
	dl_port_index = mlx5_esw_vport_to_devlink_port_index(dev, vport->vport);
	port->sfnum = sfnum;
	port->port_index = dl_port_index;
	port->vport_num = vport->vport;

	attrs.flavour = MLXDEVM_PORT_FLAVOUR_PCI_SF;
	attrs.pci_sf.controller = controller;
	attrs.pci_sf.sf = sfnum;
	attrs.pci_sf.pf = pfnum;
	mlxdevm_port_attrs_set(&port->port, &attrs);

	ret = devm_port_register_with_ops(&devm_dev->device, &port->port, dl_port_index, &mlx5_devm_port_ops);
	if (ret)
		goto port_err;

	ret = devm_rate_leaf_create(&port->port, vport, NULL);
	if (ret)
		goto rate_err;

	port->port.dl_port = dl_port;
	down_write(&devm_dev->port_list_rwsem);
	list_add_tail(&port->list, &devm_dev->port_list);
	up_write(&devm_dev->port_list_rwsem);

	return 0;

rate_err:
	devm_port_unregister(&port->port);
port_err:
	kfree(port);
	return ret;
}

void mlx5_devm_sf_port_unregister(struct mlx5_core_dev *dev, u16 vport_num)
{
	struct mlx5_devm_device *devm_dev;
	struct mlx5_devm_port *port, *tmp;
	const struct mlxdevm_ops *ops;
	bool found = false;

	devm_dev = mlx5_devm_device_get(dev);
	if (!devm_dev)
		return;

	down_write(&devm_dev->port_list_rwsem);
	list_for_each_entry_safe(port, tmp, &devm_dev->port_list, list) {
		if (port->vport_num != vport_num)
			continue;
		/* found the port */
		ops = devm_dev->device.ops;

		ops->rate_leaf_parent_set(NULL, NULL, port->port.mlxdevm_rate->priv, NULL, NULL);

		list_del(&port->list);
		found = true;
		break;
	}
	up_write(&devm_dev->port_list_rwsem);

	devm_rate_leaf_destroy(&port->port);

	WARN_ON(!found);
	devm_port_unregister(&port->port);
	kfree(port);
}

void mlx5_devm_rate_nodes_destroy(struct mlx5_core_dev *dev)
{
	struct mlx5_devm_device *mdevm;

	mdevm = mlx5_devm_device_get(dev);
	if (!mdevm)
		return;
	devm_rate_nodes_destroy(&mdevm->device);
}
