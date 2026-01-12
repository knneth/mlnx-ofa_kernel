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
#include "devlink.h"

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

static int mlx5_devm_eswitch_mode_set(struct mlxdevm *mlxdevm, u16 mode,
				      struct netlink_ext_ack *extack)
{
	struct devlink *devlink;
	devlink = mlxdevm_to_devlink(mlxdevm);

	return mlx5_devlink_eswitch_mode_set(devlink, mode, extack);
}

static int mlx5_devm_eswitch_mode_get(struct mlxdevm *mlxdevm, u16 *mode)
{
	struct devlink *devlink;
	devlink = mlxdevm_to_devlink(mlxdevm);

	return mlx5_devlink_eswitch_mode_get(devlink, mode);
}

static int mlx5_devm_eswitch_inline_mode_set(struct mlxdevm *mlxdevm, u8 mode,
					     struct netlink_ext_ack *extack)
{
	struct devlink *devlink;
	devlink = mlxdevm_to_devlink(mlxdevm);

	return mlx5_devlink_eswitch_inline_mode_set(devlink, mode, extack);
}

static int mlx5_devm_eswitch_inline_mode_get(struct mlxdevm *mlxdevm, u8 *mode)
{
	struct devlink *devlink;
	devlink = mlxdevm_to_devlink(mlxdevm);

	return mlx5_devlink_eswitch_inline_mode_get(devlink, mode);
}

static int mlx5_devm_eswitch_encap_mode_set(struct mlxdevm *mlxdevm,
					    enum mlxdevm_eswitch_encap_mode encap,
					    struct netlink_ext_ack *extack)
{
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(mlxdevm);

	return mlx5_devlink_eswitch_encap_mode_set(devlink,
						   (enum devlink_eswitch_encap_mode)encap,
						   extack);
}

static int mlx5_devm_eswitch_encap_mode_get(struct mlxdevm *mlxdevm,
					    enum mlxdevm_eswitch_encap_mode *encap)
{
	enum devlink_eswitch_encap_mode devlink_encap;
	struct devlink *devlink;
	int err;

	devlink = mlxdevm_to_devlink(mlxdevm);

	err =  mlx5_devlink_eswitch_encap_mode_get(devlink, &devlink_encap);
	if (err)
		return err;
	*encap = (enum mlxdevm_eswitch_encap_mode)devlink_encap;
	return 0;
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

	ret = mlx5_devlink_sf_port_new(devlink, &devl_attrs, extack, &devport);

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

	mdevm_dev = container_of(devm_dev, struct mlx5_devm_device, device);
	xa_erase(&mdevm_dev->devm_sfs, port_index);

	devlink = mlxdevm_to_devlink(devm_dev);

	port = mlxdevm_port_get_by_index(devm_dev, port_index);
	if (!port)
		return -ENODEV;

	return mlx5_devlink_sf_port_del(devlink, port->dl_port, extack);
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
	return mlx5_devlink_port_function_trust_set(devlink, &devport,
						    trusted, extack);
}

static int mlx5_devm_port_function_max_io_eqs_set(struct mlxdevm_port *port,
						  u32 max_io_eqs,
						  struct netlink_ext_ack *extack)
{
	return mlx5_devlink_port_fn_max_io_eqs_set(port->dl_port, max_io_eqs, extack);
}

static int mlx5_devm_port_function_max_io_eqs_get(struct mlxdevm_port *port,
						  u32 *max_io_eqs,
						  struct netlink_ext_ack *extack)
{
	return mlx5_devlink_port_fn_max_io_eqs_get(port->dl_port, max_io_eqs, extack);
}

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
	struct mlx5_vport *vport = mlx5_devlink_port_vport_get(port->dl_port);
	struct mlx5_core_dev *parent_dev;
	void *query_ctx;
	void *hca_caps;
	int ret;

	query_ctx = kzalloc(query_out_sz, GFP_KERNEL);
	if (!query_ctx)
		return -ENOMEM;

	parent_dev = mlx5_devm_core_dev_get(port->mlxdevm);

	ret = mlx5_vport_get_other_func_general_cap(parent_dev, vport->vport, query_ctx);
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
	struct mlx5_vport *vport = mlx5_devlink_port_vport_get(port->dl_port);
	int query_out_sz = MLX5_ST_SZ_BYTES(query_hca_cap_out);
	struct mlx5_core_dev *parent_dev;
	u16 vport_num = vport->vport;
	u8 cap_ilog2_val;
	void *query_ctx;
	void *hca_caps;
	int ret;

	query_ctx = kzalloc(query_out_sz, GFP_KERNEL);
	if (!query_ctx)
		return -ENOMEM;

	parent_dev = mlx5_devm_core_dev_get(port->mlxdevm);

	ret = mlx5_vport_get_other_func_cap(parent_dev, vport_num, query_ctx,
					    MLX5_CAP_GENERAL);
	if (ret)
		goto out_free;

	hca_caps = MLX5_ADDR_OF(query_hca_cap_out, query_ctx, capability);
	if (uc_list->uc_list_cap_valid) {
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
	ret = mlx5_vport_set_other_func_cap(parent_dev, hca_caps, vport_num,
					    MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE);

out_free:
	kfree(query_ctx);
	return ret;
}

static int mlx5_devm_sf_port_fn_roce_get(struct mlxdevm_port *port, bool *is_enabled,
					 struct netlink_ext_ack *extack)
{
	return mlx5_devlink_port_fn_roce_get(port->dl_port, is_enabled, extack);
}

static int mlx5_devm_sf_port_fn_roce_set(struct mlxdevm_port *port, bool enable,
					 struct netlink_ext_ack *extack)
{
	return mlx5_devlink_port_fn_roce_set(port->dl_port, enable, extack);
}

static int mlx5_devm_port_fn_migratable_get(struct mlxdevm_port *port, bool *is_enabled,
				     struct netlink_ext_ack *extack)
{
	return mlx5_devlink_port_fn_migratable_get(port->dl_port, is_enabled, extack);
}

static int mlx5_devm_port_fn_migratable_set(struct mlxdevm_port *port, bool enable,
				     struct netlink_ext_ack *extack)
{
	return mlx5_devlink_port_fn_migratable_set(port->dl_port, enable, extack);
}

static int mlx5_devm_port_fn_ipsec_crypto_get(struct mlxdevm_port *port, bool *is_enabled,
				       struct netlink_ext_ack *extack)
{
	return mlx5_devlink_port_fn_ipsec_crypto_get(port->dl_port, is_enabled, extack);
}

static int mlx5_devm_port_fn_ipsec_crypto_set(struct mlxdevm_port *port, bool enable,
				       struct netlink_ext_ack *extack)
{
	return mlx5_devlink_port_fn_ipsec_crypto_set(port->dl_port, enable, extack);
}

static int mlx5_devm_port_fn_ipsec_packet_get(struct mlxdevm_port *port, bool *is_enabled,
				       struct netlink_ext_ack *extack)
{
	return mlx5_devlink_port_fn_ipsec_packet_get(port->dl_port, is_enabled, extack);
}

static int mlx5_devm_port_fn_ipsec_packet_set(struct mlxdevm_port *port, bool enabled,
				       struct netlink_ext_ack *extack)
{
	return mlx5_devlink_port_fn_ipsec_packet_set(port->dl_port, enabled, extack);
}

static int mlx5_devm_rate_leaf_tx_max_set(struct mlxdevm_rate *rate_leaf, void *priv,
					  u64 tx_max, struct netlink_ext_ack *extack)
{
#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
	return mlx5_esw_devlink_rate_leaf_tx_max_set(NULL, priv, tx_max, extack);
#else
	return -ENOTSUPP;
#endif
}

static int mlx5_devm_rate_leaf_tx_share_set(struct mlxdevm_rate *rate_leaf, void *priv,
					    u64 tx_share, struct netlink_ext_ack *extack)
{
#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
	return mlx5_esw_devlink_rate_leaf_tx_share_set(NULL, priv, tx_share, extack);
#else
	return -ENOTSUPP;
#endif
}

static int mlx5_devm_rate_leaf_parent_set(struct mlxdevm_rate *mlxdevm_rate,
					  struct mlxdevm_rate *parent,
					  void *priv, void *parent_priv,
					  struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node = parent ? parent_priv : NULL;
	struct mlx5_vport *vport = priv;

	return mlx5_esw_common_rate_leaf_parent_set(node, vport, extack);
}

static int mlx5_devm_rate_node_parent_set(struct mlxdevm_rate *mlxdevm_rate,
					  struct mlxdevm_rate *parent,
					  void *priv, void *parent_priv,
					  struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node = priv, *parent_node;

	if (!parent)
		return mlx5_esw_qos_node_update_parent(node, NULL, extack);

	parent_node = parent_priv;
	return mlx5_esw_qos_node_update_parent(node, parent_node, extack);
}

static int mlx5_devm_rate_node_tx_share_set(struct mlxdevm_rate *rate_node, void *priv,
					    u64 tx_share, struct netlink_ext_ack *extack)
{
#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
	return mlx5_esw_devlink_rate_node_tx_share_set(NULL, priv, tx_share, extack);
#else
	return -ENOTSUPP;
#endif
}

static int mlx5_devm_rate_node_tx_max_set(struct mlxdevm_rate *rate_node, void *priv,
					  u64 tx_max, struct netlink_ext_ack *extack)
{
#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
	return mlx5_esw_devlink_rate_node_tx_max_set(NULL, priv, tx_max, extack);
#else
	return -ENOTSUPP;
#endif
}

static int mlx5_devm_rate_leaf_tc_bw_set(struct mlxdevm_rate *rate_leaf,
					 void *priv,
					 u32 *tc_bw,
					 struct netlink_ext_ack *extack)
{
#ifdef HAVE_DEVLINK_HAS_RATE_TC_BW_SET
	return mlx5_esw_devlink_rate_leaf_tc_bw_set(NULL, priv, tc_bw, extack);
#else
	return -ENOTSUPP;
#endif
}

static int mlx5_devm_rate_node_tc_bw_set(struct mlxdevm_rate *rate_node,
					 void *priv,
					 u32 *tc_bw,
					 struct netlink_ext_ack *extack)
{
#ifdef HAVE_DEVLINK_HAS_RATE_TC_BW_SET
	return mlx5_esw_devlink_rate_node_tc_bw_set(NULL, priv, tc_bw, extack);
#else
	return -ENOTSUPP;
#endif
}

static int mlx5_devm_rate_node_new(struct mlxdevm_rate *rate_node, void **priv,
				   struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(rate_node->mlxdevm);

	esw = mlx5_devlink_eswitch_get(devlink);
	if (IS_ERR(esw))
		return PTR_ERR(esw);

	return mlx5_esw_common_rate_node_new(esw, priv, extack);
}

static int mlx5_devm_rate_node_del(struct mlxdevm_rate *rate_node, void *priv,
				   struct netlink_ext_ack *extack)
{
#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
	return mlx5_esw_devlink_rate_node_del(NULL, priv, extack);
#else
	return -ENOTSUPP;
#endif
}

static int mlx5_devm_info_get(struct mlxdevm *mlxdevm, struct mlxdevm_info_req *req,
			      struct netlink_ext_ack *extack)
{
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(mlxdevm);
	return mlx5_devlink_info_get(devlink, (struct devlink_info_req*)req, extack);
}

static int mlx5_devm_flash_update(struct mlxdevm *mlxdevm,
				  struct mlxdevm_flash_update_params *params,
				  struct netlink_ext_ack *extack)
{
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(mlxdevm);
	return mlx5_devlink_flash_update(devlink,
					 (struct devlink_flash_update_params*)params,
					 extack);
}

#if 0
static int mlx5_devm_reload_down(struct mlxdevm *mlxdevm, bool netns_change,
				 enum mlxdevm_reload_action action,
				 enum mlxdevm_reload_limit limit,
				 struct netlink_ext_ack *extack)
{
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(mlxdevm);

	return mlx5_devlink_reload_down(devlink, netns_change,
				        (enum devlink_reload_action)action,
					(enum devlink_reload_limit)limit, extack);
}

static int mlx5_devm_reload_up(struct mlxdevm *mlxdevm,
			       enum mlxdevm_reload_action action,
			       enum mlxdevm_reload_limit limit, u32 *actions_performed,
			       struct netlink_ext_ack *extack)
{
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(mlxdevm);

	return mlx5_devlink_reload_up(devlink,
				      (enum devlink_reload_action)action,
				      (enum devlink_reload_limit)limit,
				      actions_performed, extack);
}
#endif

static int mlx5_devm_trap_init(struct mlxdevm *mlxdevm, const struct mlxdevm_trap *trap,
				  void *trap_ctx)
{
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(mlxdevm);
	return mlx5_devlink_trap_init(devlink, (struct devlink_trap*)trap, trap_ctx);
}

static void mlx5_devm_trap_fini(struct mlxdevm *mlxdevm, const struct mlxdevm_trap *trap,
			       void *trap_ctx)
{
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(mlxdevm);
	mlx5_devlink_trap_fini(devlink, (struct devlink_trap*) trap, trap_ctx);
}

static int mlx5_devm_trap_action_set(struct mlxdevm *mlxdevm,
				     const struct mlxdevm_trap *trap,
				     enum mlxdevm_trap_action action,
				     struct netlink_ext_ack *extack)
{
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(mlxdevm);

	return mlx5_devlink_trap_action_set(devlink,
					    (struct devlink_trap*)trap,
					    (enum devlink_trap_action)action,
					    extack);
}

/* Both mlx5_devm_ops and mlx5_devm_ports_ops are aligned with upstream devlink
 * version 6.12 callbacks. Need to keep struct updated with devlink
 */
static const struct mlxdevm_ops mlx5_devm_ops = {
#ifdef CONFIG_MLX5_ESWITCH
	.eswitch_mode_set = mlx5_devm_eswitch_mode_set,
	.eswitch_mode_get = mlx5_devm_eswitch_mode_get,
	.eswitch_inline_mode_set = mlx5_devm_eswitch_inline_mode_set,
	.eswitch_inline_mode_get = mlx5_devm_eswitch_inline_mode_get,
	.eswitch_encap_mode_set = mlx5_devm_eswitch_encap_mode_set,
	.eswitch_encap_mode_get = mlx5_devm_eswitch_encap_mode_get,
	.port_new = mlx5_devm_sf_port_new,
	.rate_leaf_tx_max_set = mlx5_devm_rate_leaf_tx_max_set,
	.rate_leaf_tx_share_set = mlx5_devm_rate_leaf_tx_share_set,
	.rate_leaf_parent_set = mlx5_devm_rate_leaf_parent_set,
	.rate_node_parent_set = mlx5_devm_rate_node_parent_set,
	.rate_node_tx_max_set = mlx5_devm_rate_node_tx_max_set,
	.rate_leaf_tc_bw_set = mlx5_devm_rate_leaf_tc_bw_set,
	.rate_node_tc_bw_set = mlx5_devm_rate_node_tc_bw_set,
	.rate_node_tx_share_set = mlx5_devm_rate_node_tx_share_set,
	.rate_node_new = mlx5_devm_rate_node_new,
	.rate_node_del = mlx5_devm_rate_node_del,
	.info_get = mlx5_devm_info_get,
	.flash_update = mlx5_devm_flash_update,
#if 0
	.reload_actions = BIT(MLXDEVM_RELOAD_ACTION_DRIVER_REINIT) |
			  BIT(MLXDEVM_RELOAD_ACTION_FW_ACTIVATE),
	.reload_limits = BIT(MLXDEVM_RELOAD_LIMIT_NO_RESET),
	.reload_down = mlx5_devm_reload_down,
	.reload_up = mlx5_devm_reload_up,
#endif
	.trap_init = mlx5_devm_trap_init,
	.trap_fini = mlx5_devm_trap_fini,
	.trap_action_set = mlx5_devm_trap_action_set,
#endif
};

static const struct mlxdevm_port_ops mlx5_devm_sf_port_ops = {
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

static const struct mlxdevm_port_ops mlx5_devm_pf_vf_port_ops = {
	.port_fn_hw_addr_set = mlx5_devm_sf_port_fn_hw_addr_set,
	.port_fn_hw_addr_get = mlx5_devm_sf_port_fn_hw_addr_get,
	.port_fn_max_io_eqs_get = mlx5_devm_port_function_max_io_eqs_get,
	.port_fn_max_io_eqs_set = mlx5_devm_port_function_max_io_eqs_set,
	.port_fn_roce_set = mlx5_devm_sf_port_fn_roce_set,
	.port_fn_roce_get= mlx5_devm_sf_port_fn_roce_get,
	.port_fn_migratable_get = mlx5_devm_port_fn_migratable_get,
	.port_fn_migratable_set = mlx5_devm_port_fn_migratable_set,
	.port_fn_ipsec_crypto_get = mlx5_devm_port_fn_ipsec_crypto_get,
	.port_fn_ipsec_crypto_set = mlx5_devm_port_fn_ipsec_crypto_set,
	.port_fn_ipsec_packet_get = mlx5_devm_port_fn_ipsec_packet_get,
	.port_fn_ipsec_packet_set = mlx5_devm_port_fn_ipsec_packet_set,
};

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

static int mlx5_devm_enable_roce_validate(struct mlxdevm *mlxdevm, u32 id,
					  union mlxdevm_param_value val,
					  struct netlink_ext_ack *extack)
{
	union devlink_param_value devlink_val;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(mlxdevm);
	devlink_val.vbool = val.vbool;

	return mlx5_devlink_enable_roce_validate(devlink, id, devlink_val, extack);
}

static int mlx5_devm_ct_max_offloaded_conns_get(struct mlxdevm *mlxdevm, u32 id,
						struct mlxdevm_param_gset_ctx *ctx)
{
	struct devlink_param_gset_ctx devlink_ctx;
	struct devlink *devlink;
	
	devlink = mlxdevm_to_devlink(mlxdevm);

	mlx5_devlink_ct_max_offloaded_conns_get(devlink, id, &devlink_ctx);
	ctx->val.vu32 = devlink_ctx.val.vu32; 
	return 0;
}

static int mlx5_devm_ct_max_offloaded_conns_set(struct mlxdevm *mlxdevm, u32 id,
						struct mlxdevm_param_gset_ctx *ctx,
						struct netlink_ext_ack *extack)
{
	struct devlink_param_gset_ctx devlink_ctx;
	struct devlink *devlink;
	
	devlink = mlxdevm_to_devlink(mlxdevm);
	devlink_ctx.val.vu32 = ctx->val.vu32;

	mlx5_devlink_ct_max_offloaded_conns_set(devlink, id, &devlink_ctx, extack);
	return 0;
}

static int mlx5_devm_large_group_num_validate(struct mlxdevm *mlxdevm, u32 id,
					      union mlxdevm_param_value val,
					      struct netlink_ext_ack *extack)
{
	union devlink_param_value devlink_val;
	struct devlink *devlink;
	
	devlink = mlxdevm_to_devlink(mlxdevm);
	devlink_val.vu32 = val.vu32;

	return mlx5_devlink_large_group_num_validate(devlink, id, devlink_val, extack);
}

static int mlx5_devm_eq_depth_validate(struct mlxdevm *mlxdevm, u32 id,
				       union mlxdevm_param_value val,
				       struct netlink_ext_ack *extack)
{
	union devlink_param_value devlink_val;
	struct devlink *devlink;
	
	devlink = mlxdevm_to_devlink(mlxdevm);
	devlink_val.vu32 = val.vu32;

	return mlx5_devlink_eq_depth_validate(devlink, id, devlink_val, extack); 
}

static int mlx5_devm_cpu_affinity_validate(struct mlxdevm *devm, u32 id,
					   union mlxdevm_param_value val,
					   struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = mlx5_devm_core_dev_get(devm);
	u16 *arr = val.vu16arr.data;
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
			   ;
	if (val.vu16arr.array_len > mlx5_irq_table_get_sfs_vec(mlx5_irq_table_get(dev))) {
		NL_SET_ERR_MSG_MOD(extack, "SF doesn't have enught IRQs");
		return -EINVAL;
	}
	return 0;

}

static const struct mlxdevm_param mlx5_devm_params[] = {
	MLXDEVM_PARAM_GENERIC(ENABLE_ROCE, BIT(MLXDEVM_PARAM_CMODE_DRIVERINIT),
			      NULL, NULL, mlx5_devm_enable_roce_validate),
	MLXDEVM_PARAM_DRIVER(MLX5_DEVM_PARAM_ID_CT_MAX_OFFLOADED_CONNS,
			     "ct_max_offloaded_conns", MLXDEVM_PARAM_TYPE_U32,
			     BIT(MLXDEVM_PARAM_CMODE_RUNTIME),
			     mlx5_devm_ct_max_offloaded_conns_get,
			     mlx5_devm_ct_max_offloaded_conns_set,
			     NULL),
#ifdef CONFIG_MLX5_ESWITCH
	MLXDEVM_PARAM_DRIVER(MLX5_DEVM_PARAM_ID_ESW_LARGE_GROUP_NUM,
			     "fdb_large_groups", MLXDEVM_PARAM_TYPE_U32,
			     BIT(MLXDEVM_PARAM_CMODE_DRIVERINIT),
			     NULL, NULL,
			     mlx5_devm_large_group_num_validate),
#endif
	MLXDEVM_PARAM_GENERIC(IO_EQ_SIZE, BIT(MLXDEVM_PARAM_CMODE_DRIVERINIT),
			      NULL, NULL, mlx5_devm_eq_depth_validate),
	MLXDEVM_PARAM_GENERIC(EVENT_EQ_SIZE, BIT(MLXDEVM_PARAM_CMODE_DRIVERINIT),
			      NULL, NULL, mlx5_devm_eq_depth_validate),
	MLXDEVM_PARAM_DRIVER(MLX5_DEVM_PARAM_ID_CPU_AFFINITY, "cpu_affinity",
			     MLXDEVM_PARAM_TYPE_ARRAY_U16,
			     BIT(MLXDEVM_PARAM_CMODE_DRIVERINIT), NULL, NULL,
			     mlx5_devm_cpu_affinity_validate),
};

static int
mlx5_devm_hairpin_num_queues_validate(struct mlxdevm *mlxdevm, u32 id,
				      union mlxdevm_param_value val,
				      struct netlink_ext_ack *extack)
{
	union devlink_param_value devlink_val;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(mlxdevm);
	devlink_val.vu32 = val.vu32;

	return mlx5_devlink_hairpin_num_queues_validate(devlink, id, devlink_val, extack);
}

static int
mlx5_devm_hairpin_queue_size_validate(struct mlxdevm *mlxdevm, u32 id,
				      union mlxdevm_param_value val,
				      struct netlink_ext_ack *extack)
{
	union devlink_param_value devlink_val;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(mlxdevm);
	devlink_val.vu32 = val.vu32;

	return mlx5_devlink_hairpin_queue_size_validate(devlink, id, devlink_val, extack);
}

static const struct mlxdevm_param mlx5_devm_eth_params[] = {
	MLXDEVM_PARAM_GENERIC(ENABLE_ETH, BIT(MLXDEVM_PARAM_CMODE_DRIVERINIT),
			      NULL, NULL, NULL),
	MLXDEVM_PARAM_DRIVER(MLX5_DEVM_PARAM_ID_HAIRPIN_NUM_QUEUES,
			     "hairpin_num_queues", MLXDEVM_PARAM_TYPE_U32,
			     BIT(MLXDEVM_PARAM_CMODE_DRIVERINIT), NULL, NULL,
			     mlx5_devm_hairpin_num_queues_validate),
	MLXDEVM_PARAM_DRIVER(MLX5_DEVM_PARAM_ID_HAIRPIN_QUEUE_SIZE,
			     "hairpin_queue_size", MLXDEVM_PARAM_TYPE_U32,
			     BIT(MLXDEVM_PARAM_CMODE_DRIVERINIT), NULL, NULL,
			     mlx5_devm_hairpin_queue_size_validate),
};

static void mlx5_devm_hairpin_params_init_values(struct mlxdevm *mlxdevm)
{
	struct mlx5_core_dev *dev = mlx5_devm_core_dev_get(mlxdevm);
	union mlxdevm_param_value value;
	u32 link_speed = 0;
	u64 link_speed64;

	/* set hairpin pair per each 50Gbs share of the link */
	mlx5_port_max_linkspeed(dev, &link_speed);
	link_speed = max_t(u32, link_speed, 50000);
	link_speed64 = link_speed;
	do_div(link_speed64, 50000);

	value.vu32 = link_speed64;
	devm_param_driverinit_value_set(
		mlxdevm, MLX5_DEVM_PARAM_ID_HAIRPIN_NUM_QUEUES, value);

	value.vu32 =
		BIT(min_t(u32, 16 - MLX5_MPWRQ_MIN_LOG_STRIDE_SZ(dev),
			  MLX5_CAP_GEN(dev, log_max_hairpin_num_packets)));
	devm_param_driverinit_value_set(
		mlxdevm, MLX5_DEVM_PARAM_ID_HAIRPIN_QUEUE_SIZE, value);
}

static int mlx5_devm_eth_params_register(struct mlxdevm *mlxdevm)
{
	struct mlx5_core_dev *dev = mlx5_devm_core_dev_get(mlxdevm);
	union mlxdevm_param_value value;
	int err;

	if (!mlx5_eth_supported(dev))
		return 0;

	err = devm_params_register(mlxdevm, mlx5_devm_eth_params,
				   ARRAY_SIZE(mlx5_devm_eth_params));
	if (err)
		return err;

	value.vbool = !mlx5_dev_is_lightweight(dev);
	devm_param_driverinit_value_set(mlxdevm,
					MLXDEVM_PARAM_GENERIC_ID_ENABLE_ETH,
					value);

	mlx5_devm_hairpin_params_init_values(mlxdevm);

	return 0;
}

static void mlx5_devm_eth_params_unregister(struct mlxdevm *mlxdevm)
{
	struct mlx5_core_dev *dev = mlx5_devm_core_dev_get(mlxdevm);

	if (!mlx5_eth_supported(dev))
		return;

	devm_params_unregister(mlxdevm, mlx5_devm_eth_params,
			       ARRAY_SIZE(mlx5_devm_eth_params));
}

static int mlx5_devm_enable_rdma_validate(struct mlxdevm *mlxdevm, u32 id,
					  union mlxdevm_param_value val,
					  struct netlink_ext_ack *extack)
{
	union devlink_param_value devlink_val;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(mlxdevm);
	devlink_val.vbool = val.vbool;

	return mlx5_devlink_enable_rdma_validate(devlink, id, devlink_val, extack);
}

static const struct mlxdevm_param mlx5_devm_rdma_params[] = {
	MLXDEVM_PARAM_GENERIC(ENABLE_RDMA, BIT(MLXDEVM_PARAM_CMODE_DRIVERINIT),
			      NULL, NULL, mlx5_devm_enable_rdma_validate),
};

static int mlx5_devm_rdma_params_register(struct mlxdevm *mlxdevm)
{
	struct mlx5_core_dev *dev = mlx5_devm_core_dev_get(mlxdevm);
	union mlxdevm_param_value value;
	int err;

	if (!IS_ENABLED(CONFIG_MLX5_INFINIBAND))
		return 0;

	err = devm_params_register(mlxdevm, mlx5_devm_rdma_params,
				   ARRAY_SIZE(mlx5_devm_rdma_params));
	if (err)
		return err;

	value.vbool = !mlx5_dev_is_lightweight(dev);
	devm_param_driverinit_value_set(mlxdevm,
					MLXDEVM_PARAM_GENERIC_ID_ENABLE_RDMA,
					value);
	return 0;
}

static void mlx5_devm_rdma_params_unregister(struct mlxdevm *mlxdevm)
{
	if (!IS_ENABLED(CONFIG_MLX5_INFINIBAND))
		return;

	devm_params_unregister(mlxdevm, mlx5_devm_rdma_params,
			       ARRAY_SIZE(mlx5_devm_rdma_params));
}

static const struct mlxdevm_param mlx5_devm_vnet_params[] = {
	MLXDEVM_PARAM_GENERIC(ENABLE_VNET, BIT(MLXDEVM_PARAM_CMODE_DRIVERINIT),
			      NULL, NULL, NULL),
};

static int mlx5_devm_vnet_params_register(struct mlxdevm *mlxdevm)
{
	struct mlx5_core_dev *dev = mlx5_devm_core_dev_get(mlxdevm);
	union mlxdevm_param_value value;
	int err;

	if (!mlx5_vnet_supported(dev))
		return 0;

	err = devm_params_register(mlxdevm, mlx5_devm_vnet_params,
				   ARRAY_SIZE(mlx5_devm_vnet_params));
	if (err)
		return err;

	value.vbool = !mlx5_dev_is_lightweight(dev);
	devm_param_driverinit_value_set(mlxdevm,
					MLXDEVM_PARAM_GENERIC_ID_ENABLE_VNET,
					value);
	return 0;
}

static void mlx5_devm_vnet_params_unregister(struct mlxdevm *mlxdevm)
{
	struct mlx5_core_dev *dev = mlx5_devm_core_dev_get(mlxdevm);

	if (!mlx5_vnet_supported(dev))
		return;

	devm_params_unregister(mlxdevm, mlx5_devm_vnet_params,
			       ARRAY_SIZE(mlx5_devm_vnet_params));
}

static int mlx5_devm_auxdev_params_register(struct mlxdevm *mlxdevm)
{
	int err;

	err = mlx5_devm_eth_params_register(mlxdevm);
	if (err)
		return err;

	err = mlx5_devm_rdma_params_register(mlxdevm);
	if (err)
		goto rdma_err;

	err = mlx5_devm_vnet_params_register(mlxdevm);
	if (err)
		goto vnet_err;
	return 0;

vnet_err:
	mlx5_devm_rdma_params_unregister(mlxdevm);
rdma_err:
	mlx5_devm_eth_params_unregister(mlxdevm);
	return err;
}

static void mlx5_devm_auxdev_params_unregister(struct mlxdevm *mlxdevm)
{
	mlx5_devm_vnet_params_unregister(mlxdevm);
	mlx5_devm_rdma_params_unregister(mlxdevm);
	mlx5_devm_eth_params_unregister(mlxdevm);
}

static int mlx5_devm_max_uc_list_validate(struct mlxdevm *mlxdevm, u32 id,
					  union mlxdevm_param_value val,
					  struct netlink_ext_ack *extack)
{
	union devlink_param_value devlink_val;
	struct devlink *devlink;

	devlink = mlxdevm_to_devlink(mlxdevm);
	devlink_val.vu32 = val.vu32;

	return mlx5_devlink_max_uc_list_validate(devlink, id, devlink_val, extack);
}

static const struct mlxdevm_param mlx5_devm_max_uc_list_params[] = {
	MLXDEVM_PARAM_GENERIC(MAX_MACS, BIT(MLXDEVM_PARAM_CMODE_DRIVERINIT),
			      NULL, NULL, mlx5_devm_max_uc_list_validate),
};

static int mlx5_devm_max_uc_list_params_register(struct mlxdevm *mlxdevm)
{
	struct mlx5_core_dev *dev = mlx5_devm_core_dev_get(mlxdevm);
	union mlxdevm_param_value value;
	int err;

	if (!MLX5_CAP_GEN_MAX(dev, log_max_current_uc_list_wr_supported))
		return 0;

	err = devm_params_register(mlxdevm, mlx5_devm_max_uc_list_params,
				   ARRAY_SIZE(mlx5_devm_max_uc_list_params));
	if (err)
		return err;

	value.vu32 = 1 << MLX5_CAP_GEN(dev, log_max_current_uc_list);
	devm_param_driverinit_value_set(mlxdevm,
					MLXDEVM_PARAM_GENERIC_ID_MAX_MACS,
					value);
	return 0;
}

static void
mlx5_devm_max_uc_list_params_unregister(struct mlxdevm *mlxdevm)
{
	struct mlx5_core_dev *dev = mlx5_devm_core_dev_get(mlxdevm);

	if (!MLX5_CAP_GEN_MAX(dev, log_max_current_uc_list_wr_supported))
		return;

	devm_params_unregister(mlxdevm, mlx5_devm_max_uc_list_params,
			       ARRAY_SIZE(mlx5_devm_max_uc_list_params));
}

static void mlx5_devm_set_params_init_values(struct mlxdevm *mlxdevm)
{
	struct mlx5_core_dev *dev = mlx5_devm_core_dev_get(mlxdevm);
	union mlxdevm_param_value value;

	value.vbool = MLX5_CAP_GEN(dev, roce) && !mlx5_dev_is_lightweight(dev);
	devm_param_driverinit_value_set(mlxdevm,
					MLXDEVM_PARAM_GENERIC_ID_ENABLE_ROCE,
					value);

#ifdef CONFIG_MLX5_ESWITCH
	value.vu32 = ESW_OFFLOADS_DEFAULT_NUM_GROUPS;
	devm_param_driverinit_value_set(mlxdevm,
					MLX5_DEVM_PARAM_ID_ESW_LARGE_GROUP_NUM,
					value);
#endif

	value.vu32 = MLX5_COMP_EQ_SIZE;
	devm_param_driverinit_value_set(mlxdevm,
					MLXDEVM_PARAM_GENERIC_ID_IO_EQ_SIZE,
					value);

	value.vu32 = MLX5_NUM_ASYNC_EQE;
	devm_param_driverinit_value_set(mlxdevm,
					MLXDEVM_PARAM_GENERIC_ID_EVENT_EQ_SIZE,
					value);

	/* EQs are created only when rdma or net-dev is creating a CQ.
	 * Hence, the initial affinity shown to the user is empty (0)
	 */
	memset(value.vu16arr.data, 0, sizeof(value.vu16arr.data));
	value.vu16arr.array_len = 0;
	devm_param_driverinit_value_set(mlxdevm, MLX5_DEVM_PARAM_ID_CPU_AFFINITY, value);
}

int mlx5_devm_params_register(struct mlxdevm *mlxdevm)
{
	int err;

	/* Here only the driver init params should be registered.
	 * Runtime params should be registered by the code which
	 * behaviour they configure.
	 */

	err = devm_params_register(mlxdevm, mlx5_devm_params,
				   ARRAY_SIZE(mlx5_devm_params));
	if (err)
		return err;

	mlx5_devm_set_params_init_values(mlxdevm);

	err = mlx5_devm_auxdev_params_register(mlxdevm);
	if (err)
		goto auxdev_reg_err;

	err = mlx5_devm_max_uc_list_params_register(mlxdevm);
	if (err)
		goto max_uc_list_err;

	return 0;

max_uc_list_err:
	mlx5_devm_auxdev_params_unregister(mlxdevm);
auxdev_reg_err:
	devm_params_unregister(mlxdevm, mlx5_devm_params,
			       ARRAY_SIZE(mlx5_devm_params));
	return err;
}

void mlx5_devm_params_unregister(struct mlxdevm *mlxdevm)
{
	mlx5_devm_max_uc_list_params_unregister(mlxdevm);
	mlx5_devm_auxdev_params_unregister(mlxdevm);
	devm_params_unregister(mlxdevm, mlx5_devm_params,
			       ARRAY_SIZE(mlx5_devm_params));
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
	mdevm_dev->device.devlink = priv_to_devlink(dev);
	mdevm_dev->device.mlxdevm_flow = false;
	mutex_lock(&mlx5_mlxdevm_mutex);
	list_add(&mdevm_dev->list, &dev_head);
	mutex_unlock(&mlx5_mlxdevm_mutex);
	mutex_init(&mdevm_dev->device.lock);
	err = mlxdevm_register(&mdevm_dev->device);
	if (err)
		goto reg_err;
	was_registered = 1;

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

	mlxdevm_unregister(&mdevm->device);

	mutex_lock(&mlx5_mlxdevm_mutex);
	list_del(&mdevm->list);
	mutex_unlock(&mlx5_mlxdevm_mutex);
	mlxdevm_put(&mdevm->device);
}
#if 0

#define MLX5_TRAP_DROP(_id, _name, _group_id)				\
	MLXDEVM_TRAP_DRIVER(DROP, DROP, _id, _name,			\
			     MLXDEVM_TRAP_GROUP_GENERIC_ID_##_group_id, \
			     MLXDEVM_TRAP_METADATA_TYPE_F_IN_PORT)

static const struct mlxdevm_trap mlx5_traps_arr[] = {
	MLX5_TRAP_DROP(MLX5_DEVM_TRAP_DRIVER_ID_INGRESS_VLAN_FILTER,
		       "mlxdevm_ingres_vlan_filter", L2_DROPS),
	MLX5_TRAP_DROP(MLX5_DEVM_TRAP_DRIVER_ID_DMAC_FILTER,
		       "mlxdevm_dmac_filter", L2_DROPS),
};

static const struct mlxdevm_trap_group mlx5_trap_groups_arr[] = {
	MLXDEVM_TRAP_GROUP_GENERIC(L2_DROPS, 0),
};

int mlx5_devm_traps_register(struct mlxdevm *mlxdevm)
{
	struct mlx5_core_dev *core_dev = mlx5_devm_core_dev_get(mlxdevm);
	int err;

	err = devm_trap_groups_register(mlxdevm, mlx5_trap_groups_arr,
					ARRAY_SIZE(mlx5_trap_groups_arr));
	if (err)
		return err;

	err = devm_traps_register(mlxdevm, mlx5_traps_arr, ARRAY_SIZE(mlx5_traps_arr),
				  &core_dev->priv);
	if (err)
		goto err_trap_group;
	return 0;

err_trap_group:
	devm_trap_groups_unregister(mlxdevm, mlx5_trap_groups_arr,
				    ARRAY_SIZE(mlx5_trap_groups_arr));
	return err;
}

void mlx5_devm_traps_unregister(struct mlxdevm *mlxdevm)
{
	devm_traps_unregister(mlxdevm, mlx5_traps_arr, ARRAY_SIZE(mlx5_traps_arr));
	devm_trap_groups_unregister(mlxdevm, mlx5_trap_groups_arr,
				    ARRAY_SIZE(mlx5_trap_groups_arr));
}
#endif

static void mlx5_pf_vf_devm_port_attrs_set(struct mlx5_eswitch *esw, u16 vport_num,
					   struct mlxdevm_port *devm_port)
{
	struct mlx5_core_dev *dev = esw->dev;
	struct netdev_phys_item_id ppid = {};
	u32 controller_num = 0;
	bool external;
	u16 pfnum;

	mlx5_esw_get_port_parent_id(dev, &ppid);
	pfnum = PCI_FUNC(dev->pdev->devfn);
	external = mlx5_core_is_ecpf_esw_manager(dev);
	if (external)
		controller_num = dev->priv.eswitch->offloads.host_number + 1;

	if (vport_num == MLX5_VPORT_PF) {
		memcpy(devm_port->attrs.switch_id.id, ppid.id, ppid.id_len);
		devm_port->attrs.switch_id.id_len = ppid.id_len;
		mlxdevm_port_attrs_pci_pf_set(devm_port, controller_num, pfnum, external);
	} else if (mlx5_eswitch_is_vf_vport(esw, vport_num)) {
		memcpy(devm_port->attrs.switch_id.id, ppid.id, ppid.id_len);
		devm_port->attrs.switch_id.id_len = ppid.id_len;
		mlxdevm_port_attrs_pci_vf_set(devm_port, controller_num, pfnum,
					      vport_num - 1, external);
	}  else if (mlx5_core_is_ec_vf_vport(esw->dev, vport_num)) {
		memcpy(devm_port->attrs.switch_id.id, ppid.id, ppid.id_len);
		devm_port->attrs.switch_id.id_len = ppid.id_len;
		mlxdevm_port_attrs_pci_vf_set(devm_port, 0, pfnum,
					      vport_num - 1, false);
	}
}

int mlx5_pf_vf_devm_port_init(struct mlx5_eswitch *esw, struct mlx5_vport *vport)
{
	struct mlxdevm_port *devm_port;
	u16 vport_num = vport->vport;

	if (!mlx5_esw_devlink_port_supported(esw, vport_num))
		return 0;

	devm_port = kzalloc(sizeof(*devm_port), GFP_KERNEL);
	if (!devm_port)
		return -ENOMEM;

	mlx5_pf_vf_devm_port_attrs_set(esw, vport_num, devm_port);

	vport->devm_port = devm_port;
	return 0;
}

static void mlx5_sf_devm_port_attrs_set(struct mlx5_eswitch *esw, struct mlxdevm_port *devm_port,
					u32 controller, u32 sfnum)
{
	struct mlx5_core_dev *dev = esw->dev;
	struct netdev_phys_item_id ppid = {};
	u16 pfnum;

	pfnum = PCI_FUNC(dev->pdev->devfn);
	mlx5_esw_get_port_parent_id(dev, &ppid);
	memcpy(devm_port->attrs.switch_id.id, &ppid.id[0], ppid.id_len);
	devm_port->attrs.switch_id.id_len = ppid.id_len;
	mlxdevm_port_attrs_pci_sf_set(devm_port, controller, pfnum, sfnum, !!controller);
}

int mlx5_sf_devm_port_init(struct mlx5_eswitch *esw, struct mlx5_vport *vport,
			   u32 controller, u32 sfnum)
{
	struct mlxdevm_port *devm_port;

	devm_port = kzalloc(sizeof(*devm_port), GFP_KERNEL);
	if (!devm_port)
		return -ENOMEM;

	mlx5_sf_devm_port_attrs_set(esw, devm_port, controller, sfnum);

	vport->devm_port = devm_port;
	return 0;
}

void mlx5_devm_port_cleanup(struct mlx5_eswitch *esw, struct mlx5_vport *vport)
{
	if (!vport->devm_port)
		return;

	kfree(vport->devm_port);
	vport->devm_port = NULL;
}

int mlx5_devm_port_register(struct mlx5_eswitch *esw, struct mlx5_vport *vport)
{
	struct mlx5_core_dev *dev = esw->dev;
	const struct mlxdevm_port_ops *ops;
	struct mlx5_devm_device *devm_dev;
	u16 vport_num = vport->vport;
	struct mlxdevm_port *devm_port;
	unsigned int dl_port_index;
	int ret;

	devm_dev = mlx5_devm_device_get(dev);
	if (!devm_dev)
		return -ENODEV;

	devm_port = vport->devm_port;
	if (!devm_port)
		return 0;

	if (mlx5_esw_is_sf_vport(esw, vport_num))
		ops = &mlx5_devm_sf_port_ops;
	else if (mlx5_eswitch_is_pf_vf_vport(esw, vport_num))
		ops = &mlx5_devm_pf_vf_port_ops;
	else
		ops = NULL;

	dl_port_index = mlx5_esw_vport_to_devlink_port_index(dev, vport_num);
	ret = devm_port_register_with_ops(&devm_dev->device, devm_port, dl_port_index, ops);
	if (ret)
		goto port_err;

	ret = devm_rate_leaf_create(devm_port, vport, NULL);
	if (ret)
		goto rate_err;

	devm_port->dl_port = &vport->dl_port->dl_port;

	return 0;

rate_err:
	devm_port_unregister(devm_port);
port_err:
	kfree(devm_port);
	return ret;
}

void mlx5_devm_port_unregister(struct mlx5_vport *vport)
{
	struct mlxdevm_port *devm_port;

	if (!vport->devm_port)
		return;
	devm_port = vport->devm_port;

	mlx5_esw_qos_vport_update_parent(vport, NULL, NULL);
	devm_rate_leaf_destroy(devm_port);

	devm_port_unregister(devm_port);
}

void mlx5_devm_rate_nodes_destroy(struct mlx5_core_dev *dev)
{
	struct mlx5_devm_device *mdevm;

	mdevm = mlx5_devm_device_get(dev);
	if (!mdevm)
		return;
	devm_rate_nodes_destroy(&mdevm->device);
}
