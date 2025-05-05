// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2016 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2016 Jiri Pirko <jiri@mellanox.com>
 */

#include "devl_internal.h"

#define MLXDEVM_PORT_FN_CAPS_VALID_MASK \
	(_BITUL(__MLXDEVM_PORT_FN_ATTR_CAPS_MAX) - 1)

static const struct nla_policy mlxdevm_function_nl_policy[MLXDEVM_PORT_FUNCTION_ATTR_MAX + 1] = {
	[MLXDEVM_PORT_FUNCTION_ATTR_HW_ADDR] = { .type = NLA_BINARY },
	[MLXDEVM_PORT_FN_ATTR_STATE] =
		NLA_POLICY_RANGE(NLA_U8, MLXDEVM_PORT_FN_STATE_INACTIVE,
				 MLXDEVM_PORT_FN_STATE_ACTIVE),
	[MLXDEVM_PORT_FN_ATTR_CAPS] =
		NLA_POLICY_BITFIELD32(MLXDEVM_PORT_FN_CAPS_VALID_MASK),
	[MLXDEVM_PORT_FN_ATTR_MAX_IO_EQS] = { .type = NLA_U32 },
	[MLXDEVM_PORT_FN_ATTR_EXT_TRUST_STATE] = { .type = NLA_U8 },
	[MLXDEVM_PORT_FN_ATTR_EXT_UC_LIST] = { .type = NLA_U32 },
};

#define ASSERT_MLXDEVM_PORT_REGISTERED(mlxdevm_port)				\
	WARN_ON_ONCE(!(mlxdevm_port)->registered)
#define ASSERT_MLXDEVM_PORT_NOT_REGISTERED(mlxdevm_port)			\
	WARN_ON_ONCE((mlxdevm_port)->registered)

struct mlxdevm_port *mlxdevm_port_get_by_index(struct mlxdevm *mlxdevm,
					       unsigned int port_index)
{
	return xa_load(&mlxdevm->ports, port_index);
}
EXPORT_SYMBOL_GPL(mlxdevm_port_get_by_index);

struct mlxdevm_port *mlxdevm_port_get_from_attrs(struct mlxdevm *mlxdevm,
						 struct nlattr **attrs)
{
	if (attrs[MLXDEVM_ATTR_PORT_INDEX]) {
		u32 port_index = nla_get_u32(attrs[MLXDEVM_ATTR_PORT_INDEX]);
		struct mlxdevm_port *mlxdevm_port;

		mlxdevm_port = mlxdevm_port_get_by_index(mlxdevm, port_index);
		if (!mlxdevm_port)
			return ERR_PTR(-ENODEV);
		return mlxdevm_port;
	}
	return ERR_PTR(-EINVAL);
}

struct mlxdevm_port *mlxdevm_port_get_from_info(struct mlxdevm *mlxdevm,
						struct genl_info *info)
{
	return mlxdevm_port_get_from_attrs(mlxdevm, info->attrs);
}

static void mlxdevm_port_fn_cap_fill(struct nla_bitfield32 *caps,
				     u32 cap, bool is_enable)
{
	caps->selector |= cap;
	if (is_enable)
		caps->value |= cap;
}

static int mlxdevm_port_fn_roce_fill(struct mlxdevm_port *mlxdevm_port,
				     struct nla_bitfield32 *caps,
				     struct netlink_ext_ack *extack)
{
	bool is_enable;
	int err;

	if (!mlxdevm_port->ops->port_fn_roce_get)
		return 0;

	err = mlxdevm_port->ops->port_fn_roce_get(mlxdevm_port, &is_enable,
						  extack);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}

	mlxdevm_port_fn_cap_fill(caps, MLXDEVM_PORT_FN_CAP_ROCE, is_enable);
	return 0;
}

static int mlxdevm_port_fn_migratable_fill(struct mlxdevm_port *mlxdevm_port,
					   struct nla_bitfield32 *caps,
					   struct netlink_ext_ack *extack)
{
	bool is_enable;
	int err;

	if (!mlxdevm_port->ops->port_fn_migratable_get ||
	    mlxdevm_port->attrs.flavour != MLXDEVM_PORT_FLAVOUR_PCI_VF)
		return 0;

	err = mlxdevm_port->ops->port_fn_migratable_get(mlxdevm_port,
							&is_enable, extack);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}

	mlxdevm_port_fn_cap_fill(caps, MLXDEVM_PORT_FN_CAP_MIGRATABLE, is_enable);
	return 0;
}

static int mlxdevm_port_fn_ipsec_crypto_fill(struct mlxdevm_port *mlxdevm_port,
					     struct nla_bitfield32 *caps,
					     struct netlink_ext_ack *extack)
{
	bool is_enable;
	int err;

	if (!mlxdevm_port->ops->port_fn_ipsec_crypto_get ||
	    mlxdevm_port->attrs.flavour != MLXDEVM_PORT_FLAVOUR_PCI_VF)
		return 0;

	err = mlxdevm_port->ops->port_fn_ipsec_crypto_get(mlxdevm_port, &is_enable, extack);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}

	mlxdevm_port_fn_cap_fill(caps, MLXDEVM_PORT_FN_CAP_IPSEC_CRYPTO, is_enable);
	return 0;
}

static int mlxdevm_port_fn_ipsec_packet_fill(struct mlxdevm_port *mlxdevm_port,
					     struct nla_bitfield32 *caps,
					     struct netlink_ext_ack *extack)
{
	bool is_enable;
	int err;

	if (!mlxdevm_port->ops->port_fn_ipsec_packet_get ||
	    mlxdevm_port->attrs.flavour != MLXDEVM_PORT_FLAVOUR_PCI_VF)
		return 0;

	err = mlxdevm_port->ops->port_fn_ipsec_packet_get(mlxdevm_port, &is_enable, extack);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}

	mlxdevm_port_fn_cap_fill(caps, MLXDEVM_PORT_FN_CAP_IPSEC_PACKET, is_enable);
	return 0;
}

static int mlxdevm_port_fn_caps_fill(struct mlxdevm_port *mlxdevm_port,
				     struct sk_buff *msg,
				     struct netlink_ext_ack *extack,
				     bool *msg_updated)
{
	struct nla_bitfield32 caps = {};
	int err;

	err = mlxdevm_port_fn_roce_fill(mlxdevm_port, &caps, extack);
	if (err)
		return err;

	err = mlxdevm_port_fn_migratable_fill(mlxdevm_port, &caps, extack);
	if (err)
		return err;

	err = mlxdevm_port_fn_ipsec_crypto_fill(mlxdevm_port, &caps, extack);
	if (err)
		return err;

	err = mlxdevm_port_fn_ipsec_packet_fill(mlxdevm_port, &caps, extack);
	if (err)
		return err;

	if (!caps.selector)
		return 0;
	err = nla_put_bitfield32(msg, MLXDEVM_PORT_FN_ATTR_CAPS, caps.value,
				 caps.selector);
	if (err)
		return err;

	*msg_updated = true;
	return 0;
}

static int mlxdevm_port_fn_max_io_eqs_fill(struct mlxdevm_port *port,
					   struct sk_buff *msg,
					   struct netlink_ext_ack *extack,
					   bool *msg_updated)
{
	u32 max_io_eqs;
	int err;

	if (!port->ops->port_fn_max_io_eqs_get)
		return 0;

	err = port->ops->port_fn_max_io_eqs_get(port, &max_io_eqs, extack);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}
	err = nla_put_u32(msg, MLXDEVM_PORT_FN_ATTR_MAX_IO_EQS, max_io_eqs);
	if (err)
		return err;
	*msg_updated = true;
	return 0;
}
#if 0

int devlink_nl_port_handle_fill(struct sk_buff *msg, struct devlink_port *devlink_port)
{
	if (devlink_nl_put_handle(msg, devlink_port->devlink))
		return -EMSGSIZE;
	if (nla_put_u32(msg, DEVLINK_ATTR_PORT_INDEX, devlink_port->index))
		return -EMSGSIZE;
	return 0;
}

size_t devlink_nl_port_handle_size(struct devlink_port *devlink_port)
{
	struct devlink *devlink = devlink_port->devlink;

	return nla_total_size(strlen(devlink->dev->bus->name) + 1) /* DEVLINK_ATTR_BUS_NAME */
	     + nla_total_size(strlen(dev_name(devlink->dev)) + 1) /* DEVLINK_ATTR_DEV_NAME */
	     + nla_total_size(4); /* DEVLINK_ATTR_PORT_INDEX */
}
#endif

static int mlxdevm_nl_port_attrs_put(struct sk_buff *msg,
				     struct mlxdevm_port *mlxdevm_port)
{
	struct mlxdevm_port_attrs *attrs = &mlxdevm_port->attrs;

	if (!mlxdevm_port->attrs_set)
		return 0;
	if (attrs->lanes) {
		if (nla_put_u32(msg, MLXDEVM_ATTR_PORT_LANES, attrs->lanes))
			return -EMSGSIZE;
	}
	if (nla_put_u8(msg, MLXDEVM_ATTR_PORT_SPLITTABLE, attrs->splittable))
		return -EMSGSIZE;
	if (nla_put_u16(msg, MLXDEVM_ATTR_PORT_FLAVOUR, attrs->flavour))
		return -EMSGSIZE;
	switch (mlxdevm_port->attrs.flavour) {
	case MLXDEVM_PORT_FLAVOUR_PCI_PF:
		if (nla_put_u32(msg, MLXDEVM_ATTR_PORT_CONTROLLER_NUMBER,
				attrs->pci_pf.controller) ||
		    nla_put_u16(msg, MLXDEVM_ATTR_PORT_PCI_PF_NUMBER, attrs->pci_pf.pf))
			return -EMSGSIZE;
		if (nla_put_u8(msg, MLXDEVM_ATTR_PORT_EXTERNAL, attrs->pci_pf.external))
			return -EMSGSIZE;
		break;
	case MLXDEVM_PORT_FLAVOUR_PCI_VF:
		if (nla_put_u32(msg, MLXDEVM_ATTR_PORT_CONTROLLER_NUMBER,
				attrs->pci_vf.controller) ||
		    nla_put_u16(msg, MLXDEVM_ATTR_PORT_PCI_PF_NUMBER, attrs->pci_vf.pf) ||
		    nla_put_u16(msg, MLXDEVM_ATTR_PORT_PCI_VF_NUMBER, attrs->pci_vf.vf))
			return -EMSGSIZE;
		if (nla_put_u8(msg, MLXDEVM_ATTR_PORT_EXTERNAL, attrs->pci_vf.external))
			return -EMSGSIZE;
		break;
	case MLXDEVM_PORT_FLAVOUR_PCI_SF:
		if (nla_put_u32(msg, MLXDEVM_ATTR_PORT_CONTROLLER_NUMBER,
				attrs->pci_sf.controller) ||
		    nla_put_u16(msg, MLXDEVM_ATTR_PORT_PCI_PF_NUMBER,
				attrs->pci_sf.pf) ||
		    nla_put_u32(msg, MLXDEVM_ATTR_PORT_PCI_SF_NUMBER,
				attrs->pci_sf.sf))
			return -EMSGSIZE;
		break;
	case MLXDEVM_PORT_FLAVOUR_PHYSICAL:
	case MLXDEVM_PORT_FLAVOUR_CPU:
	case MLXDEVM_PORT_FLAVOUR_DSA:
		if (nla_put_u32(msg, MLXDEVM_ATTR_PORT_NUMBER,
				attrs->phys.port_number))
			return -EMSGSIZE;
		if (!attrs->split)
			return 0;
		if (nla_put_u32(msg, MLXDEVM_ATTR_PORT_SPLIT_GROUP,
				attrs->phys.port_number))
			return -EMSGSIZE;
		if (nla_put_u32(msg, MLXDEVM_ATTR_PORT_SPLIT_SUBPORT_NUMBER,
				attrs->phys.split_subport_number))
			return -EMSGSIZE;
		break;
	default:
		break;
	}
	return 0;
}

static int mlxdevm_port_fn_hw_addr_fill(struct mlxdevm_port *port,
					struct sk_buff *msg,
					struct netlink_ext_ack *extack,
					bool *msg_updated)
{
	u8 hw_addr[MAX_ADDR_LEN];
	int hw_addr_len;
	int err;

	if (!port->ops->port_fn_hw_addr_get)
		return 0;

	err = port->ops->port_fn_hw_addr_get(port, hw_addr, &hw_addr_len,
					     extack);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}
	err = nla_put(msg, MLXDEVM_PORT_FUNCTION_ATTR_HW_ADDR, hw_addr_len, hw_addr);
	if (err)
		return err;
	*msg_updated = true;
	return 0;
}

static bool
mlxdevm_port_fn_state_valid(enum mlxdevm_port_fn_state state)
{
	return state == MLXDEVM_PORT_FN_STATE_INACTIVE ||
	       state == MLXDEVM_PORT_FN_STATE_ACTIVE;
}

static bool
mlxdevm_port_fn_opstate_valid(enum mlxdevm_port_fn_opstate opstate)
{
	return opstate == MLXDEVM_PORT_FN_OPSTATE_DETACHED ||
	       opstate == MLXDEVM_PORT_FN_OPSTATE_ATTACHED;
}

static int mlxdevm_port_fn_state_fill(struct mlxdevm_port *port,
				      struct sk_buff *msg,
				      struct netlink_ext_ack *extack,
				      bool *msg_updated)
{
	enum mlxdevm_port_fn_opstate opstate;
	enum mlxdevm_port_fn_state state;
	int err;

	if (!port->ops->port_fn_state_get)
		return 0;

	err = port->ops->port_fn_state_get(port, &state, &opstate, extack);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}
	if (!mlxdevm_port_fn_state_valid(state)) {
		WARN_ON_ONCE(1);
		NL_SET_ERR_MSG(extack, "Invalid state read from driver");
		return -EINVAL;
	}
	if (!mlxdevm_port_fn_opstate_valid(opstate)) {
		WARN_ON_ONCE(1);
		NL_SET_ERR_MSG(extack, "Invalid operational state read from driver");
		return -EINVAL;
	}
	if (nla_put_u8(msg, MLXDEVM_PORT_FN_ATTR_STATE, state) ||
	    nla_put_u8(msg, MLXDEVM_PORT_FN_ATTR_OPSTATE, opstate))
		return -EMSGSIZE;
	*msg_updated = true;
	return 0;
}

static int
mlxdevm_port_fn_trust_fill(struct mlxdevm_port *port,
			   struct sk_buff *msg,
			   struct netlink_ext_ack *extack,
			   bool *msg_updated)
{
	bool trust;
	int err = 0;

	if (!port->ops->port_fn_trust_get)
		return 0;

	err = port->ops->port_fn_trust_get(port, &trust, extack);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}

	if (nla_put_u8(msg, MLXDEVM_PORT_FN_ATTR_EXT_TRUST_STATE, trust))
		return -EMSGSIZE;
	*msg_updated = true;
	return 0;
}

static int mlxdevm_port_fn_ext_uc_list_fill(struct mlxdevm_port *port,
					    struct sk_buff *msg,
					    struct netlink_ext_ack *extack,
					    bool *msg_updated)
{
	struct mlxdevm_port_fn_ext_uc_list uc_list;
	int err;

	if (!port->ops->port_fn_ext_uc_list_get)
		return 0;

	err = port->ops->port_fn_ext_uc_list_get(port, &uc_list, extack);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}
	if (uc_list.uc_list_cap_valid) {
		if (nla_put_u32(msg, MLXDEVM_PORT_FN_ATTR_EXT_UC_LIST, uc_list.max_uc_list))
			return -EMSGSIZE;
	}

	*msg_updated = true;
	return 0;
}

static int
mlxdevm_port_fn_mig_set(struct mlxdevm_port *mlxdevm_port, bool enable,
			struct netlink_ext_ack *extack)
{
	return mlxdevm_port->ops->port_fn_migratable_set(mlxdevm_port, enable,
							 extack);
}

static int
mlxdevm_port_fn_roce_set(struct mlxdevm_port *mlxdevm_port, bool enable,
			 struct netlink_ext_ack *extack)
{
	return mlxdevm_port->ops->port_fn_roce_set(mlxdevm_port, enable,
						   extack);
}

static int
mlxdevm_port_fn_ipsec_crypto_set(struct mlxdevm_port *mlxdevm_port, bool enable,
				 struct netlink_ext_ack *extack)
{
	return mlxdevm_port->ops->port_fn_ipsec_crypto_set(mlxdevm_port, enable, extack);
}

static int
mlxdevm_port_fn_ipsec_packet_set(struct mlxdevm_port *mlxdevm_port, bool enable,
				 struct netlink_ext_ack *extack)
{
	return mlxdevm_port->ops->port_fn_ipsec_packet_set(mlxdevm_port, enable, extack);
}

static int mlxdevm_port_fn_caps_set(struct mlxdevm_port *mlxdevm_port,
				    const struct nlattr *attr,
				    struct netlink_ext_ack *extack)
{
	struct nla_bitfield32 caps;
	u32 caps_value;
	int err;

	caps = nla_get_bitfield32(attr);
	caps_value = caps.value & caps.selector;
	if (caps.selector & MLXDEVM_PORT_FN_CAP_ROCE) {
		err = mlxdevm_port_fn_roce_set(mlxdevm_port,
					       caps_value & MLXDEVM_PORT_FN_CAP_ROCE,
					       extack);
		if (err)
			return err;
	}
	if (caps.selector & MLXDEVM_PORT_FN_CAP_MIGRATABLE) {
		err = mlxdevm_port_fn_mig_set(mlxdevm_port, caps_value &
					      MLXDEVM_PORT_FN_CAP_MIGRATABLE,
					      extack);
		if (err)
			return err;
	}
	if (caps.selector & MLXDEVM_PORT_FN_CAP_IPSEC_CRYPTO) {
		err = mlxdevm_port_fn_ipsec_crypto_set(mlxdevm_port, caps_value &
						       MLXDEVM_PORT_FN_CAP_IPSEC_CRYPTO,
						       extack);
		if (err)
			return err;
	}
	if (caps.selector & MLXDEVM_PORT_FN_CAP_IPSEC_PACKET) {
		err = mlxdevm_port_fn_ipsec_packet_set(mlxdevm_port, caps_value &
						       MLXDEVM_PORT_FN_CAP_IPSEC_PACKET,
						       extack);
		if (err)
			return err;
	}
	return 0;
}

static int
mlxdevm_port_fn_max_io_eqs_set(struct mlxdevm_port *mlxdevm_port,
			       const struct nlattr *attr,
			       struct netlink_ext_ack *extack)
{
	u32 max_io_eqs;

	max_io_eqs = nla_get_u32(attr);
	return mlxdevm_port->ops->port_fn_max_io_eqs_set(mlxdevm_port,
							 max_io_eqs, extack);
}
static int
mlxdevm_nl_port_function_attrs_put(struct sk_buff *msg, struct mlxdevm_port *port,
				   struct netlink_ext_ack *extack)
{
	struct nlattr *function_attr;
	bool msg_updated = false;
	int err;

	function_attr = nla_nest_start_noflag(msg, MLXDEVM_ATTR_PORT_FUNCTION);
	if (!function_attr)
		return -EMSGSIZE;

	err = mlxdevm_port_fn_hw_addr_fill(port, msg, extack, &msg_updated);
	if (err)
		goto out;
	err = mlxdevm_port_fn_caps_fill(port, msg, extack, &msg_updated);
	if (err)
		goto out;
	err = mlxdevm_port_fn_state_fill(port, msg, extack, &msg_updated);
	if (err)
		goto out;
	err = mlxdevm_port_fn_max_io_eqs_fill(port, msg, extack, &msg_updated);
	if (err)
		goto out;
	err = mlxdevm_port_fn_trust_fill(port, msg, extack, &msg_updated);
	if (err)
		goto out;
	err = mlxdevm_port_fn_ext_uc_list_fill(port, msg, extack, &msg_updated);
	if (err)
		goto out;

	err = mlxdevm_rel_mlxdevm_handle_put(msg, port->mlxdevm,
					     port->rel_index,
					     MLXDEVM_PORT_FN_ATTR_MLXDEVM,
					     &msg_updated);

out:
	if (err || !msg_updated)
		nla_nest_cancel(msg, function_attr);
	else
		nla_nest_end(msg, function_attr);
	return err;
}

static int mlxdevm_nl_port_fill(struct sk_buff *msg,
				struct mlxdevm_port *mlxdevm_port,
				enum mlxdevm_command cmd, u32 portid, u32 seq,
				int flags, struct netlink_ext_ack *extack)
{
	struct mlxdevm *mlxdevm = mlxdevm_port->mlxdevm;
	void *hdr;

	hdr = genlmsg_put(msg, portid, seq, &mlxdevm_nl_family, flags, cmd);
	if (!hdr)
		return -EMSGSIZE;

	if (mlxdevm_nl_put_handle(msg, mlxdevm))
		goto nla_put_failure;
	if (nla_put_u32(msg, MLXDEVM_ATTR_PORT_INDEX, mlxdevm_port->index))
		goto nla_put_failure;

	spin_lock_bh(&mlxdevm_port->type_lock);
	if (nla_put_u16(msg, MLXDEVM_ATTR_PORT_TYPE, mlxdevm_port->type))
		goto nla_put_failure_type_locked;
	if (mlxdevm_port->desired_type != MLXDEVM_PORT_TYPE_NOTSET &&
	    nla_put_u16(msg, MLXDEVM_ATTR_PORT_DESIRED_TYPE,
			mlxdevm_port->desired_type))
		goto nla_put_failure_type_locked;
	if (mlxdevm_port->type == MLXDEVM_PORT_TYPE_ETH) {
		if (mlxdevm_port->type_eth.netdev &&
		    (nla_put_u32(msg, MLXDEVM_ATTR_PORT_NETDEV_IFINDEX,
				 mlxdevm_port->type_eth.netdev->ifindex) ||
		     nla_put_string(msg, MLXDEVM_ATTR_PORT_NETDEV_NAME,
				    mlxdevm_port->type_eth.netdev->name)))
			goto nla_put_failure_type_locked;
	}
	if (mlxdevm_port->type == MLXDEVM_PORT_TYPE_IB) {
		struct ib_device *ibdev = mlxdevm_port->type_ib.ibdev;

		if (ibdev &&
		    nla_put_string(msg, MLXDEVM_ATTR_PORT_IBDEV_NAME,
				   ibdev->name))
			goto nla_put_failure_type_locked;
	}
	spin_unlock_bh(&mlxdevm_port->type_lock);
	if (mlxdevm_nl_port_attrs_put(msg, mlxdevm_port))
		goto nla_put_failure;
	if (mlxdevm_nl_port_function_attrs_put(msg, mlxdevm_port, extack))
		goto nla_put_failure;
	if (mlxdevm_port->linecard &&
	    nla_put_u32(msg, MLXDEVM_ATTR_LINECARD_INDEX,
			mlxdevm_linecard_index(mlxdevm_port->linecard)))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);
	return 0;

nla_put_failure_type_locked:
	spin_unlock_bh(&mlxdevm_port->type_lock);
nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

static void mlxdevm_port_notify(struct mlxdevm_port *mlxdevm_port,
				enum mlxdevm_command cmd)
{
	struct mlxdevm *mlxdevm = mlxdevm_port->mlxdevm;
	struct mlxdevm_obj_desc desc;
	struct sk_buff *msg;
	int err;

	WARN_ON(cmd != MLXDEVM_CMD_PORT_NEW && cmd != MLXDEVM_CMD_PORT_DEL);

	if (!__devm_is_registered(mlxdevm) || !mlxdevm_nl_notify_need(mlxdevm))
		return;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	err = mlxdevm_nl_port_fill(msg, mlxdevm_port, cmd, 0, 0, 0, NULL);
	if (err) {
		nlmsg_free(msg);
		return;
	}

	mlxdevm_nl_obj_desc_init(&desc, mlxdevm);
	mlxdevm_nl_obj_desc_port_set(&desc, mlxdevm_port);
	mlxdevm_nl_notify_send_desc(mlxdevm, msg, &desc);
}
#if 0

static void devlink_ports_notify(struct devlink *devlink,
				 enum devlink_command cmd)
{
	struct devlink_port *devlink_port;
	unsigned long port_index;

	xa_for_each(&devlink->ports, port_index, devlink_port)
		devlink_port_notify(devlink_port, cmd);
}

void devlink_ports_notify_register(struct devlink *devlink)
{
	devlink_ports_notify(devlink, DEVLINK_CMD_PORT_NEW);
}

void devlink_ports_notify_unregister(struct devlink *devlink)
{
	devlink_ports_notify(devlink, DEVLINK_CMD_PORT_DEL);
}
#endif

int mlxdevm_nl_port_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm_port *mlxdevm_port = info->user_ptr[1];
	struct sk_buff *msg;
	int err;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	err = mlxdevm_nl_port_fill(msg, mlxdevm_port, MLXDEVM_CMD_PORT_NEW,
				   info->snd_portid, info->snd_seq, 0,
				   info->extack);
	if (err) {
		nlmsg_free(msg);
		return err;
	}

	return genlmsg_reply(msg, info);
}

static int
mlxdevm_nl_port_get_dump_one(struct sk_buff *msg, struct mlxdevm *mlxdevm,
			     struct netlink_callback *cb, int flags)
{
	struct mlxdevm_nl_dump_state *state = mlxdevm_dump_state(cb);
	struct mlxdevm_port *mlxdevm_port;
	unsigned long port_index;
	int err = 0;

	xa_for_each_start(&mlxdevm->ports, port_index, mlxdevm_port, state->idx) {
		err = mlxdevm_nl_port_fill(msg, mlxdevm_port,
					   MLXDEVM_CMD_PORT_NEW,
					   NETLINK_CB(cb->skb).portid,
					   cb->nlh->nlmsg_seq, flags,
					   cb->extack);
		if (err) {
			state->idx = port_index;
			break;
		}
	}

	return err;
}

int mlxdevm_nl_port_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	return mlxdevm_nl_dumpit(skb, cb, mlxdevm_nl_port_get_dump_one);
}

static int mlxdevm_port_type_set(struct mlxdevm_port *mlxdevm_port,
				 enum mlxdevm_port_type port_type)

{
	int err;

	if (!mlxdevm_port->ops->port_type_set)
		return -EOPNOTSUPP;

	if (port_type == mlxdevm_port->type)
		return 0;

	err = mlxdevm_port->ops->port_type_set(mlxdevm_port, port_type);
	if (err)
		return err;

	mlxdevm_port->desired_type = port_type;
	mlxdevm_port_notify(mlxdevm_port, MLXDEVM_CMD_PORT_NEW);
	return 0;
}

static int mlxdevm_port_function_hw_addr_set(struct mlxdevm_port *port,
					     const struct nlattr *attr,
					     struct netlink_ext_ack *extack)
{
	const u8 *hw_addr;
	int hw_addr_len;

	hw_addr = nla_data(attr);
	hw_addr_len = nla_len(attr);
	if (hw_addr_len > MAX_ADDR_LEN) {
		NL_SET_ERR_MSG(extack, "Port function hardware address too long");
		return -EINVAL;
	}
	if (port->type == MLXDEVM_PORT_TYPE_ETH) {
		if (hw_addr_len != ETH_ALEN) {
			NL_SET_ERR_MSG(extack, "Address must be 6 bytes for Ethernet device");
			return -EINVAL;
		}
		if (!is_unicast_ether_addr(hw_addr)) {
			NL_SET_ERR_MSG(extack, "Non-unicast hardware address unsupported");
			return -EINVAL;
		}
	}

	return port->ops->port_fn_hw_addr_set(port, hw_addr, hw_addr_len,
					      extack);
}

static int mlxdevm_port_fn_trust_set(struct mlxdevm_port *port,
				     const struct nlattr *attr,
				     struct netlink_ext_ack *extack)
{
	const struct mlxdevm_port_ops *ops;
	bool trust;

	trust = nla_get_u8(attr);
	ops = port->ops;
	if (!ops->port_fn_trust_set) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Function does not support trust setting");
		return -EOPNOTSUPP;
	}
	return ops->port_fn_trust_set(port, trust, extack);
}

static int mlxdevm_port_fn_state_set(struct mlxdevm_port *port,
				     const struct nlattr *attr,
				     struct netlink_ext_ack *extack)
{
	enum mlxdevm_port_fn_state state;

	state = nla_get_u8(attr);
	return port->ops->port_fn_state_set(port, state, extack);
}

static int mlxdevm_port_fn_ext_uc_list_set(struct mlxdevm_port *port,
				       const struct nlattr *attr,
				       struct netlink_ext_ack *extack)
{
	struct mlxdevm_port_fn_ext_uc_list uc_list;

	uc_list.max_uc_list = nla_get_u32(attr);
	uc_list.uc_list_cap_valid = true;
	return port->ops->port_fn_ext_uc_list_set(port, &uc_list, extack);
}

static int mlxdevm_port_function_validate(struct mlxdevm_port *mlxdevm_port,
					  struct nlattr **tb,
					  struct netlink_ext_ack *extack)
{
	const struct mlxdevm_port_ops *ops = mlxdevm_port->ops;
	struct nlattr *attr;

	if (tb[MLXDEVM_PORT_FUNCTION_ATTR_HW_ADDR] &&
	    !ops->port_fn_hw_addr_set) {
		NL_SET_ERR_MSG_ATTR(extack, tb[MLXDEVM_PORT_FUNCTION_ATTR_HW_ADDR],
				    "Port doesn't support function attributes");
		return -EOPNOTSUPP;
	}
	if (tb[MLXDEVM_PORT_FN_ATTR_STATE] && !ops->port_fn_state_set) {
		NL_SET_ERR_MSG_ATTR(extack, tb[MLXDEVM_PORT_FN_ATTR_STATE],
				    "Function does not support state setting");
		return -EOPNOTSUPP;
	}
	attr = tb[MLXDEVM_PORT_FN_ATTR_CAPS];
	if (attr) {
		struct nla_bitfield32 caps;

		caps = nla_get_bitfield32(attr);
		if (caps.selector & MLXDEVM_PORT_FN_CAP_ROCE &&
		    !ops->port_fn_roce_set) {
			NL_SET_ERR_MSG_ATTR(extack, attr,
					    "Port doesn't support RoCE function attribute");
			return -EOPNOTSUPP;
		}
		if (caps.selector & MLXDEVM_PORT_FN_CAP_MIGRATABLE) {
			if (!ops->port_fn_migratable_set) {
				NL_SET_ERR_MSG_ATTR(extack, attr,
						    "Port doesn't support migratable function attribute");
				return -EOPNOTSUPP;
			}
			if (mlxdevm_port->attrs.flavour != MLXDEVM_PORT_FLAVOUR_PCI_VF) {
				NL_SET_ERR_MSG_ATTR(extack, attr,
						    "migratable function attribute supported for VFs only");
				return -EOPNOTSUPP;
			}
		}
		if (caps.selector & MLXDEVM_PORT_FN_CAP_IPSEC_CRYPTO) {
			if (!ops->port_fn_ipsec_crypto_set) {
				NL_SET_ERR_MSG_ATTR(extack, attr,
						    "Port doesn't support ipsec_crypto function attribute");
				return -EOPNOTSUPP;
			}
			if (mlxdevm_port->attrs.flavour != MLXDEVM_PORT_FLAVOUR_PCI_VF) {
				NL_SET_ERR_MSG_ATTR(extack, attr,
						    "ipsec_crypto function attribute supported for VFs only");
				return -EOPNOTSUPP;
			}
		}
		if (caps.selector & MLXDEVM_PORT_FN_CAP_IPSEC_PACKET) {
			if (!ops->port_fn_ipsec_packet_set) {
				NL_SET_ERR_MSG_ATTR(extack, attr,
						    "Port doesn't support ipsec_packet function attribute");
				return -EOPNOTSUPP;
			}
			if (mlxdevm_port->attrs.flavour != MLXDEVM_PORT_FLAVOUR_PCI_VF) {
				NL_SET_ERR_MSG_ATTR(extack, attr,
						    "ipsec_packet function attribute supported for VFs only");
				return -EOPNOTSUPP;
			}
		}
	}
	if (tb[MLXDEVM_PORT_FN_ATTR_MAX_IO_EQS] &&
	    !ops->port_fn_max_io_eqs_set) {
		NL_SET_ERR_MSG_ATTR(extack, tb[MLXDEVM_PORT_FN_ATTR_MAX_IO_EQS],
				    "Function does not support max_io_eqs setting");
		return -EOPNOTSUPP;
	}
	if (tb[MLXDEVM_PORT_FN_ATTR_EXT_UC_LIST] &&
	    !ops->port_fn_ext_uc_list_set) {
		NL_SET_ERR_MSG_ATTR(extack, tb[MLXDEVM_PORT_FN_ATTR_EXT_UC_LIST],
				    "Function does not support uc_list setting");
		return -EOPNOTSUPP;
	}
	return 0;
}

static int mlxdevm_port_function_set(struct mlxdevm_port *port,
				     const struct nlattr *attr,
				     struct netlink_ext_ack *extack)
{
	struct nlattr *tb[MLXDEVM_PORT_FUNCTION_ATTR_MAX + 1];
	int err;

	err = nla_parse_nested(tb, MLXDEVM_PORT_FUNCTION_ATTR_MAX, attr,
			       mlxdevm_function_nl_policy, extack);
	if (err < 0) {
		NL_SET_ERR_MSG(extack, "Fail to parse port function attributes");
		return err;
	}

	err = mlxdevm_port_function_validate(port, tb, extack);
	if (err)
		return err;

	attr = tb[MLXDEVM_PORT_FUNCTION_ATTR_HW_ADDR];
	if (attr) {
		err = mlxdevm_port_function_hw_addr_set(port, attr, extack);
		if (err)
			return err;
	}

	attr = tb[MLXDEVM_PORT_FN_ATTR_CAPS];
	if (attr) {
		err = mlxdevm_port_fn_caps_set(port, attr, extack);
		if (err)
			return err;
	}

	attr = tb[MLXDEVM_PORT_FN_ATTR_MAX_IO_EQS];
	if (attr) {
		err = mlxdevm_port_fn_max_io_eqs_set(port, attr, extack);
		if (err)
			return err;
	}

	attr = tb[MLXDEVM_PORT_FN_ATTR_EXT_TRUST_STATE];
	if (attr) {
		err = mlxdevm_port_fn_trust_set(port, attr, extack);
		if (err)
			return err;
	}

	attr = tb[MLXDEVM_PORT_FN_ATTR_EXT_UC_LIST];
	if (attr) {
		err = mlxdevm_port_fn_ext_uc_list_set(port, attr, extack);
		if (err)
			return err;
	}
	/* Keep this as the last function attribute set, so that when
	 * multiple port function attributes are set along with state,
	 * Those can be applied first before activating the state.
	 */
	attr = tb[MLXDEVM_PORT_FN_ATTR_STATE];
	if (attr)
		err = mlxdevm_port_fn_state_set(port, attr, extack);

	if (!err)
		mlxdevm_port_notify(port, MLXDEVM_CMD_PORT_NEW);
	return err;
}

int mlxdevm_nl_port_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm_port *mlxdevm_port = info->user_ptr[1];
	int err;

	if (info->attrs[MLXDEVM_ATTR_PORT_TYPE]) {
		enum mlxdevm_port_type port_type;

		port_type = nla_get_u16(info->attrs[MLXDEVM_ATTR_PORT_TYPE]);
		err = mlxdevm_port_type_set(mlxdevm_port, port_type);
		if (err)
			return err;
	}

	if (info->attrs[MLXDEVM_ATTR_PORT_FUNCTION]) {
		struct nlattr *attr = info->attrs[MLXDEVM_ATTR_PORT_FUNCTION];
		struct netlink_ext_ack *extack = info->extack;

		err = mlxdevm_port_function_set(mlxdevm_port, attr, extack);
		if (err)
			return err;
	}

	return 0;
}
#if 0

int devlink_nl_port_split_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct devlink_port *devlink_port = info->user_ptr[1];
	struct devlink *devlink = info->user_ptr[0];
	u32 count;

	if (GENL_REQ_ATTR_CHECK(info, DEVLINK_ATTR_PORT_SPLIT_COUNT))
		return -EINVAL;
	if (!devlink_port->ops->port_split)
		return -EOPNOTSUPP;

	count = nla_get_u32(info->attrs[DEVLINK_ATTR_PORT_SPLIT_COUNT]);

	if (!devlink_port->attrs.splittable) {
		/* Split ports cannot be split. */
		if (devlink_port->attrs.split)
			NL_SET_ERR_MSG(info->extack, "Port cannot be split further");
		else
			NL_SET_ERR_MSG(info->extack, "Port cannot be split");
		return -EINVAL;
	}

	if (count < 2 || !is_power_of_2(count) || count > devlink_port->attrs.lanes) {
		NL_SET_ERR_MSG(info->extack, "Invalid split count");
		return -EINVAL;
	}

	return devlink_port->ops->port_split(devlink, devlink_port, count,
					     info->extack);
}

int devlink_nl_port_unsplit_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct devlink_port *devlink_port = info->user_ptr[1];
	struct devlink *devlink = info->user_ptr[0];

	if (!devlink_port->ops->port_unsplit)
		return -EOPNOTSUPP;
	return devlink_port->ops->port_unsplit(devlink, devlink_port, info->extack);
}
#endif

int mlxdevm_nl_port_new_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct netlink_ext_ack *extack = info->extack;
	struct mlxdevm_port_new_attrs new_attrs = {};
	struct mlxdevm *mlxdevm = info->user_ptr[0];
	struct mlxdevm_port *mlxdevm_port;
	unsigned int new_index;
	struct sk_buff *msg;
	int err;

	if (!mlxdevm->ops->port_new)
		return -EOPNOTSUPP;

	if (!info->attrs[MLXDEVM_ATTR_PORT_FLAVOUR] ||
	    !info->attrs[MLXDEVM_ATTR_PORT_PCI_PF_NUMBER]) {
		NL_SET_ERR_MSG(extack, "Port flavour or PCI PF are not specified");
		return -EINVAL;
	}
	new_attrs.flavour = nla_get_u16(info->attrs[MLXDEVM_ATTR_PORT_FLAVOUR]);
	new_attrs.pfnum =
		nla_get_u16(info->attrs[MLXDEVM_ATTR_PORT_PCI_PF_NUMBER]);

	if (info->attrs[MLXDEVM_ATTR_PORT_INDEX]) {
		/* Port index of the new port being created by driver. */
		new_attrs.port_index =
			nla_get_u32(info->attrs[MLXDEVM_ATTR_PORT_INDEX]);
		new_attrs.port_index_valid = true;
	}
	if (info->attrs[MLXDEVM_ATTR_PORT_CONTROLLER_NUMBER]) {
		new_attrs.controller =
			nla_get_u16(info->attrs[MLXDEVM_ATTR_PORT_CONTROLLER_NUMBER]);
		new_attrs.controller_valid = true;
	}
	if (new_attrs.flavour == MLXDEVM_PORT_FLAVOUR_PCI_SF &&
	    info->attrs[MLXDEVM_ATTR_PORT_PCI_SF_NUMBER]) {
		new_attrs.sfnum = nla_get_u32(info->attrs[MLXDEVM_ATTR_PORT_PCI_SF_NUMBER]);
		new_attrs.sfnum_valid = true;
	}

	err = mlxdevm->ops->port_new(mlxdevm, &new_attrs,
				     extack, &new_index);
	if (err)
		return err;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg) {
		err = -ENOMEM;
		goto err_out_port_del;
	}

	mlxdevm_port = mlxdevm_port_get_by_index(mlxdevm, new_index);

	err = mlxdevm_nl_port_fill(msg, mlxdevm_port, MLXDEVM_CMD_PORT_NEW,
				   info->snd_portid, info->snd_seq, 0, NULL);
	if (WARN_ON_ONCE(err))
		goto err_out_msg_free;
	err = genlmsg_reply(msg, info);
	if (err)
		goto err_out_port_del;
	return 0;

err_out_msg_free:
	nlmsg_free(msg);
err_out_port_del:
	mlxdevm_port->ops->port_del(mlxdevm, mlxdevm_port->index, NULL);
	return err;
}

int mlxdevm_nl_port_del_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm_port *mlxdevm_port = info->user_ptr[1];
	struct netlink_ext_ack *extack = info->extack;
	struct mlxdevm *mlxdevm = info->user_ptr[0];

	if (!mlxdevm_port->ops->port_del)
		return -EOPNOTSUPP;

	return mlxdevm_port->ops->port_del(mlxdevm, mlxdevm_port->index, extack);
}

static void mlxdevm_port_type_warn(struct work_struct *work)
{
	struct mlxdevm_port *port = container_of(to_delayed_work(work),
						 struct mlxdevm_port,
						 type_warn_dw);
	dev_warn(port->mlxdevm->dev, "Type was not set for mlxdevm port.");
}

static bool mlxdevm_port_type_should_warn(struct mlxdevm_port *mlxdevm_port)
{
	/* Ignore CPU and DSA flavours. */
	return mlxdevm_port->attrs.flavour != MLXDEVM_PORT_FLAVOUR_CPU &&
	       mlxdevm_port->attrs.flavour != MLXDEVM_PORT_FLAVOUR_DSA &&
	       mlxdevm_port->attrs.flavour != MLXDEVM_PORT_FLAVOUR_UNUSED;
}

#define MLXDEVM_PORT_TYPE_WARN_TIMEOUT (HZ * 3600)

static void mlxdevm_port_type_warn_schedule(struct mlxdevm_port *mlxdevm_port)
{
	if (!mlxdevm_port_type_should_warn(mlxdevm_port))
		return;
	/* Schedule a work to WARN in case driver does not set port
	 * type within timeout.
	 */
	schedule_delayed_work(&mlxdevm_port->type_warn_dw,
			      MLXDEVM_PORT_TYPE_WARN_TIMEOUT);
}

static void mlxdevm_port_type_warn_cancel(struct mlxdevm_port *mlxdevm_port)
{
	if (!mlxdevm_port_type_should_warn(mlxdevm_port))
		return;
	cancel_delayed_work_sync(&mlxdevm_port->type_warn_dw);
}

/**
 * mlxdevm_port_init() - Init mlxdevm port
 *
 * @mlxdevm: mlxdevm
 * @mlxdevm_port: mlxdevm port
 *
 * Initialize essential stuff that is needed for functions
 * that may be called before mlxdevm port registration.
 * Call to this function is optional and not needed
 * in case the driver does not use such functions.
 */
void mlxdevm_port_init(struct mlxdevm *mlxdevm,
		       struct mlxdevm_port *mlxdevm_port)
{
	if (mlxdevm_port->initialized)
		return;
	mlxdevm_port->mlxdevm = mlxdevm;
	INIT_LIST_HEAD(&mlxdevm_port->region_list);
	mlxdevm_port->initialized = true;
}
EXPORT_SYMBOL_GPL(mlxdevm_port_init);
#if 0

/**
 * devlink_port_fini() - Deinitialize devlink port
 *
 * @devlink_port: devlink port
 *
 * Deinitialize essential stuff that is in use for functions
 * that may be called after devlink port unregistration.
 * Call to this function is optional and not needed
 * in case the driver does not use such functions.
 */
void devlink_port_fini(struct devlink_port *devlink_port)
{
	WARN_ON(!list_empty(&devlink_port->region_list));
}
EXPORT_SYMBOL_GPL(devlink_port_fini);
#endif

static const struct mlxdevm_port_ops mlxdevm_port_dummy_ops = {};

/**
 * devm_port_register_with_ops() - Register mlxdevm port
 *
 * @mlxdevm: mlxdevm
 * @mlxdevm_port: mlxdevm port
 * @port_index: driver-specific numerical identifier of the port
 * @ops: port ops
 *
 * Register mlxdevm port with provided port index. User can use
 * any indexing, even hw-related one. mlxdevm_port structure
 * is convenient to be embedded inside user driver private structure.
 * Note that the caller should take care of zeroing the mlxdevm_port
 * structure.
 */
int devm_port_register_with_ops(struct mlxdevm *mlxdevm,
				struct mlxdevm_port *mlxdevm_port,
				unsigned int port_index,
				const struct mlxdevm_port_ops *ops)
{
	int err;

	devm_assert_locked(mlxdevm);

	ASSERT_MLXDEVM_PORT_NOT_REGISTERED(mlxdevm_port);

	mlxdevm_port_init(mlxdevm, mlxdevm_port);
	mlxdevm_port->registered = true;
	mlxdevm_port->index = port_index;
	mlxdevm_port->ops = ops ? ops : &mlxdevm_port_dummy_ops;
	spin_lock_init(&mlxdevm_port->type_lock);
	INIT_LIST_HEAD(&mlxdevm_port->reporter_list);
	err = xa_insert(&mlxdevm->ports, port_index, mlxdevm_port, GFP_KERNEL);
	if (err) {
		mlxdevm_port->registered = false;
		return err;
	}

	INIT_DELAYED_WORK(&mlxdevm_port->type_warn_dw, &mlxdevm_port_type_warn);
	mlxdevm_port_type_warn_schedule(mlxdevm_port);
	mlxdevm_port_notify(mlxdevm_port, MLXDEVM_CMD_PORT_NEW);
	return 0;
}
EXPORT_SYMBOL_GPL(devm_port_register_with_ops);

/**
 *	mlxdevm_port_register_with_ops - Register mlxdevm port
 *
 *	@mlxdevm: mlxdevm
 *	@mlxdevm_port: mlxdevm port
 *	@port_index: driver-specific numerical identifier of the port
 *	@ops: port ops
 *
 *	Register mlxdevm port with provided port index. User can use
 *	any indexing, even hw-related one. mlxdevm_port structure
 *	is convenient to be embedded inside user driver private structure.
 *	Note that the caller should take care of zeroing the mlxdevm_port
 *	structure.
 *
 *	Context: Takes and release mlxdevm->lock <mutex>.
 */
int mlxdevm_port_register_with_ops(struct mlxdevm *mlxdevm,
				   struct mlxdevm_port *mlxdevm_port,
				   unsigned int port_index,
				   const struct mlxdevm_port_ops *ops)
{
	int err;

	devm_lock(mlxdevm);
	err = devm_port_register_with_ops(mlxdevm, mlxdevm_port,
					  port_index, ops);
	devm_unlock(mlxdevm);
	return err;
}
EXPORT_SYMBOL_GPL(mlxdevm_port_register_with_ops);

/**
 * devm_port_unregister() - Unregister mlxdevm port
 *
 * @mlxdevm_port: mlxdevm port
 */
void devm_port_unregister(struct mlxdevm_port *mlxdevm_port)
{
	lockdep_assert_held(&mlxdevm_port->mlxdevm->lock);
	WARN_ON(mlxdevm_port->type != MLXDEVM_PORT_TYPE_NOTSET);

	mlxdevm_port_type_warn_cancel(mlxdevm_port);
	mlxdevm_port_notify(mlxdevm_port, MLXDEVM_CMD_PORT_DEL);
	xa_erase(&mlxdevm_port->mlxdevm->ports, mlxdevm_port->index);
	WARN_ON(!list_empty(&mlxdevm_port->reporter_list));
	mlxdevm_port->registered = false;
}
EXPORT_SYMBOL_GPL(devm_port_unregister);

/**
 *	mlxdevm_port_unregister - Unregister mlxdevm port
 *
 *	@mlxdevm_port: mlxdevm port
 *
 *	Context: Takes and release mlxdevm->lock <mutex>.
 */
void mlxdevm_port_unregister(struct mlxdevm_port *mlxdevm_port)
{
	struct mlxdevm *mlxdevm = mlxdevm_port->mlxdevm;

	devm_lock(mlxdevm);
	devm_port_unregister(mlxdevm_port);
	devm_unlock(mlxdevm);
}
EXPORT_SYMBOL_GPL(mlxdevm_port_unregister);

static void mlxdevm_port_type_netdev_checks(struct mlxdevm_port *mlxdevm_port,
					    struct net_device *netdev)
{
	const struct net_device_ops *ops = netdev->netdev_ops;

	return; /* Since the behavior of mlxdevm doesn't depend on the checks output, it is ok to ignore it for now.
		 * The reason for the trace is that driver is modified to support old devlink versions.
		 * Those old versions, compared to new mlxdevm, have differences,
		 * like depricated mechanisms and API's, which cause such bugs.
		 * TODO: invetigate root cause and come up with a fix.
		 */

	/* If driver registers mlxdevm port, it should set mlxdevm port
	 * attributes accordingly so the compat functions are called
	 * and the original ops are not used.
	 */
	if (ops->ndo_get_phys_port_name) {
		/* Some drivers use the same set of ndos for netdevs
		 * that have mlxdevm_port registered and also for
		 * those who don't. Make sure that ndo_get_phys_port_name
		 * returns -EOPNOTSUPP here in case it is defined.
		 * Warn if not.
		 */
		char name[IFNAMSIZ];
		int err;

		err = ops->ndo_get_phys_port_name(netdev, name, sizeof(name));
		WARN_ON(err != -EOPNOTSUPP);
	}
	if (ops->ndo_get_port_parent_id) {
		/* Some drivers use the same set of ndos for netdevs
		 * that have mlxdevm_port registered and also for
		 * those who don't. Make sure that ndo_get_port_parent_id
		 * returns -EOPNOTSUPP here in case it is defined.
		 * Warn if not.
		 */
		struct netdev_phys_item_id ppid;
		int err;

		err = ops->ndo_get_port_parent_id(netdev, &ppid);
		WARN_ON(err != -EOPNOTSUPP);
	}
}

static void __mlxdevm_port_type_set(struct mlxdevm_port *mlxdevm_port,
				    enum mlxdevm_port_type type,
				    void *type_dev)
{
	struct net_device *netdev = type_dev;

	ASSERT_MLXDEVM_PORT_REGISTERED(mlxdevm_port);

	if (type == MLXDEVM_PORT_TYPE_NOTSET) {
		mlxdevm_port_type_warn_schedule(mlxdevm_port);
	} else {
		mlxdevm_port_type_warn_cancel(mlxdevm_port);
		if (type == MLXDEVM_PORT_TYPE_ETH && netdev)
			mlxdevm_port_type_netdev_checks(mlxdevm_port, netdev);
	}

	spin_lock_bh(&mlxdevm_port->type_lock);
	mlxdevm_port->type = type;
	switch (type) {
	case MLXDEVM_PORT_TYPE_ETH:
		mlxdevm_port->type_eth.netdev = netdev;
		if (netdev) {
			ASSERT_RTNL();
			mlxdevm_port->type_eth.netdev = netdev;
		}
		break;
	case MLXDEVM_PORT_TYPE_IB:
		mlxdevm_port->type_ib.ibdev = type_dev;
		break;
	default:
		break;
	}
	spin_unlock_bh(&mlxdevm_port->type_lock);
	mlxdevm_port_notify(mlxdevm_port, MLXDEVM_CMD_PORT_NEW);
}

/**
 *	mlxdevm_port_type_eth_set - Set port type to Ethernet
 *
 *	@mlxdevm_port: mlxdevm port
 *
 *	If driver is calling this, most likely it is doing something wrong.
 */
void mlxdevm_port_type_eth_set(struct mlxdevm_port *mlxdevm_port, struct net_device *netdev)
{
	__mlxdevm_port_type_set(mlxdevm_port, MLXDEVM_PORT_TYPE_ETH, netdev);
}
EXPORT_SYMBOL_GPL(mlxdevm_port_type_eth_set);
#if 0

/**
 *	devlink_port_type_ib_set - Set port type to InfiniBand
 *
 *	@devlink_port: devlink port
 *	@ibdev: related IB device
 */
void devlink_port_type_ib_set(struct devlink_port *devlink_port,
			      struct ib_device *ibdev)
{
	__devlink_port_type_set(devlink_port, DEVLINK_PORT_TYPE_IB, ibdev);
}
EXPORT_SYMBOL_GPL(devlink_port_type_ib_set);
#endif

/**
 *	mlxdevm_port_type_clear - Clear port type
 *
 *	@mlxdevm_port: mlxdevm port
 *
 *	If driver is calling this for clearing Ethernet type, most likely
 *	it is doing something wrong.
 */
void mlxdevm_port_type_clear(struct mlxdevm_port *mlxdevm_port)
{
	if (mlxdevm_port->type == MLXDEVM_PORT_TYPE_ETH)
		dev_warn(mlxdevm_port->mlxdevm->dev,
			 "mlxdevm port type for port %d cleared without a software interface reference, device type not supported by the kernel?\n",
			 mlxdevm_port->index);
	__mlxdevm_port_type_set(mlxdevm_port, MLXDEVM_PORT_TYPE_NOTSET, NULL);
}
EXPORT_SYMBOL_GPL(mlxdevm_port_type_clear);
#if 0

int devlink_port_netdevice_event(struct notifier_block *nb,
				 unsigned long event, void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct devlink_port *devlink_port = netdev->devlink_port;
	struct devlink *devlink;

	if (!devlink_port)
		return NOTIFY_OK;
	devlink = devlink_port->devlink;

	switch (event) {
	case NETDEV_POST_INIT:
		/* Set the type but not netdev pointer. It is going to be set
		 * later on by NETDEV_REGISTER event. Happens once during
		 * netdevice register
		 */
		__devlink_port_type_set(devlink_port, DEVLINK_PORT_TYPE_ETH,
					NULL);
		break;
	case NETDEV_REGISTER:
	case NETDEV_CHANGENAME:
		if (devlink_net(devlink) != dev_net(netdev))
			return NOTIFY_OK;
		/* Set the netdev on top of previously set type. Note this
		 * event happens also during net namespace change so here
		 * we take into account netdev pointer appearing in this
		 * namespace.
		 */
		__devlink_port_type_set(devlink_port, devlink_port->type,
					netdev);
		break;
	case NETDEV_UNREGISTER:
		if (devlink_net(devlink) != dev_net(netdev))
			return NOTIFY_OK;
		/* Clear netdev pointer, but not the type. This event happens
		 * also during net namespace change so we need to clear
		 * pointer to netdev that is going to another net namespace.
		 */
		__devlink_port_type_set(devlink_port, devlink_port->type,
					NULL);
		break;
	case NETDEV_PRE_UNINIT:
		/* Clear the type and the netdev pointer. Happens one during
		 * netdevice unregister.
		 */
		__devlink_port_type_set(devlink_port, DEVLINK_PORT_TYPE_NOTSET,
					NULL);
		break;
	}

	return NOTIFY_OK;
}
#endif

static int __mlxdevm_port_attrs_set(struct mlxdevm_port *mlxdevm_port,
				    enum mlxdevm_port_flavour flavour)
{
	struct mlxdevm_port_attrs *attrs = &mlxdevm_port->attrs;

	mlxdevm_port->attrs_set = true;
	attrs->flavour = flavour;
	if (attrs->switch_id.id_len) {
		mlxdevm_port->switch_port = true;
		if (WARN_ON(attrs->switch_id.id_len > MAX_PHYS_ITEM_ID_LEN))
			attrs->switch_id.id_len = MAX_PHYS_ITEM_ID_LEN;
	} else {
		mlxdevm_port->switch_port = false;
	}
	return 0;
}

/**
 *	mlxdevm_port_attrs_set - Set port attributes
 *
 *	@mlxdevm_port: mlxdevm port
 *	@attrs: mlxdevm port attrs
 */
void mlxdevm_port_attrs_set(struct mlxdevm_port *mlxdevm_port,
			    struct mlxdevm_port_attrs *attrs)
{
	int ret;

	ASSERT_MLXDEVM_PORT_NOT_REGISTERED(mlxdevm_port);

	mlxdevm_port->attrs = *attrs;
	ret = __mlxdevm_port_attrs_set(mlxdevm_port, attrs->flavour);
	if (ret)
		return;
	WARN_ON(attrs->splittable && attrs->split);
}
EXPORT_SYMBOL_GPL(mlxdevm_port_attrs_set);
#if 0

/**
 *	devlink_port_attrs_pci_pf_set - Set PCI PF port attributes
 *
 *	@devlink_port: devlink port
 *	@controller: associated controller number for the devlink port instance
 *	@pf: associated PF for the devlink port instance
 *	@external: indicates if the port is for an external controller
 */
void devlink_port_attrs_pci_pf_set(struct devlink_port *devlink_port, u32 controller,
				   u16 pf, bool external)
{
	struct devlink_port_attrs *attrs = &devlink_port->attrs;
	int ret;

	ASSERT_DEVLINK_PORT_NOT_REGISTERED(devlink_port);

	ret = __devlink_port_attrs_set(devlink_port,
				       DEVLINK_PORT_FLAVOUR_PCI_PF);
	if (ret)
		return;
	attrs->pci_pf.controller = controller;
	attrs->pci_pf.pf = pf;
	attrs->pci_pf.external = external;
}
EXPORT_SYMBOL_GPL(devlink_port_attrs_pci_pf_set);

/**
 *	devlink_port_attrs_pci_vf_set - Set PCI VF port attributes
 *
 *	@devlink_port: devlink port
 *	@controller: associated controller number for the devlink port instance
 *	@pf: associated PF for the devlink port instance
 *	@vf: associated VF of a PF for the devlink port instance
 *	@external: indicates if the port is for an external controller
 */
void devlink_port_attrs_pci_vf_set(struct devlink_port *devlink_port, u32 controller,
				   u16 pf, u16 vf, bool external)
{
	struct devlink_port_attrs *attrs = &devlink_port->attrs;
	int ret;

	ASSERT_DEVLINK_PORT_NOT_REGISTERED(devlink_port);

	ret = __devlink_port_attrs_set(devlink_port,
				       DEVLINK_PORT_FLAVOUR_PCI_VF);
	if (ret)
		return;
	attrs->pci_vf.controller = controller;
	attrs->pci_vf.pf = pf;
	attrs->pci_vf.vf = vf;
	attrs->pci_vf.external = external;
}
EXPORT_SYMBOL_GPL(devlink_port_attrs_pci_vf_set);

/**
 *	devlink_port_attrs_pci_sf_set - Set PCI SF port attributes
 *
 *	@devlink_port: devlink port
 *	@controller: associated controller number for the devlink port instance
 *	@pf: associated PF for the devlink port instance
 *	@sf: associated SF of a PF for the devlink port instance
 *	@external: indicates if the port is for an external controller
 */
void devlink_port_attrs_pci_sf_set(struct devlink_port *devlink_port, u32 controller,
				   u16 pf, u32 sf, bool external)
{
	struct devlink_port_attrs *attrs = &devlink_port->attrs;
	int ret;

	ASSERT_DEVLINK_PORT_NOT_REGISTERED(devlink_port);

	ret = __devlink_port_attrs_set(devlink_port,
				       DEVLINK_PORT_FLAVOUR_PCI_SF);
	if (ret)
		return;
	attrs->pci_sf.controller = controller;
	attrs->pci_sf.pf = pf;
	attrs->pci_sf.sf = sf;
	attrs->pci_sf.external = external;
}
EXPORT_SYMBOL_GPL(devlink_port_attrs_pci_sf_set);

static void devlink_port_rel_notify_cb(struct devlink *devlink, u32 port_index)
{
	struct devlink_port *devlink_port;

	devlink_port = devlink_port_get_by_index(devlink, port_index);
	if (!devlink_port)
		return;
	devlink_port_notify(devlink_port, DEVLINK_CMD_PORT_NEW);
}

static void devlink_port_rel_cleanup_cb(struct devlink *devlink, u32 port_index,
					u32 rel_index)
{
	struct devlink_port *devlink_port;

	devlink_port = devlink_port_get_by_index(devlink, port_index);
	if (devlink_port && devlink_port->rel_index == rel_index)
		devlink_port->rel_index = 0;
}

/**
 * devl_port_fn_devlink_set - Attach peer devlink
 *			      instance to port function.
 * @devlink_port: devlink port
 * @fn_devlink: devlink instance to attach
 */
int devl_port_fn_devlink_set(struct devlink_port *devlink_port,
			     struct devlink *fn_devlink)
{
	ASSERT_DEVLINK_PORT_REGISTERED(devlink_port);

	if (WARN_ON(devlink_port->attrs.flavour != DEVLINK_PORT_FLAVOUR_PCI_SF ||
		    devlink_port->attrs.pci_sf.external))
		return -EINVAL;

	return devlink_rel_nested_in_add(&devlink_port->rel_index,
					 devlink_port->devlink->index,
					 devlink_port->index,
					 devlink_port_rel_notify_cb,
					 devlink_port_rel_cleanup_cb,
					 fn_devlink);
}
EXPORT_SYMBOL_GPL(devl_port_fn_devlink_set);

/**
 *	devlink_port_linecard_set - Link port with a linecard
 *
 *	@devlink_port: devlink port
 *	@linecard: devlink linecard
 */
void devlink_port_linecard_set(struct devlink_port *devlink_port,
			       struct devlink_linecard *linecard)
{
	ASSERT_DEVLINK_PORT_NOT_REGISTERED(devlink_port);

	devlink_port->linecard = linecard;
}
EXPORT_SYMBOL_GPL(devlink_port_linecard_set);

static int __devlink_port_phys_port_name_get(struct devlink_port *devlink_port,
					     char *name, size_t len)
{
	struct devlink_port_attrs *attrs = &devlink_port->attrs;
	int n = 0;

	if (!devlink_port->attrs_set)
		return -EOPNOTSUPP;

	switch (attrs->flavour) {
	case DEVLINK_PORT_FLAVOUR_PHYSICAL:
		if (devlink_port->linecard)
			n = snprintf(name, len, "l%u",
				     devlink_linecard_index(devlink_port->linecard));
		if (n < len)
			n += snprintf(name + n, len - n, "p%u",
				      attrs->phys.port_number);
		if (n < len && attrs->split)
			n += snprintf(name + n, len - n, "s%u",
				      attrs->phys.split_subport_number);
		break;
	case DEVLINK_PORT_FLAVOUR_CPU:
	case DEVLINK_PORT_FLAVOUR_DSA:
	case DEVLINK_PORT_FLAVOUR_UNUSED:
		/* As CPU and DSA ports do not have a netdevice associated
		 * case should not ever happen.
		 */
		WARN_ON(1);
		return -EINVAL;
	case DEVLINK_PORT_FLAVOUR_PCI_PF:
		if (attrs->pci_pf.external) {
			n = snprintf(name, len, "c%u", attrs->pci_pf.controller);
			if (n >= len)
				return -EINVAL;
			len -= n;
			name += n;
		}
		n = snprintf(name, len, "pf%u", attrs->pci_pf.pf);
		break;
	case DEVLINK_PORT_FLAVOUR_PCI_VF:
		if (attrs->pci_vf.external) {
			n = snprintf(name, len, "c%u", attrs->pci_vf.controller);
			if (n >= len)
				return -EINVAL;
			len -= n;
			name += n;
		}
		n = snprintf(name, len, "pf%uvf%u",
			     attrs->pci_vf.pf, attrs->pci_vf.vf);
		break;
	case DEVLINK_PORT_FLAVOUR_PCI_SF:
		if (attrs->pci_sf.external) {
			n = snprintf(name, len, "c%u", attrs->pci_sf.controller);
			if (n >= len)
				return -EINVAL;
			len -= n;
			name += n;
		}
		n = snprintf(name, len, "pf%usf%u", attrs->pci_sf.pf,
			     attrs->pci_sf.sf);
		break;
	case DEVLINK_PORT_FLAVOUR_VIRTUAL:
		return -EOPNOTSUPP;
	}

	if (n >= len)
		return -EINVAL;

	return 0;
}

int devlink_compat_phys_port_name_get(struct net_device *dev,
				      char *name, size_t len)
{
	struct devlink_port *devlink_port;

	/* RTNL mutex is held here which ensures that devlink_port
	 * instance cannot disappear in the middle. No need to take
	 * any devlink lock as only permanent values are accessed.
	 */
	ASSERT_RTNL();

	devlink_port = dev->devlink_port;
	if (!devlink_port)
		return -EOPNOTSUPP;

	return __devlink_port_phys_port_name_get(devlink_port, name, len);
}

int devlink_compat_switch_id_get(struct net_device *dev,
				 struct netdev_phys_item_id *ppid)
{
	struct devlink_port *devlink_port;

	/* Caller must hold RTNL mutex or reference to dev, which ensures that
	 * devlink_port instance cannot disappear in the middle. No need to take
	 * any devlink lock as only permanent values are accessed.
	 */
	devlink_port = dev->devlink_port;
	if (!devlink_port || !devlink_port->switch_port)
		return -EOPNOTSUPP;

	memcpy(ppid, &devlink_port->attrs.switch_id, sizeof(*ppid));

	return 0;
}
#endif
