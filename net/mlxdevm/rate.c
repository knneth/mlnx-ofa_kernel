// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2016 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2016 Jiri Pirko <jiri@mellanox.com>
 */

#include "devl_internal.h"

static inline bool
mlxdevm_rate_is_leaf(struct mlxdevm_rate *mlxdevm_rate)
{
	return mlxdevm_rate->type == MLXDEVM_RATE_TYPE_LEAF;
}

static inline bool
mlxdevm_rate_is_node(struct mlxdevm_rate *mlxdevm_rate)
{
	return mlxdevm_rate->type == MLXDEVM_RATE_TYPE_NODE;
}

static struct mlxdevm_rate *
mlxdevm_rate_leaf_get_from_info(struct mlxdevm *mlxdevm, struct genl_info *info)
{
	struct mlxdevm_rate *mlxdevm_rate;
	struct mlxdevm_port *mlxdevm_port;

	mlxdevm_port = mlxdevm_port_get_from_attrs(mlxdevm, info->attrs);
	if (IS_ERR(mlxdevm_port))
		return ERR_CAST(mlxdevm_port);
	mlxdevm_rate = mlxdevm_port->mlxdevm_rate;
	return mlxdevm_rate ?: ERR_PTR(-ENODEV);
}

static struct mlxdevm_rate *
mlxdevm_rate_node_get_by_name(struct mlxdevm *mlxdevm, const char *node_name)
{
	static struct mlxdevm_rate *mlxdevm_rate;

	list_for_each_entry(mlxdevm_rate, &mlxdevm->rate_list, list) {
		if (mlxdevm_rate_is_node(mlxdevm_rate) &&
		    !strcmp(node_name, mlxdevm_rate->name))
			return mlxdevm_rate;
	}
	return ERR_PTR(-ENODEV);
}

static struct mlxdevm_rate *
mlxdevm_rate_node_get_from_attrs(struct mlxdevm *mlxdevm, struct nlattr **attrs)
{
	const char *rate_node_name;
	size_t len;

	if (!attrs[MLXDEVM_ATTR_RATE_NODE_NAME])
		return ERR_PTR(-EINVAL);
	rate_node_name = nla_data(attrs[MLXDEVM_ATTR_RATE_NODE_NAME]);
	len = strlen(rate_node_name);
	/* Name cannot be empty or decimal number */
	if (!len || strspn(rate_node_name, "0123456789") == len)
		return ERR_PTR(-EINVAL);

	return mlxdevm_rate_node_get_by_name(mlxdevm, rate_node_name);
}

static struct mlxdevm_rate *
mlxdevm_rate_node_get_from_info(struct mlxdevm *mlxdevm, struct genl_info *info)
{
	return mlxdevm_rate_node_get_from_attrs(mlxdevm, info->attrs);
}

static struct mlxdevm_rate *
mlxdevm_rate_get_from_info(struct mlxdevm *mlxdevm, struct genl_info *info)
{
	struct nlattr **attrs = info->attrs;

	if (attrs[MLXDEVM_ATTR_PORT_INDEX])
		return mlxdevm_rate_leaf_get_from_info(mlxdevm, info);
	else if (attrs[MLXDEVM_ATTR_RATE_NODE_NAME])
		return mlxdevm_rate_node_get_from_info(mlxdevm, info);
	else
		return ERR_PTR(-EINVAL);
}

static int mlxdevm_nl_rate_fill(struct sk_buff *msg,
				struct mlxdevm_rate *mlxdevm_rate,
				enum mlxdevm_command cmd, u32 portid, u32 seq,
				int flags, struct netlink_ext_ack *extack)
{
	struct mlxdevm *mlxdevm = mlxdevm_rate->mlxdevm;
	void *hdr;

	hdr = genlmsg_put(msg, portid, seq, &mlxdevm_nl_family, flags, cmd);
	if (!hdr)
		return -EMSGSIZE;

	if (mlxdevm_nl_put_handle(msg, mlxdevm))
		goto nla_put_failure;

	if (nla_put_u16(msg, MLXDEVM_ATTR_RATE_TYPE, mlxdevm_rate->type))
		goto nla_put_failure;

	if (mlxdevm_rate_is_leaf(mlxdevm_rate)) {
		if (nla_put_u32(msg, MLXDEVM_ATTR_PORT_INDEX,
				mlxdevm_rate->mlxdevm_port->index))
			goto nla_put_failure;
	} else if (mlxdevm_rate_is_node(mlxdevm_rate)) {
		if (nla_put_string(msg, MLXDEVM_ATTR_RATE_NODE_NAME,
				   mlxdevm_rate->name))
			goto nla_put_failure;
	}

	if (nla_put_u64_64bit(msg, MLXDEVM_ATTR_RATE_TX_SHARE,
			      mlxdevm_rate->tx_share, MLXDEVM_ATTR_PAD))
		goto nla_put_failure;

	if (nla_put_u64_64bit(msg, MLXDEVM_ATTR_RATE_TX_MAX,
			      mlxdevm_rate->tx_max, MLXDEVM_ATTR_PAD))
		goto nla_put_failure;

	if (nla_put_u32(msg, MLXDEVM_ATTR_RATE_TX_PRIORITY,
			mlxdevm_rate->tx_priority))
		goto nla_put_failure;

	if (nla_put_u32(msg, MLXDEVM_ATTR_RATE_TX_WEIGHT,
			mlxdevm_rate->tx_weight))
		goto nla_put_failure;

	if (mlxdevm_rate->parent)
		if (nla_put_string(msg, MLXDEVM_ATTR_RATE_PARENT_NODE_NAME,
				   mlxdevm_rate->parent->name))
			goto nla_put_failure;

	genlmsg_end(msg, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

static void mlxdevm_rate_notify(struct mlxdevm_rate *mlxdevm_rate,
				enum mlxdevm_command cmd)
{
	struct mlxdevm *mlxdevm = mlxdevm_rate->mlxdevm;
	struct sk_buff *msg;
	int err;

	WARN_ON(cmd != MLXDEVM_CMD_RATE_NEW && cmd != MLXDEVM_CMD_RATE_DEL);

	if (!devm_is_registered(mlxdevm) || !mlxdevm_nl_notify_need(mlxdevm))
		return;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	err = mlxdevm_nl_rate_fill(msg, mlxdevm_rate, cmd, 0, 0, 0, NULL);
	if (err) {
		nlmsg_free(msg);
		return;
	}

	mlxdevm_nl_notify_send(mlxdevm, msg);
}
#if 0

void devlink_rates_notify_register(struct devlink *devlink)
{
	struct devlink_rate *rate_node;

	list_for_each_entry(rate_node, &devlink->rate_list, list)
		devlink_rate_notify(rate_node, DEVLINK_CMD_RATE_NEW);
}

void devlink_rates_notify_unregister(struct devlink *devlink)
{
	struct devlink_rate *rate_node;

	list_for_each_entry_reverse(rate_node, &devlink->rate_list, list)
		devlink_rate_notify(rate_node, DEVLINK_CMD_RATE_DEL);
}
#endif

static int
mlxdevm_nl_rate_get_dump_one(struct sk_buff *msg, struct mlxdevm *mlxdevm,
			     struct netlink_callback *cb, int flags)
{
	struct mlxdevm_nl_dump_state *state = mlxdevm_dump_state(cb);
	struct mlxdevm_rate *mlxdevm_rate;
	int idx = 0;
	int err = 0;

	list_for_each_entry(mlxdevm_rate, &mlxdevm->rate_list, list) {
		enum mlxdevm_command cmd = MLXDEVM_CMD_RATE_NEW;
		u32 id = NETLINK_CB(cb->skb).portid;

		if (idx < state->idx) {
			idx++;
			continue;
		}
		err = mlxdevm_nl_rate_fill(msg, mlxdevm_rate, cmd, id,
					   cb->nlh->nlmsg_seq, flags, NULL);
		if (err) {
			state->idx = idx;
			break;
		}
		idx++;
	}

	return err;
}

int mlxdevm_nl_rate_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	return mlxdevm_nl_dumpit(skb, cb, mlxdevm_nl_rate_get_dump_one);
}

int mlxdevm_nl_rate_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm *mlxdevm = info->user_ptr[0];
	struct mlxdevm_rate *mlxdevm_rate;
	struct sk_buff *msg;
	int err;

	mlxdevm_rate = mlxdevm_rate_get_from_info(mlxdevm, info);
	if (IS_ERR(mlxdevm_rate))
		return PTR_ERR(mlxdevm_rate);

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	err = mlxdevm_nl_rate_fill(msg, mlxdevm_rate, MLXDEVM_CMD_RATE_NEW,
				   info->snd_portid, info->snd_seq, 0,
				   info->extack);
	if (err) {
		nlmsg_free(msg);
		return err;
	}

	return genlmsg_reply(msg, info);
}

static bool
mlxdevm_rate_is_parent_node(struct mlxdevm_rate *mlxdevm_rate,
			    struct mlxdevm_rate *parent)
{
	while (parent) {
		if (parent == mlxdevm_rate)
			return true;
		parent = parent->parent;
	}
	return false;
}

static int
mlxdevm_nl_rate_parent_node_set(struct mlxdevm_rate *mlxdevm_rate,
				struct genl_info *info,
				struct nlattr *nla_parent)
{
	struct mlxdevm *mlxdevm = mlxdevm_rate->mlxdevm;
	const char *parent_name = nla_data(nla_parent);
	const struct mlxdevm_ops *ops = mlxdevm->ops;
	size_t len = strlen(parent_name);
	struct mlxdevm_rate *parent;
	int err = -EOPNOTSUPP;

	parent = mlxdevm_rate->parent;

	if (parent && !len) {
		if (mlxdevm_rate_is_leaf(mlxdevm_rate))
			err = ops->rate_leaf_parent_set(mlxdevm_rate, NULL,
							mlxdevm_rate->priv, NULL,
							info->extack);
		else if (mlxdevm_rate_is_node(mlxdevm_rate))
			err = ops->rate_node_parent_set(mlxdevm_rate, NULL,
							mlxdevm_rate->priv, NULL,
							info->extack);
		if (err)
			return err;

		refcount_dec(&parent->refcnt);
		mlxdevm_rate->parent = NULL;
	} else if (len) {
		parent = mlxdevm_rate_node_get_by_name(mlxdevm, parent_name);
		if (IS_ERR(parent))
			return -ENODEV;

		if (parent == mlxdevm_rate) {
			NL_SET_ERR_MSG(info->extack, "Parent to self is not allowed");
			return -EINVAL;
		}

		if (mlxdevm_rate_is_node(mlxdevm_rate) &&
		    mlxdevm_rate_is_parent_node(mlxdevm_rate, parent->parent)) {
			NL_SET_ERR_MSG(info->extack, "Node is already a parent of parent node.");
			return -EEXIST;
		}

		if (mlxdevm_rate_is_leaf(mlxdevm_rate))
			err = ops->rate_leaf_parent_set(mlxdevm_rate, parent,
							mlxdevm_rate->priv, parent->priv,
							info->extack);
		else if (mlxdevm_rate_is_node(mlxdevm_rate))
			err = ops->rate_node_parent_set(mlxdevm_rate, parent,
							mlxdevm_rate->priv, parent->priv,
							info->extack);
		if (err)
			return err;

		if (mlxdevm_rate->parent)
			/* we're reassigning to other parent in this case */
			refcount_dec(&mlxdevm_rate->parent->refcnt);

		refcount_inc(&parent->refcnt);
		mlxdevm_rate->parent = parent;
	}

	return 0;
}

static int mlxdevm_nl_rate_set(struct mlxdevm_rate *mlxdevm_rate,
			       const struct mlxdevm_ops *ops,
			       struct genl_info *info)
{
	struct nlattr *nla_parent, **attrs = info->attrs;
	int err = -EOPNOTSUPP;
	u32 priority;
	u32 weight;
	u64 rate;

	if (attrs[MLXDEVM_ATTR_RATE_TX_SHARE]) {
		rate = nla_get_u64(attrs[MLXDEVM_ATTR_RATE_TX_SHARE]);
		if (mlxdevm_rate_is_leaf(mlxdevm_rate)) {
			err = ops->rate_leaf_tx_share_set(mlxdevm_rate, mlxdevm_rate->priv,
							  rate, info->extack);
		}
		else if (mlxdevm_rate_is_node(mlxdevm_rate)){
			err = ops->rate_node_tx_share_set(mlxdevm_rate, mlxdevm_rate->priv,
							  rate, info->extack);
		}
		if (err)
			return err;
		mlxdevm_rate->tx_share = rate;
	}

	if (attrs[MLXDEVM_ATTR_RATE_TX_MAX]) {
		rate = nla_get_u64(attrs[MLXDEVM_ATTR_RATE_TX_MAX]);
		if (mlxdevm_rate_is_leaf(mlxdevm_rate)){
			err = ops->rate_leaf_tx_max_set(mlxdevm_rate, mlxdevm_rate->priv,
							rate, info->extack);
		}
		else if (mlxdevm_rate_is_node(mlxdevm_rate)) {
			err = ops->rate_node_tx_max_set(mlxdevm_rate, mlxdevm_rate->priv,
							rate, info->extack);
		}
		if (err)
			return err;
		mlxdevm_rate->tx_max = rate;
	}

	if (attrs[MLXDEVM_ATTR_RATE_TX_PRIORITY]) {
		priority = nla_get_u32(attrs[MLXDEVM_ATTR_RATE_TX_PRIORITY]);
		if (mlxdevm_rate_is_leaf(mlxdevm_rate))
			err = ops->rate_leaf_tx_priority_set(mlxdevm_rate, mlxdevm_rate->priv,
							     priority, info->extack);
		else if (mlxdevm_rate_is_node(mlxdevm_rate))
			err = ops->rate_node_tx_priority_set(mlxdevm_rate, mlxdevm_rate->priv,
							     priority, info->extack);

		if (err)
			return err;
		mlxdevm_rate->tx_priority = priority;
	}

	if (attrs[MLXDEVM_ATTR_RATE_TX_WEIGHT]) {
		weight = nla_get_u32(attrs[MLXDEVM_ATTR_RATE_TX_WEIGHT]);
		if (mlxdevm_rate_is_leaf(mlxdevm_rate))
			err = ops->rate_leaf_tx_weight_set(mlxdevm_rate, mlxdevm_rate->priv,
							   weight, info->extack);
		else if (mlxdevm_rate_is_node(mlxdevm_rate))
			err = ops->rate_node_tx_weight_set(mlxdevm_rate, mlxdevm_rate->priv,
							   weight, info->extack);

		if (err)
			return err;
		mlxdevm_rate->tx_weight = weight;
	}

	nla_parent = attrs[MLXDEVM_ATTR_RATE_PARENT_NODE_NAME];
	if (nla_parent) {
		err = mlxdevm_nl_rate_parent_node_set(mlxdevm_rate, info,
						      nla_parent);
		if (err)
			return err;
	}

	return 0;
}

static bool mlxdevm_rate_set_ops_supported(const struct mlxdevm_ops *ops,
					   struct genl_info *info,
					   enum mlxdevm_rate_type type)
{
	struct nlattr **attrs = info->attrs;

	if (type == MLXDEVM_RATE_TYPE_LEAF) {
		if (attrs[MLXDEVM_ATTR_RATE_TX_SHARE] && !ops->rate_leaf_tx_share_set) {
			NL_SET_ERR_MSG(info->extack, "TX share set isn't supported for the leafs");
			return false;
		}
		if (attrs[MLXDEVM_ATTR_RATE_TX_MAX] && !ops->rate_leaf_tx_max_set) {
			NL_SET_ERR_MSG(info->extack, "TX max set isn't supported for the leafs");
			return false;
		}
		if (attrs[MLXDEVM_ATTR_RATE_PARENT_NODE_NAME] &&
		    !ops->rate_leaf_parent_set) {
			NL_SET_ERR_MSG(info->extack, "Parent set isn't supported for the leafs");
			return false;
		}
		if (attrs[MLXDEVM_ATTR_RATE_TX_PRIORITY] && !ops->rate_leaf_tx_priority_set) {
			NL_SET_ERR_MSG_ATTR(info->extack,
					    attrs[MLXDEVM_ATTR_RATE_TX_PRIORITY],
					    "TX priority set isn't supported for the leafs");
			return false;
		}
		if (attrs[MLXDEVM_ATTR_RATE_TX_WEIGHT] && !ops->rate_leaf_tx_weight_set) {
			NL_SET_ERR_MSG_ATTR(info->extack,
					    attrs[MLXDEVM_ATTR_RATE_TX_WEIGHT],
					    "TX weight set isn't supported for the leafs");
			return false;
		}
	} else if (type == MLXDEVM_RATE_TYPE_NODE) {
		if (attrs[MLXDEVM_ATTR_RATE_TX_SHARE] && !ops->rate_node_tx_share_set) {
			NL_SET_ERR_MSG(info->extack, "TX share set isn't supported for the nodes");
			return false;
		}
		if (attrs[MLXDEVM_ATTR_RATE_TX_MAX] && !ops->rate_node_tx_max_set) {
			NL_SET_ERR_MSG(info->extack, "TX max set isn't supported for the nodes");
			return false;
		}
		if (attrs[MLXDEVM_ATTR_RATE_PARENT_NODE_NAME] &&
		    !ops->rate_node_parent_set) {
			NL_SET_ERR_MSG(info->extack, "Parent set isn't supported for the nodes");
			return false;
		}
		if (attrs[MLXDEVM_ATTR_RATE_TX_PRIORITY] && !ops->rate_node_tx_priority_set) {
			NL_SET_ERR_MSG_ATTR(info->extack,
					    attrs[MLXDEVM_ATTR_RATE_TX_PRIORITY],
					    "TX priority set isn't supported for the nodes");
			return false;
		}
		if (attrs[MLXDEVM_ATTR_RATE_TX_WEIGHT] && !ops->rate_node_tx_weight_set) {
			NL_SET_ERR_MSG_ATTR(info->extack,
					    attrs[MLXDEVM_ATTR_RATE_TX_WEIGHT],
					    "TX weight set isn't supported for the nodes");
			return false;
		}
	} else {
		WARN(1, "Unknown type of rate object");
		return false;
	}

	return true;
}

int mlxdevm_nl_rate_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm *mlxdevm = info->user_ptr[0];
	struct mlxdevm_rate *mlxdevm_rate;
	const struct mlxdevm_ops *ops;
	int err;

	mlxdevm_rate = mlxdevm_rate_get_from_info(mlxdevm, info);
	if (IS_ERR(mlxdevm_rate))
		return PTR_ERR(mlxdevm_rate);

	ops = mlxdevm->ops;
	if (!ops || !mlxdevm_rate_set_ops_supported(ops, info, mlxdevm_rate->type))
		return -EOPNOTSUPP;

	err = mlxdevm_nl_rate_set(mlxdevm_rate, ops, info);

	if (!err)
		mlxdevm_rate_notify(mlxdevm_rate, MLXDEVM_CMD_RATE_NEW);
	return err;
}

int mlxdevm_nl_rate_new_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm *mlxdevm = info->user_ptr[0];
	struct mlxdevm_rate *rate_node;
	const struct mlxdevm_ops *ops;
	int err;

	ops = mlxdevm->ops;
	if (!ops || !ops->rate_node_new || !ops->rate_node_del) {
		NL_SET_ERR_MSG(info->extack, "Rate nodes aren't supported");
		return -EOPNOTSUPP;
	}

	if (!mlxdevm_rate_set_ops_supported(ops, info, MLXDEVM_RATE_TYPE_NODE))
		return -EOPNOTSUPP;

	rate_node = mlxdevm_rate_node_get_from_attrs(mlxdevm, info->attrs);
	if (!IS_ERR(rate_node))
		return -EEXIST;
	else if (rate_node == ERR_PTR(-EINVAL))
		return -EINVAL;

	rate_node = kzalloc(sizeof(*rate_node), GFP_KERNEL);
	if (!rate_node)
		return -ENOMEM;

	rate_node->mlxdevm = mlxdevm;
	rate_node->type = MLXDEVM_RATE_TYPE_NODE;
	rate_node->name = nla_strdup(info->attrs[MLXDEVM_ATTR_RATE_NODE_NAME], GFP_KERNEL);
	if (!rate_node->name) {
		err = -ENOMEM;
		goto err_strdup;
	}

	err = ops->rate_node_new(rate_node, &rate_node->priv, info->extack);
	if (err)
		goto err_node_new;

	err = mlxdevm_nl_rate_set(rate_node, ops, info);
	if (err)
		goto err_rate_set;

	refcount_set(&rate_node->refcnt, 1);
	list_add(&rate_node->list, &mlxdevm->rate_list);
	mlxdevm_rate_notify(rate_node, MLXDEVM_CMD_RATE_NEW);
	return 0;

err_rate_set:
	ops->rate_node_del(rate_node, rate_node->priv, info->extack);
err_node_new:
	kfree(rate_node->name);
err_strdup:
	kfree(rate_node);
	return err;
}

int mlxdevm_nl_rate_del_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm *mlxdevm = info->user_ptr[0];
	struct mlxdevm_rate *rate_node;
	int err;

	rate_node = mlxdevm_rate_node_get_from_info(mlxdevm, info);
	if (IS_ERR(rate_node))
		return PTR_ERR(rate_node);

	if (refcount_read(&rate_node->refcnt) > 1) {
		NL_SET_ERR_MSG(info->extack, "Node has children. Cannot delete node.");
		return -EBUSY;
	}

	mlxdevm_rate_notify(rate_node, MLXDEVM_CMD_RATE_DEL);
	err = mlxdevm->ops->rate_node_del(rate_node, rate_node->priv,
					  info->extack);
	if (rate_node->parent)
		refcount_dec(&rate_node->parent->refcnt);
	list_del(&rate_node->list);
	kfree(rate_node->name);
	kfree(rate_node);
	return err;
}
#if 0

int devlink_rate_nodes_check(struct devlink *devlink, u16 mode,
			     struct netlink_ext_ack *extack)
{
	struct devlink_rate *devlink_rate;

	list_for_each_entry(devlink_rate, &devlink->rate_list, list)
		if (devlink_rate_is_node(devlink_rate)) {
			NL_SET_ERR_MSG(extack, "Rate node(s) exists.");
			return -EBUSY;
		}
	return 0;
}

/**
 * devl_rate_node_create - create devlink rate node
 * @devlink: devlink instance
 * @priv: driver private data
 * @node_name: name of the resulting node
 * @parent: parent devlink_rate struct
 *
 * Create devlink rate object of type node
 */
struct devlink_rate *
devl_rate_node_create(struct devlink *devlink, void *priv, char *node_name,
		      struct devlink_rate *parent)
{
	struct devlink_rate *rate_node;

	rate_node = devlink_rate_node_get_by_name(devlink, node_name);
	if (!IS_ERR(rate_node))
		return ERR_PTR(-EEXIST);

	rate_node = kzalloc(sizeof(*rate_node), GFP_KERNEL);
	if (!rate_node)
		return ERR_PTR(-ENOMEM);

	if (parent) {
		rate_node->parent = parent;
		refcount_inc(&rate_node->parent->refcnt);
	}

	rate_node->type = DEVLINK_RATE_TYPE_NODE;
	rate_node->devlink = devlink;
	rate_node->priv = priv;

	rate_node->name = kstrdup(node_name, GFP_KERNEL);
	if (!rate_node->name) {
		kfree(rate_node);
		return ERR_PTR(-ENOMEM);
	}

	refcount_set(&rate_node->refcnt, 1);
	list_add(&rate_node->list, &devlink->rate_list);
	devlink_rate_notify(rate_node, DEVLINK_CMD_RATE_NEW);
	return rate_node;
}
EXPORT_SYMBOL_GPL(devl_rate_node_create);
#endif

/**
 * devm_rate_leaf_create - create mlxdevm rate leaf
 * @mlxdevm_port: mlxdevm port object to create rate object on
 * @priv: driver private data
 * @parent: parent mlxdevm_rate struct
 *
 * Create mlxdevm rate object of type leaf on provided @mlxdevm_port.
 */
int devm_rate_leaf_create(struct mlxdevm_port *mlxdevm_port, void *priv,
			  struct mlxdevm_rate *parent)
{
	struct mlxdevm *mlxdevm = mlxdevm_port->mlxdevm;
	struct mlxdevm_rate *mlxdevm_rate;

	devm_assert_locked(mlxdevm_port->mlxdevm);

	if (WARN_ON(mlxdevm_port->mlxdevm_rate))
		return -EBUSY;

	mlxdevm_rate = kzalloc(sizeof(*mlxdevm_rate), GFP_KERNEL);
	if (!mlxdevm_rate)
		return -ENOMEM;

	if (parent) {
		mlxdevm_rate->parent = parent;
		refcount_inc(&mlxdevm_rate->parent->refcnt);
	}

	mlxdevm_rate->type = MLXDEVM_RATE_TYPE_LEAF;
	mlxdevm_rate->mlxdevm = mlxdevm;
	mlxdevm_rate->mlxdevm_port = mlxdevm_port;
	mlxdevm_rate->priv = priv;
	list_add_tail(&mlxdevm_rate->list, &mlxdevm->rate_list);
	mlxdevm_port->mlxdevm_rate = mlxdevm_rate;
	mlxdevm_rate_notify(mlxdevm_rate, MLXDEVM_CMD_RATE_NEW);

	return 0;
}
EXPORT_SYMBOL_GPL(devm_rate_leaf_create);

/**
 * devm_rate_leaf_destroy - destroy mlxdevm rate leaf
 *
 * @mlxdevm_port: mlxdevm port linked to the rate object
 *
 * Destroy the mlxdevm rate object of type leaf on provided @mlxdevm_port.
 */
void devm_rate_leaf_destroy(struct mlxdevm_port *mlxdevm_port)
{
	struct mlxdevm_rate *mlxdevm_rate = mlxdevm_port->mlxdevm_rate;

	devm_assert_locked(mlxdevm_port->mlxdevm);
	if (!mlxdevm_rate)
		return;

	mlxdevm_rate_notify(mlxdevm_rate, MLXDEVM_CMD_RATE_DEL);
	if (mlxdevm_rate->parent)
		refcount_dec(&mlxdevm_rate->parent->refcnt);
	list_del(&mlxdevm_rate->list);
	mlxdevm_port->mlxdevm_rate = NULL;
	kfree(mlxdevm_rate);
}
EXPORT_SYMBOL_GPL(devm_rate_leaf_destroy);

/**
 * devm_rate_nodes_destroy - destroy all mlxdevm rate nodes on device
 * @mlxdevm: mlxdevm instance
 *
 * Unset parent for all rate objects and destroy all rate nodes
 * on specified device.
 */
void devm_rate_nodes_destroy(struct mlxdevm *mlxdevm) //TODO: check where to add mlxdevm only callbacks
{
	static struct mlxdevm_rate *mlxdevm_rate, *tmp;
	const struct mlxdevm_ops *ops = mlxdevm->ops;

	devm_assert_locked(mlxdevm);

	list_for_each_entry(mlxdevm_rate, &mlxdevm->rate_list, list) {
		if (!mlxdevm_rate->parent)
			continue;

		refcount_dec(&mlxdevm_rate->parent->refcnt);
		if (mlxdevm_rate_is_leaf(mlxdevm_rate))
			ops->rate_leaf_parent_set(mlxdevm_rate, NULL, mlxdevm_rate->priv,
						  NULL, NULL);
		else if (mlxdevm_rate_is_node(mlxdevm_rate))
			ops->rate_node_parent_set(mlxdevm_rate, NULL, mlxdevm_rate->priv,
						  NULL, NULL);
	}
	list_for_each_entry_safe(mlxdevm_rate, tmp, &mlxdevm->rate_list, list) {
		if (mlxdevm_rate_is_node(mlxdevm_rate)) {
			ops->rate_node_del(mlxdevm_rate, mlxdevm_rate->priv, NULL);
			list_del(&mlxdevm_rate->list);
			kfree(mlxdevm_rate->name);
			kfree(mlxdevm_rate);
		}
	}
}
EXPORT_SYMBOL_GPL(devm_rate_nodes_destroy);
