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

bool mlxdevm_rate_is_node(const struct mlxdevm_rate *mlxdevm_rate)
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

/* Repeatedly walks the nested mlxdevm chain while cross device rate nodes are
 * supported and finds the topmost instance where rates should be stored.
 * That instance is locked, referenced and returned.
 * When cross device rate nodes aren't supported the original mlxdevm instance
 * is returned.
 */
static struct mlxdevm *devm_rate_lock(struct mlxdevm *mlxdevm)
{
	struct mlxdevm *rate_mlxdevm = mlxdevm, *parent;

	devm_assert_locked(mlxdevm);

	while (rate_mlxdevm->ops &&
	       rate_mlxdevm->ops->supported_cross_device_rate_nodes) {
		parent = mlxdevm_nested_in_get_lock(rate_mlxdevm);
		if (!parent)
			break;
		if (rate_mlxdevm != mlxdevm) {
			/* Unlock intermediate instances. */
			devm_unlock(rate_mlxdevm);
			mlxdevm_put(rate_mlxdevm);
		}
		rate_mlxdevm = parent;
	}
	return rate_mlxdevm;
}

/* Unlocks and puts 'rate mlxdevm' if different than 'mlxdevm'. */
static void devm_rate_unlock(struct mlxdevm *mlxdevm,
			     struct mlxdevm *rate_mlxdevm)
{
	if (mlxdevm == rate_mlxdevm)
		return;

	devm_unlock(rate_mlxdevm);
	mlxdevm_put(rate_mlxdevm);
}

static struct mlxdevm_rate *
mlxdevm_rate_node_get_by_name(struct mlxdevm *rate_mlxdevm,
			      struct mlxdevm *mlxdevm, const char *node_name)
{
	struct mlxdevm_rate *mlxdevm_rate;

	list_for_each_entry(mlxdevm_rate, &rate_mlxdevm->rate_list, list) {
		if (mlxdevm_rate->mlxdevm == mlxdevm &&
		    mlxdevm_rate_is_node(mlxdevm_rate) &&
		    !strcmp(node_name, mlxdevm_rate->name))
			return mlxdevm_rate;
	}
	return ERR_PTR(-ENODEV);
}

static struct mlxdevm_rate *
mlxdevm_rate_node_get_from_attrs(struct mlxdevm *rate_mlxdevm,
				 struct mlxdevm *mlxdevm, struct nlattr **attrs)
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

	return mlxdevm_rate_node_get_by_name(rate_mlxdevm, mlxdevm,
					     rate_node_name);
}

static struct mlxdevm_rate *
mlxdevm_rate_node_get_from_info(struct mlxdevm *rate_mlxdevm,
				struct mlxdevm *mlxdevm, struct genl_info *info)
{
	return mlxdevm_rate_node_get_from_attrs(rate_mlxdevm, mlxdevm,
						info->attrs);
}

static struct mlxdevm_rate *
mlxdevm_rate_get_from_info(struct mlxdevm *rate_mlxdevm,
			   struct mlxdevm *mlxdevm, struct genl_info *info)
{
	struct nlattr **attrs = info->attrs;

	if (attrs[MLXDEVM_ATTR_PORT_INDEX])
		return mlxdevm_rate_leaf_get_from_info(mlxdevm, info);
	else if (attrs[MLXDEVM_ATTR_RATE_NODE_NAME])
		return mlxdevm_rate_node_get_from_info(rate_mlxdevm, mlxdevm,
						       info);
	else
		return ERR_PTR(-EINVAL);
}

static int mlxdevm_rate_put_tc_bws(struct sk_buff *msg, u32 *tc_bw)
{
	struct nlattr *nla_tc_bw;
	int i;

	for (i = 0; i < MLXDEVM_RATE_TCS_MAX; i++) {
		nla_tc_bw = nla_nest_start(msg, MLXDEVM_ATTR_RATE_TC_BWS);
		if (!nla_tc_bw)
			return -EMSGSIZE;

		if (nla_put_u8(msg, MLXDEVM_RATE_TC_ATTR_INDEX, i) ||
		    nla_put_u32(msg, MLXDEVM_RATE_TC_ATTR_BW, tc_bw[i]))
			goto nla_put_failure;

		nla_nest_end(msg, nla_tc_bw);
	}
	return 0;

nla_put_failure:
	nla_nest_cancel(msg, nla_tc_bw);
	return -EMSGSIZE;
}

static int mlxdevm_nl_rate_parent_fill(struct sk_buff *msg,
                                       struct mlxdevm_rate *mlxdevm_rate)
{
        struct mlxdevm_rate *parent = mlxdevm_rate->parent;
        struct mlxdevm *mlxdevm = parent->mlxdevm;

        if (nla_put_string(msg, MLXDEVM_ATTR_RATE_PARENT_NODE_NAME,
                           parent->name))
                return -EMSGSIZE;

        if (mlxdevm != mlxdevm_rate->mlxdevm &&
            mlxdevm_nl_put_nested_handle(msg,
                                         mlxdevm_net(mlxdevm_rate->mlxdevm),
                                         mlxdevm, MLXDEVM_ATTR_PARENT_DEV))
                return -EMSGSIZE;

        return 0;
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

	if (mlxdevm_nl_put_u64(msg, MLXDEVM_ATTR_RATE_TX_SHARE,
			       mlxdevm_rate->tx_share))
		goto nla_put_failure;

	if (mlxdevm_nl_put_u64(msg, MLXDEVM_ATTR_RATE_TX_MAX,
			       mlxdevm_rate->tx_max))
		goto nla_put_failure;

	if (nla_put_u32(msg, MLXDEVM_ATTR_RATE_TX_PRIORITY,
			mlxdevm_rate->tx_priority))
		goto nla_put_failure;

	if (nla_put_u32(msg, MLXDEVM_ATTR_RATE_TX_WEIGHT,
			mlxdevm_rate->tx_weight))
		goto nla_put_failure;

	if (mlxdevm_rate->parent &&
	    mlxdevm_nl_rate_parent_fill(msg, mlxdevm_rate))
		goto nla_put_failure;

	if (mlxdevm_rate_put_tc_bws(msg, mlxdevm_rate->tc_bw))
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
#ifdef HAVE_BLOCKED_DEVLINK_CODE

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
	struct mlxdevm *rate_mlxdevm;
	int idx = 0;
	int err = 0;

	rate_mlxdevm = devm_rate_lock(mlxdevm);
	list_for_each_entry(mlxdevm_rate, &rate_mlxdevm->rate_list, list) {
		enum mlxdevm_command cmd = MLXDEVM_CMD_RATE_NEW;
		u32 id = NETLINK_CB(cb->skb).portid;

		if (idx < state->idx || mlxdevm_rate->mlxdevm != mlxdevm) {
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
	devm_rate_unlock(mlxdevm, rate_mlxdevm);

	return err;
}

int mlxdevm_nl_rate_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	return mlxdevm_nl_dumpit(skb, cb, mlxdevm_nl_rate_get_dump_one);
}

int mlxdevm_nl_rate_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm *rate_mlxdevm, *mlxdevm = mlxdevm_nl_ctx(info)->mlxdevm;
	struct mlxdevm_rate *mlxdevm_rate;
	struct sk_buff *msg;
	int err;

	rate_mlxdevm = devm_rate_lock(mlxdevm);
	mlxdevm_rate = mlxdevm_rate_get_from_info(rate_mlxdevm, mlxdevm, info);
	if (IS_ERR(mlxdevm_rate)) {
		err = PTR_ERR(mlxdevm_rate);
		goto unlock;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg) {
		err = -ENOMEM;
		goto unlock;
	}

	err = mlxdevm_nl_rate_fill(msg, mlxdevm_rate, MLXDEVM_CMD_RATE_NEW,
				   info->snd_portid, info->snd_seq, 0,
				   info->extack);
	if (err)
		goto err_fill;

	devm_rate_unlock(mlxdevm, rate_mlxdevm);
	return genlmsg_reply(msg, info);

err_fill:
	nlmsg_free(msg);
unlock:
	devm_rate_unlock(mlxdevm, rate_mlxdevm);
	return err;
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
				struct mlxdevm *rate_mlxdevm,
				struct genl_info *info,
				struct nlattr *nla_parent)
{
	struct mlxdevm *mlxdevm = mlxdevm_rate->mlxdevm, *parent_mlxdevm;
	const char *parent_name = nla_data(nla_parent);
	const struct mlxdevm_ops *ops = mlxdevm->ops;
	size_t len = strlen(parent_name);
	struct mlxdevm_rate *parent;
	int err = -EOPNOTSUPP;

	parent_mlxdevm = mlxdevm_nl_ctx(info)->parent_mlxdevm ? : mlxdevm;
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
		/* parent_mlxdevm (when different than mlxdevm) isn't locked,
		 * but the rate node mlxdevm instance is, so nobody from the
		 * same group of devices sharing rates could change the used
		 * fields or unregister the parent.
		 */
		parent = mlxdevm_rate_node_get_by_name(rate_mlxdevm,
		                                       parent_mlxdevm,
						       parent_name);
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

static int mlxdevm_nl_rate_tc_bw_parse(struct nlattr *parent_nest, u32 *tc_bw,
				       unsigned long *bitmap,
				       struct netlink_ext_ack *extack)
{
	struct nlattr *tb[MLXDEVM_RATE_TC_ATTR_MAX + 1];
	u8 tc_index;
	int err;

	err = nla_parse_nested(tb, MLXDEVM_RATE_TC_ATTR_MAX, parent_nest,
			       mlxdevm_dl_rate_tc_bws_nl_policy, extack);
	if (err)
		return err;

	if (!tb[MLXDEVM_RATE_TC_ATTR_INDEX]) {
		NL_SET_ERR_ATTR_MISS(extack, parent_nest,
				     MLXDEVM_RATE_TC_ATTR_INDEX);
		return -EINVAL;
	}

	tc_index = nla_get_u8(tb[MLXDEVM_RATE_TC_ATTR_INDEX]);

	if (!tb[MLXDEVM_RATE_TC_ATTR_BW]) {
		NL_SET_ERR_ATTR_MISS(extack, parent_nest,
				     MLXDEVM_RATE_TC_ATTR_BW);
		return -EINVAL;
	}

	if (test_and_set_bit(tc_index, bitmap)) {
		NL_SET_ERR_MSG_FMT(extack,
				   "Duplicate traffic class index specified (%u)",
				   tc_index);
		return -EINVAL;
	}

	tc_bw[tc_index] = nla_get_u32(tb[MLXDEVM_RATE_TC_ATTR_BW]);

	return 0;
}

static int mlxdevm_nl_rate_tc_bw_set(struct mlxdevm_rate *mlxdevm_rate,
				     struct genl_info *info)
{
	DECLARE_BITMAP(bitmap, MLXDEVM_RATE_TCS_MAX) = {};
	struct mlxdevm *mlxdevm = mlxdevm_rate->mlxdevm;
	const struct mlxdevm_ops *ops = mlxdevm->ops;
	u32 tc_bw[MLXDEVM_RATE_TCS_MAX] = {};
	int rem, err = -EOPNOTSUPP, i;
	struct nlattr *attr;

	nlmsg_for_each_attr_type(attr, MLXDEVM_ATTR_RATE_TC_BWS, info->nlhdr,
				 GENL_HDRLEN, rem) {
		err = mlxdevm_nl_rate_tc_bw_parse(attr, tc_bw, bitmap,
						  info->extack);
		if (err)
			return err;
	}

	for (i = 0; i < MLXDEVM_RATE_TCS_MAX; i++) {
		if (!test_bit(i, bitmap)) {
			NL_SET_ERR_MSG_FMT(info->extack,
					   "Bandwidth values must be specified for all %u traffic classes",
					   MLXDEVM_RATE_TCS_MAX);
			return -EINVAL;
		}
	}

	if (mlxdevm_rate_is_leaf(mlxdevm_rate))
		err = ops->rate_leaf_tc_bw_set(mlxdevm_rate, mlxdevm_rate->priv,
					       tc_bw, info->extack);
	else if (mlxdevm_rate_is_node(mlxdevm_rate))
		err = ops->rate_node_tc_bw_set(mlxdevm_rate, mlxdevm_rate->priv,
					       tc_bw, info->extack);

	if (err)
		return err;

	memcpy(mlxdevm_rate->tc_bw, tc_bw, sizeof(tc_bw));

	return 0;
}

static int mlxdevm_nl_rate_set(struct mlxdevm_rate *mlxdevm_rate,
			       struct mlxdevm *rate_mlxdevm,
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

	if (attrs[MLXDEVM_ATTR_RATE_TC_BWS]) {
		err = mlxdevm_nl_rate_tc_bw_set(mlxdevm_rate, info);
		if (err)
			return err;
	}

	nla_parent = attrs[MLXDEVM_ATTR_RATE_PARENT_NODE_NAME];
	if (nla_parent) {
		err = mlxdevm_nl_rate_parent_node_set(mlxdevm_rate,
						      rate_mlxdevm, info,
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
		if (attrs[MLXDEVM_ATTR_RATE_TC_BWS] &&
		    !ops->rate_leaf_tc_bw_set) {
			NL_SET_ERR_MSG_ATTR(info->extack,
					    attrs[MLXDEVM_ATTR_RATE_TC_BWS],
					    "TC bandwidth set isn't supported for the leafs");
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
		if (attrs[MLXDEVM_ATTR_RATE_TC_BWS] &&
		    !ops->rate_node_tc_bw_set) {
			NL_SET_ERR_MSG_ATTR(info->extack,
					    attrs[MLXDEVM_ATTR_RATE_TC_BWS],
					    "TC bandwidth set isn't supported for the nodes");
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
	struct mlxdevm_nl_ctx *ctx = mlxdevm_nl_ctx(info);
	struct mlxdevm *mlxdevm = ctx->mlxdevm;
	struct mlxdevm_rate *mlxdevm_rate;
	const struct mlxdevm_ops *ops;
	struct mlxdevm *rate_mlxdevm;
	int err;

	rate_mlxdevm = devm_rate_lock(mlxdevm);
	mlxdevm_rate = mlxdevm_rate_get_from_info(rate_mlxdevm, mlxdevm, info);
	if (IS_ERR(mlxdevm_rate)) {
		err = PTR_ERR(mlxdevm_rate);
		goto unlock;
	}

	ops = mlxdevm->ops;
	if (!ops ||
	    !mlxdevm_rate_set_ops_supported(ops, info, mlxdevm_rate->type)) {
		err = -EOPNOTSUPP;
		goto unlock;
	}

	if (ctx->parent_mlxdevm && ctx->parent_mlxdevm != mlxdevm &&
	    !ops->supported_cross_device_rate_nodes) {
		NL_SET_ERR_MSG(info->extack,
			       "Cross-device rate parents aren't supported");
		err = -EOPNOTSUPP;
		goto unlock;
	}

	err = mlxdevm_nl_rate_set(mlxdevm_rate, rate_mlxdevm, ops, info);

	if (!err)
		mlxdevm_rate_notify(mlxdevm_rate, MLXDEVM_CMD_RATE_NEW);
unlock:
	devm_rate_unlock(mlxdevm, rate_mlxdevm);
	return err;
}

int mlxdevm_nl_rate_new_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm_nl_ctx *ctx = mlxdevm_nl_ctx(info);
	struct mlxdevm *mlxdevm = ctx->mlxdevm;
	struct mlxdevm_rate *rate_node;
	const struct mlxdevm_ops *ops;
	struct mlxdevm *rate_mlxdevm;
	int err;

	ops = mlxdevm->ops;
	if (!ops || !ops->rate_node_new || !ops->rate_node_del) {
		NL_SET_ERR_MSG(info->extack, "Rate nodes aren't supported");
		return -EOPNOTSUPP;
	}

	if (!mlxdevm_rate_set_ops_supported(ops, info, MLXDEVM_RATE_TYPE_NODE))
		return -EOPNOTSUPP;

	if (ctx->parent_mlxdevm && ctx->parent_mlxdevm != mlxdevm &&
	    !ops->supported_cross_device_rate_nodes) {
		NL_SET_ERR_MSG(info->extack,
		               "Cross-device rate parents aren't supported");
		return -EOPNOTSUPP;
	}

	rate_mlxdevm = devm_rate_lock(mlxdevm);
	rate_node = mlxdevm_rate_node_get_from_attrs(rate_mlxdevm, mlxdevm,
						     info->attrs);
	if (!IS_ERR(rate_node)) {
		err = -EEXIST;
		goto unlock;
	} else if (rate_node == ERR_PTR(-EINVAL)) {
		err = -EINVAL;
		goto unlock;
	}

	rate_node = kzalloc_obj(*rate_node);
	if (!rate_node) {
		err = -ENOMEM;
		goto unlock;
	}

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

	err = mlxdevm_nl_rate_set(rate_node, rate_mlxdevm, ops, info);
	if (err)
		goto err_rate_set;

	refcount_set(&rate_node->refcnt, 1);
	list_add(&rate_node->list, &rate_mlxdevm->rate_list);
	mlxdevm_rate_notify(rate_node, MLXDEVM_CMD_RATE_NEW);
	devm_rate_unlock(mlxdevm, rate_mlxdevm);
	return 0;

err_rate_set:
	ops->rate_node_del(rate_node, rate_node->priv, info->extack);
err_node_new:
	kfree(rate_node->name);
err_strdup:
	kfree(rate_node);
unlock:
	devm_rate_unlock(mlxdevm, rate_mlxdevm);
	return err;
}

int mlxdevm_nl_rate_del_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm *rate_mlxdevm, *mlxdevm = mlxdevm_nl_ctx(info)->mlxdevm;
	struct mlxdevm_rate *rate_node;
	int err;

	rate_mlxdevm = devm_rate_lock(mlxdevm);
	rate_node = mlxdevm_rate_node_get_from_info(rate_mlxdevm, mlxdevm,
						    info);
	if (IS_ERR(rate_node)) {
		err = PTR_ERR(rate_node);
		goto unlock;
	}

	if (refcount_read(&rate_node->refcnt) > 1) {
		NL_SET_ERR_MSG(info->extack, "Node has children. Cannot delete node.");
		err = -EBUSY;
		goto unlock;
	}

	mlxdevm_rate_notify(rate_node, MLXDEVM_CMD_RATE_DEL);
	err = mlxdevm->ops->rate_node_del(rate_node, rate_node->priv,
					  info->extack);
	if (rate_node->parent)
		refcount_dec(&rate_node->parent->refcnt);
	list_del(&rate_node->list);
	kfree(rate_node->name);
	kfree(rate_node);
unlock:
	devm_rate_unlock(mlxdevm, rate_mlxdevm);
	return err;
}

int mlxdevm_rates_check(struct mlxdevm *mlxdevm,
			bool (*rate_filter)(const struct mlxdevm_rate *),
			struct netlink_ext_ack *extack)
{
	struct mlxdevm_rate *mlxdevm_rate;
	struct mlxdevm *rate_mlxdevm;
	int err = 0;

	rate_mlxdevm = devm_rate_lock(mlxdevm);
	list_for_each_entry(mlxdevm_rate, &rate_mlxdevm->rate_list, list)
		if (mlxdevm_rate->mlxdevm == mlxdevm &&
		    (!rate_filter || rate_filter(mlxdevm_rate))) {
			if (extack)
				NL_SET_ERR_MSG(extack, "Rate node(s) exists.");
			err = -EBUSY;
			break;
		}
	devm_rate_unlock(mlxdevm, rate_mlxdevm);
	return err;
}
#ifdef HAVE_BLOCKED_DEVLINK_CODE

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

	rate_node = kzalloc_obj(*rate_node);
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
	struct mlxdevm *rate_mlxdevm, *mlxdevm = mlxdevm_port->mlxdevm;
	struct mlxdevm_rate *mlxdevm_rate;

	devm_assert_locked(mlxdevm);

	if (WARN_ON(mlxdevm_port->mlxdevm_rate))
		return -EBUSY;

	mlxdevm_rate = kzalloc_obj(*mlxdevm_rate);
	if (!mlxdevm_rate)
		return -ENOMEM;

	rate_mlxdevm = devm_rate_lock(mlxdevm);
	if (parent) {
		mlxdevm_rate->parent = parent;
		refcount_inc(&mlxdevm_rate->parent->refcnt);
	}

	mlxdevm_rate->type = MLXDEVM_RATE_TYPE_LEAF;
	mlxdevm_rate->mlxdevm = mlxdevm;
	mlxdevm_rate->mlxdevm_port = mlxdevm_port;
	mlxdevm_rate->priv = priv;
	list_add_tail(&mlxdevm_rate->list, &rate_mlxdevm->rate_list);
	mlxdevm_port->mlxdevm_rate = mlxdevm_rate;
	mlxdevm_rate_notify(mlxdevm_rate, MLXDEVM_CMD_RATE_NEW);
	devm_rate_unlock(mlxdevm, rate_mlxdevm);

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
	struct mlxdevm *rate_mlxdevm, *mlxdevm = mlxdevm_port->mlxdevm;

	devm_assert_locked(mlxdevm);
	if (!mlxdevm_rate)
		return;

	rate_mlxdevm = devm_rate_lock(mlxdevm);
	mlxdevm_rate_notify(mlxdevm_rate, MLXDEVM_CMD_RATE_DEL);
	if (mlxdevm_rate->parent)
		refcount_dec(&mlxdevm_rate->parent->refcnt);
	list_del(&mlxdevm_rate->list);
	mlxdevm_port->mlxdevm_rate = NULL;
	devm_rate_unlock(mlxdevm, rate_mlxdevm);
	kfree(mlxdevm_rate);
}
EXPORT_SYMBOL_GPL(devm_rate_leaf_destroy);

/**
 * devm_rate_nodes_destroy - destroy all mlxdevm rate nodes on device
 * @mlxdevm: mlxdevm instance
 *
 * Unset parent for all rate objects involving this device and destroy all rate
 * nodes on it.
 */
void devm_rate_nodes_destroy(struct mlxdevm *mlxdevm)
{
	struct mlxdevm_rate *mlxdevm_rate, *tmp;
	const struct mlxdevm_ops *ops;
	struct mlxdevm *rate_mlxdevm;

	devm_assert_locked(mlxdevm);
	rate_mlxdevm = devm_rate_lock(mlxdevm);

	list_for_each_entry(mlxdevm_rate, &rate_mlxdevm->rate_list, list) {
		if (!mlxdevm_rate->parent ||
		    (mlxdevm_rate->mlxdevm != mlxdevm &&
		     mlxdevm_rate->parent->mlxdevm != mlxdevm))
			continue;

		/* This could destroy rate objects on other devlinks in the
		 * same hierarchy under 'rate_devlink'. This is safe because
		 * the shared common ancestor is locked so there can be no
		 * other concurrent rate operations on devlink_rate->devlink.
		 */
		ops = mlxdevm_rate->mlxdevm->ops;
		if (mlxdevm_rate_is_leaf(mlxdevm_rate))
			ops->rate_leaf_parent_set(mlxdevm_rate, NULL, mlxdevm_rate->priv,
						  NULL, NULL);
		else if (mlxdevm_rate_is_node(mlxdevm_rate))
			ops->rate_node_parent_set(mlxdevm_rate, NULL, mlxdevm_rate->priv,
						  NULL, NULL);

		refcount_dec(&mlxdevm_rate->parent->refcnt);
		mlxdevm_rate->parent = NULL;
	}
	ops = mlxdevm->ops;
	list_for_each_entry_safe(mlxdevm_rate, tmp, &rate_mlxdevm->rate_list,
		                 list) {
		if (mlxdevm_rate->mlxdevm == mlxdevm &&
		    mlxdevm_rate_is_node(mlxdevm_rate)) {
			ops->rate_node_del(mlxdevm_rate, mlxdevm_rate->priv, NULL);
			list_del(&mlxdevm_rate->list);
			kfree(mlxdevm_rate->name);
			kfree(mlxdevm_rate);
		}
	}
	devm_rate_unlock(mlxdevm, rate_mlxdevm);
}
EXPORT_SYMBOL_GPL(devm_rate_nodes_destroy);
