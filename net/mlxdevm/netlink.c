// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2016 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2016 Jiri Pirko <jiri@mellanox.com>
 */
#include <net/genetlink.h>
#include <net/sock.h>
#include <net/devlink.h>

#include "devl_internal.h"


#define MLXDEVM_NL_FLAG_NEED_PORT		BIT(0)
#define MLXDEVM_NL_FLAG_NEED_DEVLINK_OR_PORT	BIT(1)
#define MLXDEVM_NL_FLAG_NEED_DEV_LOCK		BIT(2)

static const struct genl_multicast_group mlxdevm_nl_mcgrps[] = {
	[MLXDEVM_MCGRP_CONFIG] = { .name = MLXDEVM_GENL_MCGRP_CONFIG_NAME },
};

struct mlxdevm_nl_sock_priv {
	struct mlxdevm_obj_desc __rcu *flt;
	spinlock_t flt_lock; /* Protects flt. */
};

static void mlxdevm_nl_sock_priv_init(void *priv)
{
	struct mlxdevm_nl_sock_priv *sk_priv = priv;

	spin_lock_init(&sk_priv->flt_lock);
}

static void mlxdevm_nl_sock_priv_destroy(void *priv)
{
	struct mlxdevm_nl_sock_priv *sk_priv = priv;
	struct mlxdevm_obj_desc *flt;

	flt = rcu_dereference_protected(sk_priv->flt, true);
	kfree_rcu(flt, rcu);
}
#ifdef HAVE_BLOCKED_DEVLINK_CODE

int devlink_nl_notify_filter_set_doit(struct sk_buff *skb,
				      struct genl_info *info)
{
	struct devlink_nl_sock_priv *sk_priv;
	struct nlattr **attrs = info->attrs;
	struct devlink_obj_desc *flt;
	size_t data_offset = 0;
	size_t data_size = 0;
	char *pos;

	if (attrs[DEVLINK_ATTR_BUS_NAME])
		data_size = size_add(data_size,
				     nla_len(attrs[DEVLINK_ATTR_BUS_NAME]) + 1);
	if (attrs[DEVLINK_ATTR_DEV_NAME])
		data_size = size_add(data_size,
				     nla_len(attrs[DEVLINK_ATTR_DEV_NAME]) + 1);

	flt = kzalloc(size_add(sizeof(*flt), data_size), GFP_KERNEL);
	if (!flt)
		return -ENOMEM;

	pos = (char *) flt->data;
	if (attrs[DEVLINK_ATTR_BUS_NAME]) {
		data_offset += nla_strscpy(pos,
					   attrs[DEVLINK_ATTR_BUS_NAME],
					   data_size) + 1;
		flt->bus_name = pos;
		pos += data_offset;
	}
	if (attrs[DEVLINK_ATTR_DEV_NAME]) {
		nla_strscpy(pos, attrs[DEVLINK_ATTR_DEV_NAME],
			    data_size - data_offset);
		flt->dev_name = pos;
	}

	if (attrs[DEVLINK_ATTR_PORT_INDEX]) {
		flt->port_index = nla_get_u32(attrs[DEVLINK_ATTR_PORT_INDEX]);
		flt->port_index_valid = true;
	}

	/* Don't attach empty filter. */
	if (!flt->bus_name && !flt->dev_name && !flt->port_index_valid) {
		kfree(flt);
		flt = NULL;
	}

	sk_priv = genl_sk_priv_get(&devlink_nl_family, NETLINK_CB(skb).sk);
	if (IS_ERR(sk_priv)) {
		kfree(flt);
		return PTR_ERR(sk_priv);
	}
	spin_lock(&sk_priv->flt_lock);
	flt = rcu_replace_pointer(sk_priv->flt, flt,
				  lockdep_is_held(&sk_priv->flt_lock));
	spin_unlock(&sk_priv->flt_lock);
	kfree_rcu(flt, rcu);
	return 0;
}
#endif

static bool mlxdevm_obj_desc_match(const struct mlxdevm_obj_desc *desc,
				   const struct mlxdevm_obj_desc *flt)
{
	if (desc->bus_name && flt->bus_name &&
	    strcmp(desc->bus_name, flt->bus_name))
		return false;
	if (desc->dev_name && flt->dev_name &&
	    strcmp(desc->dev_name, flt->dev_name))
		return false;
	if (desc->port_index_valid && flt->port_index_valid &&
	    desc->port_index != flt->port_index)
		return false;
	return true;
}

/**
 * __genl_sk_priv_get - Get family private pointer for socket, if exists
 *
 * @family: family
 * @sk: socket
 *
 * Lookup a private memory for a Generic netlink family and specified socket.
 *
 * Caller should make sure this is called in RCU read locked section.
 *
 * Return: valid pointer on success, otherwise negative error value
 * encoded by ERR_PTR(), NULL in case priv does not exist.
 */
static void *mlxdevm__genl_sk_priv_get(struct genl_family *family, struct sock *sk)
{
	if (WARN_ON_ONCE(!family->sock_privs))
		return ERR_PTR(-EINVAL);
	return xa_load(family->sock_privs, (unsigned long) sk);
}

int mlxdevm_nl_notify_filter(struct sock *dsk, struct sk_buff *skb, void *data)
{
	struct mlxdevm_obj_desc *desc = data;
	struct mlxdevm_nl_sock_priv *sk_priv;
	struct mlxdevm_obj_desc *flt;
	int ret = 0;

	rcu_read_lock();
	sk_priv = mlxdevm__genl_sk_priv_get(&mlxdevm_nl_family, dsk);
	if (!IS_ERR_OR_NULL(sk_priv)) {
		flt = rcu_dereference(sk_priv->flt);
		if (flt)
			ret = !mlxdevm_obj_desc_match(desc, flt);
	}
	rcu_read_unlock();
	return ret;
}

int mlxdevm_nl_put_nested_handle(struct sk_buff *msg, struct net *net,
				 struct mlxdevm *mlxdevm, int attrtype)
{
	struct nlattr *nested_attr;
	struct net *devl_net;

	nested_attr = nla_nest_start(msg, attrtype);
	if (!nested_attr)
		return -EMSGSIZE;
	if (mlxdevm_nl_put_handle(msg, mlxdevm))
		goto nla_put_failure;

	rcu_read_lock();
	devl_net = read_pnet_rcu(&mlxdevm->_net);
	if (!net_eq(net, devl_net)) {
		int id = peernet2id_alloc(net, devl_net, GFP_ATOMIC);

		rcu_read_unlock();
		if (nla_put_s32(msg, MLXDEVM_ATTR_NETNS_ID, id))
			return -EMSGSIZE;
	} else {
		rcu_read_unlock();
	}

	nla_nest_end(msg, nested_attr);
	return 0;

nla_put_failure:
	nla_nest_cancel(msg, nested_attr);
	return -EMSGSIZE;
}

int mlxdevm_nl_msg_reply_and_new(struct sk_buff **msg, struct genl_info *info)
{
	int err;

	if (*msg) {
		err = genlmsg_reply(*msg, info);
		if (err)
			return err;
	}
	*msg = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!*msg)
		return -ENOMEM;
	return 0;
}

struct mlxdevm *
mlxdevm_get_from_attrs_lock(struct net *net, struct nlattr **attrs,
			    bool dev_lock)
{
	struct mlxdevm *mlxdevm;
	struct devlink *devlink;
	unsigned long index;
	char *busname;
	char *devname;

	if (!attrs[MLXDEVM_ATTR_BUS_NAME] || !attrs[MLXDEVM_ATTR_DEV_NAME])
		return ERR_PTR(-EINVAL);

	busname = nla_data(attrs[MLXDEVM_ATTR_BUS_NAME]);
	devname = nla_data(attrs[MLXDEVM_ATTR_DEV_NAME]);

	mlxdevms_xa_for_each_registered_get(net, index, mlxdevm) {
		if (strcmp(mlxdevm->dev->bus->name, busname) == 0 &&
		    strcmp(dev_name(mlxdevm->dev), devname) == 0) {
			devlink = mlxdevm->devlink;
			if (devlink)
				devl_lock(devlink);
			devm_dev_lock(mlxdevm, dev_lock);
			mlxdevm->mlxdevm_flow = true;
			if (devm_is_registered(mlxdevm))
				return mlxdevm;
			mlxdevm->mlxdevm_flow = false;
			devm_dev_unlock(mlxdevm, dev_lock);
			if (devlink)
				devl_unlock(devlink);
		}
		mlxdevm_put(mlxdevm);
	}

	return ERR_PTR(-ENODEV);
}

static int __mlxdevm_nl_pre_doit(struct sk_buff *skb, struct genl_info *info,
				 u8 flags)
{
	bool dev_lock = flags & MLXDEVM_NL_FLAG_NEED_DEV_LOCK;
	struct mlxdevm_port *mlxdevm_port;
	struct devlink *devlink;
	struct mlxdevm *mlxdevm;
	int err;

	mlxdevm = mlxdevm_get_from_attrs_lock(genl_info_net(info), info->attrs,
					      dev_lock);
	if (IS_ERR(mlxdevm))
		return PTR_ERR(mlxdevm);

	info->user_ptr[0] = mlxdevm;
	if (flags & MLXDEVM_NL_FLAG_NEED_PORT) {
		mlxdevm_port = mlxdevm_port_get_from_info(mlxdevm, info);
		if (IS_ERR(mlxdevm_port)) {
			err = PTR_ERR(mlxdevm_port);
			goto unlock;
		}
		info->user_ptr[1] = mlxdevm_port;
	} else if (flags & MLXDEVM_NL_FLAG_NEED_DEVLINK_OR_PORT) {
		mlxdevm_port = mlxdevm_port_get_from_info(mlxdevm, info);
		if (!IS_ERR(mlxdevm_port))
			info->user_ptr[1] = mlxdevm_port;
	}
	return 0;

unlock:
	devm_dev_unlock(mlxdevm, dev_lock);
	devlink = mlxdevm->devlink;
	if (devlink)
		devl_unlock(devlink);
	mlxdevm_put(mlxdevm);
	return err;
}

int mlxdevm_nl_pre_doit(const struct genl_split_ops *ops,
			struct sk_buff *skb, struct genl_info *info)
{
	return __mlxdevm_nl_pre_doit(skb, info, 0);
}

int mlxdevm_nl_pre_doit_port(const struct genl_split_ops *ops,
			     struct sk_buff *skb, struct genl_info *info)
{
	return __mlxdevm_nl_pre_doit(skb, info, MLXDEVM_NL_FLAG_NEED_PORT);
}

int mlxdevm_nl_pre_doit_dev_lock(const struct genl_split_ops *ops,
				 struct sk_buff *skb, struct genl_info *info)
{
	return __mlxdevm_nl_pre_doit(skb, info, MLXDEVM_NL_FLAG_NEED_DEV_LOCK);
}
#ifdef HAVE_BLOCKED_DEVLINK_CODE

int devlink_nl_pre_doit_port_optional(const struct genl_split_ops *ops,
				      struct sk_buff *skb,
				      struct genl_info *info)
{
	return __devlink_nl_pre_doit(skb, info, DEVLINK_NL_FLAG_NEED_DEVLINK_OR_PORT);
}
#endif

static void __mlxdevm_nl_post_doit(struct sk_buff *skb, struct genl_info *info,
				   u8 flags)
{
	bool dev_lock = flags & MLXDEVM_NL_FLAG_NEED_DEV_LOCK;
	struct mlxdevm *mlxdevm;
	struct devlink *devlink;

	mlxdevm = info->user_ptr[0];
	mlxdevm->mlxdevm_flow = false;
	devm_dev_unlock(mlxdevm, dev_lock);
	devlink = mlxdevm->devlink;
	if (devlink)
		devl_unlock(devlink);
	mlxdevm_put(mlxdevm);
}

void mlxdevm_nl_post_doit(const struct genl_split_ops *ops,
			  struct sk_buff *skb, struct genl_info *info)
{
	__mlxdevm_nl_post_doit(skb, info, 0);
}

void
mlxdevm_nl_post_doit_dev_lock(const struct genl_split_ops *ops,
			      struct sk_buff *skb, struct genl_info *info)
{
	__mlxdevm_nl_post_doit(skb, info, MLXDEVM_NL_FLAG_NEED_DEV_LOCK);
}

static int mlxdevm_nl_inst_single_dumpit(struct sk_buff *msg,
					 struct netlink_callback *cb, int flags,
					 mlxdevm_nl_dump_one_func_t *dump_one,
					 struct nlattr **attrs)
{
	struct mlxdevm *mlxdevm;
	struct devlink *devlink;
	int err;

	mlxdevm = mlxdevm_get_from_attrs_lock(sock_net(msg->sk), attrs, false);
	if (IS_ERR(mlxdevm))
		return PTR_ERR(mlxdevm);
	err = dump_one(msg, mlxdevm, cb, flags | NLM_F_DUMP_FILTERED);

	devm_unlock(mlxdevm);
	devlink = mlxdevm->devlink;
	if (devlink)
		devl_unlock(devlink);
	mlxdevm_put(mlxdevm);

	if (err != -EMSGSIZE)
		return err;
	return msg->len;
}

static int mlxdevm_nl_inst_iter_dumpit(struct sk_buff *msg,
				       struct netlink_callback *cb, int flags,
				       mlxdevm_nl_dump_one_func_t *dump_one)
{
	struct mlxdevm_nl_dump_state *state = mlxdevm_dump_state(cb);
	struct mlxdevm *mlxdevm;
	struct devlink *devlink;
	int err = 0;

	while ((mlxdevm = mlxdevms_xa_find_get(sock_net(msg->sk),
					       &state->instance))) {
		devlink = mlxdevm->devlink;
		if (devlink)
			devl_lock(devlink);
		devm_lock(mlxdevm);

		if (devm_is_registered(mlxdevm))
			err = dump_one(msg, mlxdevm, cb, flags);
		else
			err = 0;

		devm_unlock(mlxdevm);
		if (devlink)
			devl_unlock(devlink);
		mlxdevm_put(mlxdevm);

		if (err)
			break;

		state->instance++;

		/* restart sub-object walk for the next instance */
		state->idx = 0;
	}

	if (err != -EMSGSIZE)
		return err;
	return msg->len;
}

int mlxdevm_nl_dumpit(struct sk_buff *msg, struct netlink_callback *cb,
		      mlxdevm_nl_dump_one_func_t *dump_one)
{
	const struct genl_info *info = genl_info_dump(cb);
	struct nlattr **attrs = info->attrs;
	int flags = NLM_F_MULTI;

	if (attrs &&
	    (attrs[MLXDEVM_ATTR_BUS_NAME] || attrs[MLXDEVM_ATTR_DEV_NAME]))
		return mlxdevm_nl_inst_single_dumpit(msg, cb, flags, dump_one,
						     attrs);
	else
		return mlxdevm_nl_inst_iter_dumpit(msg, cb, flags, dump_one);
}

struct genl_family mlxdevm_nl_family  = {
	.name		= MLXDEVM_GENL_NAME,
	.version	= MLXDEVM_GENL_VERSION,
	.netnsok	= true,
	.parallel_ops	= true,
	.module		= THIS_MODULE,
	.split_ops	= mlxdevm_nl_ops,
	.n_split_ops	= ARRAY_SIZE(mlxdevm_nl_ops),
	.resv_start_op	= MLXDEVM_CMD_SELFTESTS_RUN + 1,
	.mcgrps		= mlxdevm_nl_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(mlxdevm_nl_mcgrps),
	.sock_priv_size		= sizeof(struct mlxdevm_nl_sock_priv),
	.sock_priv_init		= mlxdevm_nl_sock_priv_init,
	.sock_priv_destroy	= mlxdevm_nl_sock_priv_destroy,
};
