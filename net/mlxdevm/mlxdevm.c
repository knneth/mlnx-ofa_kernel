// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021 Mellanox Technologies Ltd */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/genetlink.h>
#include <linux/etherdevice.h>

#include <net/mlxdevm.h>
#include <uapi/mlxdevm/mlxdevm_netlink.h>

#define DRV_NAME	"mlxdevm"
#define PFX		DRV_NAME ": "
#define DRV_VERSION	"1.0.0"
#define DRV_RELDATE	"February 25, 2021"

MODULE_AUTHOR("Parav Pandit");
MODULE_DESCRIPTION("mlxdevm kernel module");
MODULE_INFO(supported, "external");
MODULE_LICENSE("Dual BSD/GPL");
#ifdef RETPOLINE_MLNX
MODULE_INFO(retpoline, "Y");
#endif
MODULE_VERSION(DRV_VERSION);

static DEFINE_MUTEX(mlxdevm_mutex);
static LIST_HEAD(dev_head);
static struct genl_family mlxdevm_nl_family;

static const struct nla_policy mlxdevm_function_nl_policy[MLXDEVM_PORT_FUNCTION_ATTR_MAX + 1] = {
	[MLXDEVM_PORT_FUNCTION_ATTR_HW_ADDR] = { .type = NLA_BINARY },
	[MLXDEVM_PORT_FN_ATTR_STATE] = { .type = NLA_U8 },
	[MLXDEVM_PORT_FN_ATTR_EXT_CAP_ROCE] = { .type = NLA_U8 },
	[MLXDEVM_PORT_FN_ATTR_EXT_CAP_UC_LIST] = { .type = NLA_U32 },
};

static int mlxdevm_nl_dev_handle_fill(struct sk_buff *msg,
				      const struct mlxdevm *dev)
{
	if (nla_put_string(msg, MLXDEVM_ATTR_DEV_BUS_NAME, dev->device->bus->name))
		return -EMSGSIZE;
	if (nla_put_string(msg, MLXDEVM_ATTR_DEV_NAME, dev_name(dev->device)))
		return -EMSGSIZE;
	return 0;
}

static bool dev_handle_match(const struct mlxdevm *dev,
			     const char *busname, const char *devname)
{
	if ((strcmp(dev->device->bus->name, busname) == 0) &&
	    (strcmp(dev_name(dev->device), devname) == 0))
		return true;

	return false;
}

static struct mlxdevm *mlxdevm_dev_get_from_attr(struct nlattr **attrs)
{
	struct mlxdevm *dev;
	const char *busname;
	const char *devname;

	if (!attrs[MLXDEVM_ATTR_DEV_BUS_NAME] || !attrs[MLXDEVM_ATTR_DEV_NAME])
		return ERR_PTR(-EINVAL);

	devname = nla_data(attrs[MLXDEVM_ATTR_DEV_NAME]);
	busname = nla_data(attrs[MLXDEVM_ATTR_DEV_BUS_NAME]);

	list_for_each_entry(dev, &dev_head, list) {
		if (dev_handle_match(dev, busname, devname))
			return dev;
	}
	return ERR_PTR(-ENODEV);
}

/**
 * mlxdevm_register - register a device management device
 *
 * @dev: Pointer to mlxdevm device
 * mlxdevm_register() register a device management device which supports
 * various device management functionalities.
 */
int mlxdevm_register(struct mlxdevm *dev)
{
	if (!dev->device || !dev->device->bus)
		return -EINVAL;

	INIT_LIST_HEAD(&dev->list);
	INIT_LIST_HEAD(&dev->port_list);
	INIT_LIST_HEAD(&dev->param_list);
	INIT_LIST_HEAD(&dev->rate_group_list);

	init_rwsem(&dev->port_list_rwsem);
	init_rwsem(&dev->rate_group_rwsem);
	mutex_init(&dev->lock);
	mutex_lock(&mlxdevm_mutex);
	list_add_tail(&dev->list, &dev_head);
	mutex_unlock(&mlxdevm_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(mlxdevm_register);

void mlxdevm_unregister(struct mlxdevm *dev)
{
	mutex_lock(&mlxdevm_mutex);
	list_del(&dev->list);
	mutex_unlock(&mlxdevm_mutex);
	mutex_destroy(&dev->lock);
	WARN_ON(!list_empty(&dev->rate_group_list));
	WARN_ON(!list_empty(&dev->port_list));
	WARN_ON(!list_empty(&dev->param_list));
}
EXPORT_SYMBOL_GPL(mlxdevm_unregister);

static int mlxdevm_param_driver_verify(const struct mlxdevm_param *param)
{
	return 0;
}

static int mlxdevm_param_verify(const struct mlxdevm_param *param)
{
	if (!param || !param->name || !param->supported_cmodes)
		return -EINVAL;
	return mlxdevm_param_driver_verify(param);
}

static struct mlxdevm_param_item *
mlxdevm_param_find_by_name(struct list_head *param_list,
			   const char *param_name)
{
	struct mlxdevm_param_item *param_item;

	list_for_each_entry(param_item, param_list, list)
		if (!strcmp(param_item->param->name, param_name))
			return param_item;
	return NULL;
}

static struct mlxdevm_param_item *
mlxdevm_param_find_by_id(struct list_head *param_list, u32 param_id)
{
	struct mlxdevm_param_item *param_item;

	list_for_each_entry(param_item, param_list, list)
		if (param_item->param->id == param_id)
			return param_item;
	return NULL;
}

static bool
mlxdevm_param_cmode_is_supported(const struct mlxdevm_param *param,
				 enum mlxdevm_param_cmode cmode)
{
	return test_bit(cmode, &param->supported_cmodes);
}

static int mlxdevm_param_get(struct mlxdevm *devm,
			     const struct mlxdevm_param *param,
			     struct mlxdevm_param_gset_ctx *ctx)
{
	if (!param->get)
		return -EOPNOTSUPP;
	return param->get(devm, param->id, ctx);
}

static int mlxdevm_param_set(struct mlxdevm *devm,
			     const struct mlxdevm_param *param,
			     struct mlxdevm_param_gset_ctx *ctx)
{
	if (!param->set)
		return -EOPNOTSUPP;
	return param->set(devm, param->id, ctx);
}

static int
mlxdevm_param_type_to_nla_type(enum mlxdevm_param_type param_type)
{
	switch (param_type) {
	case MLXDEVM_PARAM_TYPE_U8:
		return NLA_U8;
	case MLXDEVM_PARAM_TYPE_U16:
		return NLA_U16;
	case MLXDEVM_PARAM_TYPE_U32:
		return NLA_U32;
	case MLXDEVM_PARAM_TYPE_STRING:
		return NLA_STRING;
	case MLXDEVM_PARAM_TYPE_BOOL:
		return NLA_FLAG;
	case MLXDEVM_PARAM_TYPE_ARRAY_U16:
		return NLA_NESTED;
	default:
		return -EINVAL;
	}
}

static int
mlxdevm_nl_param_value_fill_one(struct sk_buff *msg,
				enum mlxdevm_param_type type,
				enum mlxdevm_param_cmode cmode,
				union mlxdevm_param_value val)
{
	struct nlattr *param_value_attr;

	param_value_attr = nla_nest_start_noflag(msg,
						 MLXDEVM_ATTR_PARAM_VALUE);
	if (!param_value_attr)
		goto nla_put_failure;

	if (nla_put_u8(msg, MLXDEVM_ATTR_PARAM_VALUE_CMODE, cmode))
		goto value_nest_cancel;

	switch (type) {
	case MLXDEVM_PARAM_TYPE_U8:
		if (nla_put_u8(msg, MLXDEVM_ATTR_PARAM_VALUE_DATA, val.vu8))
			goto value_nest_cancel;
		break;
	case MLXDEVM_PARAM_TYPE_U16:
		if (nla_put_u16(msg, MLXDEVM_ATTR_PARAM_VALUE_DATA, val.vu16))
			goto value_nest_cancel;
		break;
	case MLXDEVM_PARAM_TYPE_U32:
		if (nla_put_u32(msg, MLXDEVM_ATTR_PARAM_VALUE_DATA, val.vu32))
			goto value_nest_cancel;
		break;
	case MLXDEVM_PARAM_TYPE_STRING:
		if (nla_put_string(msg, MLXDEVM_ATTR_PARAM_VALUE_DATA,
				   val.vstr))
			goto value_nest_cancel;
		break;
	case MLXDEVM_PARAM_TYPE_BOOL:
		if (val.vbool &&
		    nla_put_flag(msg, MLXDEVM_ATTR_PARAM_VALUE_DATA))
			goto value_nest_cancel;
		break;
	case MLXDEVM_PARAM_TYPE_ARRAY_U16:
		if (nla_put_u8(msg, MLXDEVM_ATTR_EXT_PARAM_ARRAY_TYPE,
			       sizeof(u16)))
			goto value_nest_cancel;
		if (nla_put(msg, MLXDEVM_ATTR_PARAM_VALUE_DATA,
			    val.vu16arr.array_len * sizeof(u16),
			    val.vu16arr.data))
			goto value_nest_cancel;
		break;
	}

	nla_nest_end(msg, param_value_attr);
	return 0;

value_nest_cancel:
	nla_nest_cancel(msg, param_value_attr);
nla_put_failure:
	return -EMSGSIZE;
}

static int mlxdevm_nl_param_fill(struct sk_buff *msg, struct mlxdevm *devm,
				 unsigned int port_index,
				 struct mlxdevm_param_item *param_item,
				 enum mlxdevm_command cmd,
				 u32 portid, u32 seq, int flags)
{
	union mlxdevm_param_value param_value[MLXDEVM_PARAM_CMODE_MAX + 1];
	bool param_value_set[MLXDEVM_PARAM_CMODE_MAX + 1] = {};
	const struct mlxdevm_param *param = param_item->param;
	struct mlxdevm_param_gset_ctx ctx;
	struct nlattr *param_values_list;
	struct nlattr *param_attr;
	int nla_type;
	void *hdr;
	int err;
	int i;

	/* Get value from driver part to driverinit configuration mode */
	for (i = 0; i <= MLXDEVM_PARAM_CMODE_MAX; i++) {
		if (!mlxdevm_param_cmode_is_supported(param, i))
			continue;
		if (i == MLXDEVM_PARAM_CMODE_DRIVERINIT) {
			if (!param_item->driverinit_value_valid)
				return -EOPNOTSUPP;
			param_value[i] = param_item->driverinit_value;
		} else {
			if (!param_item->published)
				continue;
			ctx.cmode = i;
			err = mlxdevm_param_get(devm, param, &ctx);
			if (err)
				return err;
			param_value[i] = ctx.val;
		}
		param_value_set[i] = true;
	}

	hdr = genlmsg_put(msg, portid, seq, &mlxdevm_nl_family, flags, cmd);
	if (!hdr)
		return -EMSGSIZE;

	if (mlxdevm_nl_dev_handle_fill(msg, devm))
		goto genlmsg_cancel;

	param_attr = nla_nest_start_noflag(msg, MLXDEVM_ATTR_PARAM);
	if (!param_attr)
		goto genlmsg_cancel;
	if (nla_put_string(msg, MLXDEVM_ATTR_PARAM_NAME, param->name))
		goto param_nest_cancel;
	if (param->generic && nla_put_flag(msg, MLXDEVM_ATTR_PARAM_GENERIC))
		goto param_nest_cancel;

	nla_type = mlxdevm_param_type_to_nla_type(param->type);
	if (nla_type < 0)
		goto param_nest_cancel;
	if (nla_put_u8(msg, MLXDEVM_ATTR_PARAM_TYPE, nla_type))
		goto param_nest_cancel;

	param_values_list = nla_nest_start_noflag(msg,
						  MLXDEVM_ATTR_PARAM_VALUES_LIST);
	if (!param_values_list)
		goto param_nest_cancel;

	for (i = 0; i <= MLXDEVM_PARAM_CMODE_MAX; i++) {
		if (!param_value_set[i])
			continue;
		err = mlxdevm_nl_param_value_fill_one(msg, param->type,
						      i, param_value[i]);
		if (err)
			goto values_list_nest_cancel;
	}

	nla_nest_end(msg, param_values_list);
	nla_nest_end(msg, param_attr);
	genlmsg_end(msg, hdr);
	return 0;

values_list_nest_cancel:
	nla_nest_end(msg, param_values_list);
param_nest_cancel:
	nla_nest_cancel(msg, param_attr);
genlmsg_cancel:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

static void mlxdevm_param_notify(struct mlxdevm *devm,
				 unsigned int port_index,
				 struct mlxdevm_param_item *param_item,
				 enum mlxdevm_command cmd)
{
}

static int mlxdevm_nl_cmd_param_get_dumpit(struct sk_buff *msg,
					   struct netlink_callback *cb)
{
	struct mlxdevm_param_item *param_item;
	struct mlxdevm *devm;
	int start = cb->args[0];
	int idx = 0;
	int err = 0;

	mutex_lock(&mlxdevm_mutex);
	list_for_each_entry(devm, &dev_head, list) {
		mutex_lock(&devm->lock);
		list_for_each_entry(param_item, &devm->param_list, list) {
			if (idx < start) {
				idx++;
				continue;
			}
			err = mlxdevm_nl_param_fill(msg, devm, 0, param_item,
						    MLXDEVM_CMD_PARAM_GET,
						    NETLINK_CB(cb->skb).portid,
						    cb->nlh->nlmsg_seq,
						    NLM_F_MULTI);
			if (err == -EOPNOTSUPP) {
				err = 0;
			} else if (err) {
				mutex_unlock(&devm->lock);
				goto out;
			}
			idx++;
		}
		mutex_unlock(&devm->lock);
	}
out:
	mutex_unlock(&mlxdevm_mutex);

	if (err != -EMSGSIZE)
		return err;

	cb->args[0] = idx;
	return msg->len;
}

static int
mlxdevm_param_type_get_from_info(struct genl_info *info,
				 enum mlxdevm_param_type *param_type)
{
	if (!info->attrs[MLXDEVM_ATTR_PARAM_TYPE])
		return -EINVAL;

	switch (nla_get_u8(info->attrs[MLXDEVM_ATTR_PARAM_TYPE])) {
	case NLA_U8:
		*param_type = MLXDEVM_PARAM_TYPE_U8;
		break;
	case NLA_U16:
		*param_type = MLXDEVM_PARAM_TYPE_U16;
		break;
	case NLA_U32:
		*param_type = MLXDEVM_PARAM_TYPE_U32;
		break;
	case NLA_STRING:
		*param_type = MLXDEVM_PARAM_TYPE_STRING;
		break;
	case NLA_FLAG:
		*param_type = MLXDEVM_PARAM_TYPE_BOOL;
		break;
	case NLA_NESTED:
		if (!info->attrs[MLXDEVM_ATTR_EXT_PARAM_ARRAY_TYPE])
			return -EINVAL;
		switch (nla_get_u8(info->attrs[MLXDEVM_ATTR_EXT_PARAM_ARRAY_TYPE])) {
		case sizeof(u16):
			*param_type = MLXDEVM_PARAM_TYPE_ARRAY_U16;
			break;
		default:
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int
mlxdevm_param_value_get_from_info(const struct mlxdevm_param *param,
				  struct genl_info *info,
				  union mlxdevm_param_value *value)
{
	struct nlattr *param_data;
	int len;

	param_data = info->attrs[MLXDEVM_ATTR_PARAM_VALUE_DATA];

	if (param->type != MLXDEVM_PARAM_TYPE_BOOL && !param_data)
		return -EINVAL;

	switch (param->type) {
	case MLXDEVM_PARAM_TYPE_U8:
		if (nla_len(param_data) != sizeof(u8))
			return -EINVAL;
		value->vu8 = nla_get_u8(param_data);
		break;
	case MLXDEVM_PARAM_TYPE_U16:
		if (nla_len(param_data) != sizeof(u16))
			return -EINVAL;
		value->vu16 = nla_get_u16(param_data);
		break;
	case MLXDEVM_PARAM_TYPE_U32:
		if (nla_len(param_data) != sizeof(u32))
			return -EINVAL;
		value->vu32 = nla_get_u32(param_data);
		break;
	case MLXDEVM_PARAM_TYPE_STRING:
		len = strnlen(nla_data(param_data), nla_len(param_data));
		if (len == nla_len(param_data) ||
		    len >= __MLXDEVM_PARAM_MAX_STRING_VALUE)
			return -EINVAL;
		strcpy(value->vstr, nla_data(param_data));
		break;
	case MLXDEVM_PARAM_TYPE_BOOL:
		if (param_data && nla_len(param_data))
			return -EINVAL;
		value->vbool = nla_get_flag(param_data);
		break;
	case MLXDEVM_PARAM_TYPE_ARRAY_U16:
		if (nla_len(param_data) > sizeof(value->vu16arr.data))
			return -EINVAL;
		if (nla_len(param_data) % sizeof(u16))
			return -EINVAL;
		nla_memcpy(value->vu16arr.data, param_data,
			   sizeof(value->vu16arr.data));
		value->vu16arr.array_len = nla_len(param_data) / sizeof(u16);
		break;
	}
	return 0;
}

static struct mlxdevm_param_item *
mlxdevm_param_get_from_info(struct list_head *param_list,
			    struct genl_info *info)
{
	char *param_name;

	if (!info->attrs[MLXDEVM_ATTR_PARAM_NAME])
		return NULL;

	param_name = nla_data(info->attrs[MLXDEVM_ATTR_PARAM_NAME]);
	return mlxdevm_param_find_by_name(param_list, param_name);
}

static int mlxdevm_nl_cmd_param_get_doit(struct sk_buff *skb,
					 struct genl_info *info)
{
	struct mlxdevm_param_item *param_item;
	struct mlxdevm *devm;
	struct sk_buff *msg;
	int err;

	mutex_lock(&mlxdevm_mutex);
	devm = mlxdevm_dev_get_from_attr(info->attrs);
	if (IS_ERR(devm)) {
		mutex_unlock(&mlxdevm_mutex);
		NL_SET_ERR_MSG_MOD(info->extack, "Fail to find the specified mgmt device");
		return PTR_ERR(devm);
	}

	param_item = mlxdevm_param_get_from_info(&devm->param_list, info);
	if (!param_item) {
		err = -EINVAL;
		goto out;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg) {
		err = -ENOMEM;
		goto out;
	}

	err = mlxdevm_nl_param_fill(msg, devm, 0, param_item,
				    MLXDEVM_CMD_PARAM_GET,
				    info->snd_portid, info->snd_seq, 0);
	if (err) {
		nlmsg_free(msg);
		goto out;
	}
	mutex_unlock(&mlxdevm_mutex);

	return genlmsg_reply(msg, info);

out:
	mutex_unlock(&mlxdevm_mutex);
	return err;
}

static int __mlxdevm_nl_cmd_param_set_doit(struct mlxdevm *devm,
					   unsigned int port_index,
					   struct list_head *param_list,
					   struct genl_info *info,
					   enum mlxdevm_command cmd)
{
	struct mlxdevm_param_item *param_item;
	enum mlxdevm_param_type param_type;
	struct mlxdevm_param_gset_ctx ctx;
	const struct mlxdevm_param *param;
	union mlxdevm_param_value value;
	enum mlxdevm_param_cmode cmode;
	int err = 0;

	param_item = mlxdevm_param_get_from_info(param_list, info);
	if (!param_item)
		return -EINVAL;
	param = param_item->param;
	err = mlxdevm_param_type_get_from_info(info, &param_type);
	if (err)
		return err;
	if (param_type != param->type)
		return -EINVAL;
	err = mlxdevm_param_value_get_from_info(param, info, &value);
	if (err)
		return err;
	if (param->validate) {
		err = param->validate(devm, param->id, value, info->extack);
		if (err)
			return err;
	}

	if (!info->attrs[MLXDEVM_ATTR_PARAM_VALUE_CMODE])
		return -EINVAL;
	cmode = nla_get_u8(info->attrs[MLXDEVM_ATTR_PARAM_VALUE_CMODE]);
	if (!mlxdevm_param_cmode_is_supported(param, cmode))
		return -EOPNOTSUPP;

	if (cmode == MLXDEVM_PARAM_CMODE_DRIVERINIT) {
		if (param->type == MLXDEVM_PARAM_TYPE_STRING) {
			strcpy(param_item->driverinit_value.vstr, value.vstr);
		} else if (param->type == MLXDEVM_PARAM_TYPE_ARRAY_U16) {
			param_item->driverinit_value.vu16arr.array_len =
				value.vu16arr.array_len;
			memcpy(param_item->driverinit_value.vu16arr.data, value.vu16arr.data,
			       value.vu16arr.array_len * sizeof(u16));
		} else {
			param_item->driverinit_value = value;
		}
		param_item->driverinit_value_valid = true;
	} else {
		if (!param->set)
			return -EOPNOTSUPP;
		ctx.val = value;
		ctx.cmode = cmode;
		err = mlxdevm_param_set(devm, param, &ctx);
		if (err)
			return err;
	}

	mlxdevm_param_notify(devm, port_index, param_item, cmd);
	return 0;
}

static int mlxdevm_nl_cmd_param_set_doit(struct sk_buff *skb,
					 struct genl_info *info)
{
	struct mlxdevm *devm;
	int err;

	mutex_lock(&mlxdevm_mutex);
	devm = mlxdevm_dev_get_from_attr(info->attrs);
	err = __mlxdevm_nl_cmd_param_set_doit(devm, 0, &devm->param_list,
					      info, MLXDEVM_CMD_PARAM_NEW);
	mutex_unlock(&mlxdevm_mutex);
	return err;
}

static int mlxdevm_param_register_one(struct mlxdevm *devm,
				      unsigned int port_index,
				      struct list_head *param_list,
				      const struct mlxdevm_param *param,
				      enum mlxdevm_command cmd)
{
	struct mlxdevm_param_item *param_item;

	if (mlxdevm_param_find_by_name(param_list, param->name))
		return -EEXIST;

	if (param->supported_cmodes == BIT(MLXDEVM_PARAM_CMODE_DRIVERINIT))
		WARN_ON(param->get || param->set);
	else
		WARN_ON(!param->get || !param->set);

	param_item = kzalloc(sizeof(*param_item), GFP_KERNEL);
	if (!param_item)
		return -ENOMEM;
	param_item->param = param;

	list_add_tail(&param_item->list, param_list);
	mlxdevm_param_notify(devm, port_index, param_item, cmd);
	return 0;
}

static void mlxdevm_param_unregister_one(struct mlxdevm *devm,
					 unsigned int port_index,
					 struct list_head *param_list,
					 const struct mlxdevm_param *param,
					 enum mlxdevm_command cmd)
{
	struct mlxdevm_param_item *param_item;

	param_item = mlxdevm_param_find_by_name(param_list, param->name);
	WARN_ON(!param_item);
	mlxdevm_param_notify(devm, port_index, param_item, cmd);
	list_del(&param_item->list);
	kfree(param_item);
}

static int __mlxdevm_params_register(struct mlxdevm *devm,
				     unsigned int port_index,
				     struct list_head *param_list,
				     const struct mlxdevm_param *params,
				     size_t params_count,
				     enum mlxdevm_command reg_cmd,
				     enum mlxdevm_command unreg_cmd)
{
	const struct mlxdevm_param *param = params;
	int i;
	int err;

	mutex_lock(&devm->lock);
	for (i = 0; i < params_count; i++, param++) {
		err = mlxdevm_param_verify(param);
		if (err)
			goto rollback;

		err = mlxdevm_param_register_one(devm, port_index,
						 param_list, param, reg_cmd);
		if (err)
			goto rollback;
	}

	mutex_unlock(&devm->lock);
	return 0;

rollback:
	if (!i)
		goto unlock;
	for (param--; i > 0; i--, param--)
		mlxdevm_param_unregister_one(devm, port_index, param_list,
					     param, unreg_cmd);
unlock:
	mutex_unlock(&devm->lock);
	return err;
}

static void __mlxdevm_params_unregister(struct mlxdevm *devm,
					unsigned int port_index,
					struct list_head *param_list,
					const struct mlxdevm_param *params,
					size_t params_count,
					enum mlxdevm_command cmd)
{
	const struct mlxdevm_param *param = params;
	int i;

	mutex_lock(&devm->lock);
	for (i = 0; i < params_count; i++, param++)
		mlxdevm_param_unregister_one(devm, 0, param_list, param,
					     cmd);
	mutex_unlock(&devm->lock);
}

/**
 *	mlxdevm_params_register - register configuration parameters
 *
 *	@devm: devm device
 *	@params: configuration parameters array
 *	@params_count: number of parameters provided
 *
 *	Register the configuration parameters supported by the driver.
 */
int mlxdevm_params_register(struct mlxdevm *devm,
			    const struct mlxdevm_param *params,
			    size_t params_count)
{
	return __mlxdevm_params_register(devm, 0, &devm->param_list,
					 params, params_count,
					 MLXDEVM_CMD_PARAM_NEW,
					 MLXDEVM_CMD_PARAM_DEL);
}
EXPORT_SYMBOL_GPL(mlxdevm_params_register);

/**
 *	mlxdevm_params_unregister - unregister configuration parameters
 *	@devm: devm device
 *	@params: configuration parameters to unregister
 *	@params_count: number of parameters provided
 */
void mlxdevm_params_unregister(struct mlxdevm *devm,
			       const struct mlxdevm_param *params,
			       size_t params_count)
{
	return __mlxdevm_params_unregister(devm, 0, &devm->param_list,
					   params, params_count,
					   MLXDEVM_CMD_PARAM_DEL);
}
EXPORT_SYMBOL_GPL(mlxdevm_params_unregister);

/**
 *	mlxdevm_params_publish - publish configuration parameters
 *
 *	@devm: devm device
 *
 *	Publish previously registered configuration parameters.
 */
void mlxdevm_params_publish(struct mlxdevm *devm)
{
	struct mlxdevm_param_item *param_item;

	list_for_each_entry(param_item, &devm->param_list, list) {
		if (param_item->published)
			continue;
		param_item->published = true;
		mlxdevm_param_notify(devm, 0, param_item,
				     MLXDEVM_CMD_PARAM_NEW);
	}
}
EXPORT_SYMBOL_GPL(mlxdevm_params_publish);

/**
 * mlxdevm_params_unpublish - unpublish configuration parameters
 *
 * @devm: devm device
 *
 * Unpublish previously registered configuration parameters.
 */
void mlxdevm_params_unpublish(struct mlxdevm *devm)
{
	struct mlxdevm_param_item *param_item;

	list_for_each_entry(param_item, &devm->param_list, list) {
		if (!param_item->published)
			continue;
		param_item->published = false;
		mlxdevm_param_notify(devm, 0, param_item,
				     MLXDEVM_CMD_PARAM_DEL);
	}
}
EXPORT_SYMBOL_GPL(mlxdevm_params_unpublish);

static int
__mlxdevm_param_driverinit_value_get(struct list_head *param_list, u32 param_id,
				     union mlxdevm_param_value *init_val)
{
	struct mlxdevm_param_item *param_item;

	param_item = mlxdevm_param_find_by_id(param_list, param_id);
	if (!param_item)
		return -EINVAL;

	if (!param_item->driverinit_value_valid ||
	    !mlxdevm_param_cmode_is_supported(param_item->param,
					      MLXDEVM_PARAM_CMODE_DRIVERINIT))
		return -EOPNOTSUPP;

	if (param_item->param->type == MLXDEVM_PARAM_TYPE_STRING) {
		strcpy(init_val->vstr, param_item->driverinit_value.vstr);
	} else if (param_item->param->type == MLXDEVM_PARAM_TYPE_ARRAY_U16) {
		init_val->vu16arr.array_len =
			param_item->driverinit_value.vu16arr.array_len;
		memcpy(init_val->vu16arr.data, param_item->driverinit_value.vu16arr.data,
		       init_val->vu16arr.array_len * sizeof(u16));
	} else {
		*init_val = param_item->driverinit_value;
	}

	return 0;
}

static int
__mlxdevm_param_driverinit_value_set(struct mlxdevm *devm,
				     unsigned int port_index,
				     struct list_head *param_list, u32 param_id,
				     union mlxdevm_param_value init_val,
				     enum mlxdevm_command cmd)
{
	struct mlxdevm_param_item *param_item;

	param_item = mlxdevm_param_find_by_id(param_list, param_id);
	if (!param_item)
		return -EINVAL;

	if (!mlxdevm_param_cmode_is_supported(param_item->param,
					      MLXDEVM_PARAM_CMODE_DRIVERINIT))
		return -EOPNOTSUPP;

	if (param_item->param->type == MLXDEVM_PARAM_TYPE_STRING) {
		strcpy(param_item->driverinit_value.vstr, init_val.vstr);
	} else if (param_item->param->type == MLXDEVM_PARAM_TYPE_ARRAY_U16) {
		param_item->driverinit_value.vu16arr.array_len =
			init_val.vu16arr.array_len;
		memcpy(param_item->driverinit_value.vu16arr.data, init_val.vu16arr.data,
		       init_val.vu16arr.array_len * sizeof(u16));
	} else {
		param_item->driverinit_value = init_val;
	}
	param_item->driverinit_value_valid = true;

	mlxdevm_param_notify(devm, port_index, param_item, cmd);
	return 0;
}

/**
 * mlxdevm_param_driverinit_value_get - get configuration parameter
 * value for driver initializing
 *
 * @devm: devm device
 * @param_id: parameter ID
 * @init_val: value of parameter in driverinit configuration mode
 *
 * This function should be used by the driver to get driverinit
 * configuration for initialization after reload command.
 */
int mlxdevm_param_driverinit_value_get(struct mlxdevm *devm, u32 param_id,
				       union mlxdevm_param_value *init_val)
{
	return __mlxdevm_param_driverinit_value_get(&devm->param_list,
						     param_id, init_val);
}
EXPORT_SYMBOL_GPL(mlxdevm_param_driverinit_value_get);

/**
 * mlxdevm_param_driverinit_value_set - set value of configuration
 *					parameter for driverinit
 *					configuration mode
 *
 * @devm: devm device
 * @param_id: parameter ID
 * @init_val: value of parameter to set for driverinit configuration mode
 *
 * This function should be used by the driver to set driverinit
 * configuration mode default value.
 */
int mlxdevm_param_driverinit_value_set(struct mlxdevm *devm, u32 param_id,
				       union mlxdevm_param_value init_val)
{
	return __mlxdevm_param_driverinit_value_set(devm, 0,
						    &devm->param_list,
						    param_id, init_val,
						    MLXDEVM_CMD_PARAM_NEW);
}
EXPORT_SYMBOL_GPL(mlxdevm_param_driverinit_value_set);

static struct mlxdevm_port *mlxdevm_port_get_by_index(struct mlxdevm *dev,
						      unsigned int port_index)
{
	struct mlxdevm_port *port;

	list_for_each_entry(port, &dev->port_list, list) {
		if (port->index == port_index)
			return port;
	}
	return NULL;
}

static bool mlxdevm_port_index_exists(struct mlxdevm *dev,
				      unsigned int port_index)
{
	return mlxdevm_port_get_by_index(dev, port_index);
}

static struct mlxdevm_port *mlxdevm_port_get_from_attrs(struct mlxdevm *dev,
							struct nlattr **attrs)
{
	if (attrs[MLXDEVM_ATTR_PORT_INDEX]) {
		u32 port_index = nla_get_u32(attrs[MLXDEVM_ATTR_PORT_INDEX]);
		struct mlxdevm_port *port;

		port = mlxdevm_port_get_by_index(dev, port_index);
		if (!port)
			return ERR_PTR(-ENODEV);
		return port;
	}
	return ERR_PTR(-EINVAL);
}

/**
 * mlxdevm_rate_group_register - Register a rate group
 * @dev: mlxdevm instance
 * @group: group to register
 *
 * mlxdevm_rate_group_register() registers a rate group. Caller must provide
 * a valid and unique group name.
 * Return: Returns 0 on success, error code otherwise.
 */
int mlxdevm_rate_group_register(struct mlxdevm *dev,
				struct mlxdevm_rate_group *group)
{
	struct mlxdevm_rate_group *cur;
	int err = 0;

	if (!group->name) {
		WARN_ON(1);
		return -EINVAL;
	}
	INIT_LIST_HEAD(&group->list);
	down_write(&dev->rate_group_rwsem);
	list_for_each_entry(cur, &dev->rate_group_list, list) {
		if (strcmp(cur->name, group->name) == 0) {
			err = -EEXIST;
			goto out;
		}
	}
	list_add_tail(&group->list, &dev->rate_group_list);
	/* Given group is unique, add it. */
out:
	up_write(&dev->rate_group_rwsem);
	return err;
}
EXPORT_SYMBOL_GPL(mlxdevm_rate_group_register);

/**
 * mlxdevm_rate_group_unregister - Unregister a previously registered rate group
 * @dev: mlxdevm instance
 * @group: group to unregister
 *
 * mlxdevm_rate_group_unregister() unregisters a rate group.
 */
void mlxdevm_rate_group_unregister(struct mlxdevm *dev,
				   struct mlxdevm_rate_group *group)
{
	down_write(&dev->rate_group_rwsem);
	list_del(&group->list);
	up_write(&dev->rate_group_rwsem);
}
EXPORT_SYMBOL_GPL(mlxdevm_rate_group_unregister);

/**
 * mlxdevm_port_register - Register mlxdevm port
 *
 * @dev: dev
 * @mlxdevm_port: mlxdevm port
 * @port_index: driver-specific numerical identifier of the port
 *
 * Register mlxdevm port with provided port index. User can use
 * any indexing, even hw-related one. mlxdevm_port structure
 * is convenient to be embedded inside user driver private structure.
 * Note that the caller should take care of zeroing the mlxdevm_port
 * structure.
 * Return: returns 0 on success or error code.
 */
int mlxdevm_port_register(struct mlxdevm *dev, struct mlxdevm_port *mlxdevm_port,
			  unsigned int port_index)
{
	if (mlxdevm_port_index_exists(dev, port_index))
		return -EEXIST;

	mlxdevm_port->index = port_index;
	spin_lock_init(&mlxdevm_port->type_lock);
	down_write(&dev->port_list_rwsem);
	list_add_tail(&mlxdevm_port->list, &dev->port_list);
	up_write(&dev->port_list_rwsem);
	return 0;
}
EXPORT_SYMBOL_GPL(mlxdevm_port_register);

/**
 * mlxdevm_port_unregister - Unregister mlxdevm port
 *
 * @dev: dev
 * @mlxdevm_port: mlxdevm port
 */
void mlxdevm_port_unregister(struct mlxdevm *dev, struct mlxdevm_port *mlxdevm_port)
{
	down_write(&dev->port_list_rwsem);
	list_del(&mlxdevm_port->list);
	up_write(&dev->port_list_rwsem);
}
EXPORT_SYMBOL_GPL(mlxdevm_port_unregister);

void mlxdevm_port_type_eth_set(struct mlxdevm_port *port, struct net_device *ndev)
{
	spin_lock_bh(&port->type_lock);
	port->type = MLXDEVM_PORT_TYPE_ETH;
	port->type_dev = ndev;
	spin_unlock_bh(&port->type_lock);
}
EXPORT_SYMBOL_GPL(mlxdevm_port_type_eth_set);

void mlxdevm_port_attr_set(struct mlxdevm_port *port, struct mlxdevm_port_attrs *attrs)
{
	port->attrs = *attrs;
}
EXPORT_SYMBOL_GPL(mlxdevm_port_attr_set);

static int mlxdevm_dev_fill(const struct mlxdevm *dev, struct sk_buff *msg,
			    u32 portid, u32 seq, int flags)
{
	void *hdr;
	int err;

	hdr = genlmsg_put(msg, portid, seq, &mlxdevm_nl_family, flags,
			  MLXDEVM_CMD_DEV_NEW);
	if (!hdr)
		return -EMSGSIZE;
	err = mlxdevm_nl_dev_handle_fill(msg, dev);
	if (err)
		goto msg_err;

	genlmsg_end(msg, hdr);
	return 0;

msg_err:
	genlmsg_cancel(msg, hdr);
	return err;
}

static int mlxdevm_nl_cmd_dev_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm *dev;
	struct sk_buff *msg;
	int err;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	mutex_lock(&mlxdevm_mutex);
	dev = mlxdevm_dev_get_from_attr(info->attrs);
	if (IS_ERR(dev)) {
		mutex_unlock(&mlxdevm_mutex);
		NL_SET_ERR_MSG_MOD(info->extack, "Fail to find the specified mgmt device");
		err = PTR_ERR(dev);
		goto out;
	}

	err = mlxdevm_dev_fill(dev, msg, info->snd_portid, info->snd_seq, 0);
	mutex_unlock(&mlxdevm_mutex);
	if (err)
		goto out;
	err = genlmsg_reply(msg, info);
	return err;

out:
	nlmsg_free(msg);
	return err;
}

static int
mlxdevm_nl_cmd_dev_get_dumpit(struct sk_buff *msg, struct netlink_callback *cb)
{
	struct mlxdevm *dev;
	int start = cb->args[0];
	int idx = 0;
	int err;

	mutex_lock(&mlxdevm_mutex);
	list_for_each_entry(dev, &dev_head, list) {
		if (idx < start) {
			idx++;
			continue;
		}
		err = mlxdevm_dev_fill(dev, msg, NETLINK_CB(cb->skb).portid,
				       cb->nlh->nlmsg_seq, NLM_F_MULTI);
		if (err)
			goto out;
		idx++;
	}
out:
	mutex_unlock(&mlxdevm_mutex);
	cb->args[0] = idx;
	return msg->len;
}

static int
mlxdevm_nl_port_attrs_put(struct sk_buff *msg, struct mlxdevm_port *port)
{
	struct mlxdevm_port_attrs *attrs = &port->attrs;

	if (nla_put_u16(msg, MLXDEVM_ATTR_PORT_FLAVOUR, attrs->flavour))
		return -EMSGSIZE;
	switch (port->attrs.flavour) {
	case MLXDEVM_PORT_FLAVOUR_PCI_SF:
		if (nla_put_u32(msg, MLXDEVM_ATTR_PORT_CONTROLLER_NUMBER,
				attrs->pci_sf.controller) ||
		    nla_put_u16(msg, MLXDEVM_ATTR_PORT_PCI_PF_NUMBER,
				attrs->pci_sf.pf) ||
		    nla_put_u32(msg, MLXDEVM_ATTR_PORT_PCI_SF_NUMBER,
				attrs->pci_sf.sf))
			return -EMSGSIZE;
		break;
	default:
		break;
	}
	return 0;
}

static int
mlxdevm_port_fn_hw_addr_fill(struct mlxdevm *dev, const struct mlxdevm_ops *ops,
			     struct mlxdevm_port *port, struct sk_buff *msg,
			     struct netlink_ext_ack *extack, bool *msg_updated)
{
	u8 hw_addr[MAX_ADDR_LEN];
	int hw_addr_len;
	int err;

	if (!ops->port_fn_hw_addr_get)
		return 0;

	err = ops->port_fn_hw_addr_get(dev, port, hw_addr, &hw_addr_len, extack);
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

static int
mlxdevm_port_fn_state_fill(struct mlxdevm *dev,
			   const struct mlxdevm_ops *ops,
			   struct mlxdevm_port *port, struct sk_buff *msg,
			   struct netlink_ext_ack *extack,
			   bool *msg_updated)
{
	enum mlxdevm_port_fn_opstate opstate;
	enum mlxdevm_port_fn_state state;
	int err;

	if (!ops->port_fn_state_get)
		return 0;

	err = ops->port_fn_state_get(dev, port, &state, &opstate, extack);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}
	if (!mlxdevm_port_fn_state_valid(state)) {
		WARN_ON_ONCE(1);
		NL_SET_ERR_MSG_MOD(extack, "Invalid state read from driver");
		return -EINVAL;
	}
	if (!mlxdevm_port_fn_opstate_valid(opstate)) {
		WARN_ON_ONCE(1);
		NL_SET_ERR_MSG_MOD(extack,
				   "Invalid operational state read from driver");
		return -EINVAL;
	}
	if (nla_put_u8(msg, MLXDEVM_PORT_FN_ATTR_STATE, state) ||
	    nla_put_u8(msg, MLXDEVM_PORT_FN_ATTR_OPSTATE, opstate))
		return -EMSGSIZE;
	*msg_updated = true;
	return 0;
}

static bool
mlxdevm_port_fn_cap_roce_valid(enum mlxdevm_port_fn_cap_roce state)
{
	return state == MLXDEVM_PORT_FN_CAP_ROCE_ENABLE ||
	       state == MLXDEVM_PORT_FN_CAP_ROCE_DISABLE;
}

static int
mlxdevm_port_fn_cap_fill(struct mlxdevm *dev,
			 const struct mlxdevm_ops *ops,
			 struct mlxdevm_port *port, struct sk_buff *msg,
			 struct netlink_ext_ack *extack,
			 bool *msg_updated)
{
	struct mlxdevm_port_fn_cap cap;
	int err;

	if (!ops->port_fn_cap_get)
		return 0;

	err = ops->port_fn_cap_get(dev, port, &cap, extack);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}
	if (cap.roce_cap_valid) {
		if (!mlxdevm_port_fn_cap_roce_valid(cap.roce)) {
			WARN_ON_ONCE(1);
			NL_SET_ERR_MSG_MOD(extack, "Invalid roce state read from driver");
			return -EINVAL;
		}

		if (nla_put_u8(msg, MLXDEVM_PORT_FN_ATTR_EXT_CAP_ROCE, cap.roce))
			return -EMSGSIZE;
	}
	if (cap.uc_list_cap_valid) {
		if (nla_put_u32(msg, MLXDEVM_PORT_FN_ATTR_EXT_CAP_UC_LIST, cap.max_uc_list))
			return -EMSGSIZE;
	}

	*msg_updated = true;
	return 0;
}

static int
mlxdevm_nl_port_fn_attrs_put(struct sk_buff *msg, struct mlxdevm *dev,
			     struct mlxdevm_port *port,
			     struct netlink_ext_ack *extack)
{
	const struct mlxdevm_ops *ops;
	struct nlattr *fn_attr;
	bool msg_updated = false;
	int err;

	ops = dev->ops;
	if (!ops)
		return -EOPNOTSUPP;

	fn_attr = nla_nest_start_noflag(msg, MLXDEVM_ATTR_PORT_FUNCTION);
	if (!fn_attr)
		return -EMSGSIZE;

	err = mlxdevm_port_fn_hw_addr_fill(dev, ops, port, msg,
					   extack, &msg_updated);
	if (err)
		goto out;
	err = mlxdevm_port_fn_state_fill(dev, ops, port, msg, extack,
					 &msg_updated);
	if (err)
		goto out;

	err = mlxdevm_port_fn_cap_fill(dev, ops, port, msg, extack,
				       &msg_updated);

out:
	if (err || !msg_updated)
		nla_nest_cancel(msg, fn_attr);
	else
		nla_nest_end(msg, fn_attr);
	return err;
}

static int mlxdevm_nl_port_fill(struct sk_buff *msg, struct mlxdevm *dev,
				struct mlxdevm_port *port,
				enum mlxdevm_command cmd, u32 portid,
				u32 seq, int flags,
				struct netlink_ext_ack *extack)
{
	void *hdr;

	hdr = genlmsg_put(msg, portid, seq, &mlxdevm_nl_family, flags, cmd);
	if (!hdr)
		return -EMSGSIZE;

	if (mlxdevm_nl_dev_handle_fill(msg, dev))
		goto nla_put_failure;
	if (nla_put_u32(msg, MLXDEVM_ATTR_PORT_INDEX, port->index))
		goto nla_put_failure;

	/* Hold rtnl lock while accessing port's netdev attributes. */
	rtnl_lock();
	spin_lock_bh(&port->type_lock);
	if (nla_put_u16(msg, MLXDEVM_ATTR_PORT_TYPE, port->type))
		goto nla_put_failure_type_locked;
	if (port->type == MLXDEVM_PORT_TYPE_ETH) {
		struct net_device *netdev = port->type_dev;

		if (netdev &&
		    (nla_put_u32(msg, MLXDEVM_ATTR_PORT_NETDEV_IFINDEX,
				 netdev->ifindex) ||
		     nla_put_string(msg, MLXDEVM_ATTR_PORT_NETDEV_NAME,
				    netdev->name)))
			goto nla_put_failure_type_locked;
	}
	spin_unlock_bh(&port->type_lock);
	rtnl_unlock();
	if (mlxdevm_nl_port_attrs_put(msg, port))
		goto nla_put_failure;
	if (mlxdevm_nl_port_fn_attrs_put(msg, dev, port, extack))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);
	return 0;

nla_put_failure_type_locked:
	spin_unlock_bh(&port->type_lock);
	rtnl_unlock();
nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

static int
mlxdevm_nl_cmd_port_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm *dev;
	struct mlxdevm_port *port;
	struct sk_buff *msg;
	int err;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	mutex_lock(&mlxdevm_mutex);
	dev = mlxdevm_dev_get_from_attr(info->attrs);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto err;
	}

	port = mlxdevm_port_get_from_attrs(dev, info->attrs);
	if (IS_ERR(port)) {
		err = PTR_ERR(port);
		goto err;
	}

	err = mlxdevm_nl_port_fill(msg, dev, port,
				   MLXDEVM_CMD_PORT_NEW,
				   info->snd_portid, info->snd_seq, 0,
				   info->extack);
	if (err)
		goto err;

	mutex_unlock(&mlxdevm_mutex);
	return genlmsg_reply(msg, info);

err:
	mutex_unlock(&mlxdevm_mutex);
	nlmsg_free(msg);
	return err;
}

static int mlxdevm_nl_cmd_port_get_dumpit(struct sk_buff *msg,
					  struct netlink_callback *cb)
{
	struct mlxdevm *dev;
	struct mlxdevm_port *port;
	int start = cb->args[0];
	int idx = 0;
	int err;

	mutex_lock(&mlxdevm_mutex);
	list_for_each_entry(dev, &dev_head, list) {
		down_read(&dev->port_list_rwsem);
		list_for_each_entry(port, &dev->port_list, list) {
			if (idx < start) {
				idx++;
				continue;
			}
			err = mlxdevm_nl_port_fill(msg, dev, port,
						   MLXDEVM_CMD_PORT_NEW,
						   NETLINK_CB(cb->skb).portid,
						   cb->nlh->nlmsg_seq,
						   NLM_F_MULTI,
						   cb->extack);
			if (err) {
				up_read(&dev->port_list_rwsem);
				goto out;
			}
			idx++;
		}
		up_read(&dev->port_list_rwsem);
	}
out:
	mutex_unlock(&mlxdevm_mutex);

	cb->args[0] = idx;
	return msg->len;
}

static int mlxdevm_nl_rate_fill_common(struct sk_buff *msg, enum mlxdevm_rate_type rate_type,
				       u64 tx_max, u64 tx_share)
{
	if (nla_put_u16(msg, MLXDEVM_ATTR_EXT_RATE_TYPE, rate_type))
		return -EMSGSIZE;
	if (nla_put_u64_64bit(msg, MLXDEVM_ATTR_EXT_RATE_TX_MAX, tx_max, MLXDEVM_ATTR_EXT_PAD))
		return -EMSGSIZE;
	if (nla_put_u64_64bit(msg, MLXDEVM_ATTR_EXT_RATE_TX_SHARE, tx_share, MLXDEVM_ATTR_EXT_PAD))
		return -EMSGSIZE;
	return 0;
}

static int mlxdevm_nl_leaf_fill(struct sk_buff *msg, struct mlxdevm *dev,
				struct mlxdevm_port *port,
				enum mlxdevm_command cmd, u32 portid,
				u32 seq, int flags,
				struct netlink_ext_ack *extack)
{
	const struct mlxdevm_ops *ops = dev->ops;
	u64 tx_share = 0;
	u64 tx_max = 0;
	char *group;
	void *hdr;
	int err;

	if (!ops || !ops->rate_leaf_get)
		return -EOPNOTSUPP;

	/* Reading a group here cannot result in use-after-free access of the group
	 * because this is done while holding the rate_group_rwsem. This serializes
	 * any ongoing group destruction from the driver layer.
	 */
	err = ops->rate_leaf_get(dev, port, &tx_max, &tx_share, &group, extack);
	if (err)
		return err;

	hdr = genlmsg_put(msg, portid, seq, &mlxdevm_nl_family, flags, cmd);
	if (!hdr)
		return -EMSGSIZE;

	if (mlxdevm_nl_dev_handle_fill(msg, dev))
		goto nla_put_failure;
	if (nla_put_u32(msg, MLXDEVM_ATTR_PORT_INDEX, port->index))
		goto nla_put_failure;

	if (group) {
		if (nla_put_string(msg, MLXDEVM_ATTR_EXT_RATE_PARENT_NODE_NAME, group))
			goto nla_put_failure;
	}

	if (mlxdevm_nl_rate_fill_common(msg, MLXDEVM_RATE_EXT_TYPE_LEAF, tx_max, tx_share))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

static int mlxdevm_nl_node_fill(struct sk_buff *msg, struct mlxdevm *dev,
				struct mlxdevm_rate_group *group,
				enum mlxdevm_command cmd, u32 portid,
				u32 seq, int flags,
				struct netlink_ext_ack *extack)
{
	void *hdr;

	hdr = genlmsg_put(msg, portid, seq, &mlxdevm_nl_family, flags, cmd);
	if (!hdr)
		return -EMSGSIZE;

	if (mlxdevm_nl_dev_handle_fill(msg, dev))
		goto nla_put_failure;

	if (nla_put_string(msg, MLXDEVM_ATTR_EXT_RATE_NODE_NAME, group->name))
		goto nla_put_failure;

	if (mlxdevm_nl_rate_fill_common(msg, MLXDEVM_RATE_EXT_TYPE_NODE,
					group->tx_max, group->tx_share))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

static int mlxdevm_port_fn_leaf_tx_share(struct mlxdevm *dev, struct mlxdevm_port *port,
					 u64 tx_share, struct netlink_ext_ack *extack)
{
	const struct mlxdevm_ops *ops = dev->ops;

	if (!ops || !ops->rate_leaf_tx_share_set) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Function does not support leaf tx_share setting");
		return -EOPNOTSUPP;
	}
	return ops->rate_leaf_tx_share_set(dev, port, tx_share, extack);
}

static int mlxdevm_port_fn_leaf_tx_max(struct mlxdevm *dev, struct mlxdevm_port *port,
				       u64 tx_max, struct netlink_ext_ack *extack)
{
	const struct mlxdevm_ops *ops = dev->ops;

	if (!ops || !ops->rate_leaf_tx_max_set) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Function does not support leaf tx_max setting");
		return -EOPNOTSUPP;
	}
	return ops->rate_leaf_tx_max_set(dev, port, tx_max, extack);
}

static int mlxdevm_port_fn_leaf_group(struct mlxdevm *dev, struct mlxdevm_port *port,
				      const char *group, struct netlink_ext_ack *extack)
{
	const struct mlxdevm_ops *ops = dev->ops;

	if (!ops || !ops->rate_leaf_group_set) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Function does not support leaf parent group setting");
		return -EOPNOTSUPP;
	}
	return ops->rate_leaf_group_set(dev, port, group, extack);
}

static int mlxdevm_port_fn_node_tx_share(struct mlxdevm *dev, const char *group,
					 u64 tx_share, struct netlink_ext_ack *extack)
{
	const struct mlxdevm_ops *ops = dev->ops;

	if (!ops || !ops->rate_node_tx_share_set) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Function does not support node tx_share setting");
		return -EOPNOTSUPP;
	}
	return ops->rate_node_tx_share_set(dev, group, tx_share, extack);
}

static int mlxdevm_port_fn_node_tx_max(struct mlxdevm *dev, const char *group,
				       u64 tx_max, struct netlink_ext_ack *extack)
{
	const struct mlxdevm_ops *ops = dev->ops;

	if (!ops || !ops->rate_node_tx_max_set) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Function does not support node tx_share setting");
		return -EOPNOTSUPP;
	}
	return ops->rate_node_tx_max_set(dev, group, tx_max, extack);
}

static int mlxdevm_rate_node_get_doit_locked(struct mlxdevm *dev, struct genl_info *info,
					     struct sk_buff *msg)
{
	struct mlxdevm_rate_group *cur, *found_group;
	const char *group;
	int err;

	if (!info->attrs[MLXDEVM_ATTR_EXT_RATE_NODE_NAME])
		return -EINVAL;

	group = nla_strdup(info->attrs[MLXDEVM_ATTR_EXT_RATE_NODE_NAME], GFP_KERNEL);
	if (!group)
		return -ENOMEM;

	down_read(&dev->rate_group_rwsem);
	found_group = NULL;
	list_for_each_entry(cur, &dev->rate_group_list, list) {
		if (strcmp(cur->name, group) == 0) {
			found_group = cur;
			break;
		}
	}

	if (found_group)
		err = mlxdevm_nl_node_fill(msg, dev,
					   found_group,
					   MLXDEVM_CMD_EXT_RATE_GET,
					   info->snd_portid, info->snd_seq, 0,
					   info->extack);
	else
		err = -ENOENT;

	up_read(&dev->rate_group_rwsem);
	kfree(group);
	return err;
}

static int mlxdevm_rate_leaf_get_doit_locked(struct mlxdevm *dev, struct genl_info *info,
					     struct sk_buff *msg)
{
	struct mlxdevm_port *port = mlxdevm_port_get_from_attrs(dev, info->attrs);

	if (IS_ERR(port))
		return PTR_ERR(port);

	return mlxdevm_nl_leaf_fill(msg, dev, port,
				    MLXDEVM_CMD_EXT_RATE_GET,
				    info->snd_portid, info->snd_seq, 0,
				    info->extack);
}

static int mlxdevm_rate_leaf_get_doit(struct mlxdevm *dev, struct genl_info *info,
				      struct sk_buff *msg)
{
	int err;

	down_read(&dev->port_list_rwsem);
	err = mlxdevm_rate_leaf_get_doit_locked(dev, info, msg);
	up_read(&dev->port_list_rwsem);
	return err;
}

static int mlxdevm_nl_cmd_rate_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm *dev;
	struct sk_buff *msg;
	u16 rate_type;
	int err;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	if (!info->attrs[MLXDEVM_ATTR_EXT_RATE_TYPE]) {
		err = -EINVAL;
		goto err_nolock;
	}
	rate_type = nla_get_u16(info->attrs[MLXDEVM_ATTR_EXT_RATE_TYPE]);

	mutex_lock(&mlxdevm_mutex);
	dev = mlxdevm_dev_get_from_attr(info->attrs);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto err;
	}

	if (rate_type == MLXDEVM_RATE_EXT_TYPE_NODE)
		err = mlxdevm_rate_node_get_doit_locked(dev, info, msg);
	else
		err = mlxdevm_rate_leaf_get_doit(dev, info, msg);

	if (err)
		goto err;

	mutex_unlock(&mlxdevm_mutex);
	return genlmsg_reply(msg, info);

err:
	mutex_unlock(&mlxdevm_mutex);
err_nolock:
	nlmsg_free(msg);
	return err;
}

static int mlxdevm_nl_cmd_rate_get_dumpit(struct sk_buff *msg,
					  struct netlink_callback *cb)
{
	struct mlxdevm_rate_group *group;
	struct mlxdevm_port *port;
	struct mlxdevm *dev;
	int idx = 0;
	int err;

	if (cb->args[0])
		return msg->len;

	mutex_lock(&mlxdevm_mutex);
	list_for_each_entry(dev, &dev_head, list) {
		down_read(&dev->rate_group_rwsem);
		list_for_each_entry(group, &dev->rate_group_list, list) {
			err = mlxdevm_nl_node_fill(msg, dev, group,
						   MLXDEVM_CMD_EXT_RATE_NEW,
						   NETLINK_CB(cb->skb).portid,
						   cb->nlh->nlmsg_seq,
						   NLM_F_MULTI,
						   cb->extack);
			if (err) {
				up_read(&dev->rate_group_rwsem);
				goto out;
			}
			idx++;
		}
		up_read(&dev->rate_group_rwsem);
	}

	list_for_each_entry(dev, &dev_head, list) {
		down_read(&dev->port_list_rwsem);
		list_for_each_entry(port, &dev->port_list, list) {
			err = mlxdevm_nl_leaf_fill(msg, dev, port,
						   MLXDEVM_CMD_PORT_NEW,
						   NETLINK_CB(cb->skb).portid,
						   cb->nlh->nlmsg_seq,
						   NLM_F_MULTI,
						   cb->extack);
			if (err) {
				up_read(&dev->port_list_rwsem);
				goto out;
			}
			idx++;
		}
		up_read(&dev->port_list_rwsem);
	}

out:
	mutex_unlock(&mlxdevm_mutex);
	cb->args[0] = idx;
	return msg->len;
}

static int mlxdevm_cmd_rate_set_leaf(struct genl_info *info, struct mlxdevm *dev)
{
	struct netlink_ext_ack *extack = info->extack;
	struct mlxdevm_port *port;
	const char *group = NULL;
	int err = 0;
	u64 rate;

	down_write(&dev->port_list_rwsem);
	port = mlxdevm_port_get_from_attrs(dev, info->attrs);
	if (IS_ERR(port)) {
		err = PTR_ERR(port);
		goto out;
	}

	if (info->attrs[MLXDEVM_ATTR_EXT_RATE_TX_SHARE]) {
		rate = nla_get_u64(info->attrs[MLXDEVM_ATTR_EXT_RATE_TX_SHARE]);
		err = mlxdevm_port_fn_leaf_tx_share(dev, port, rate, extack);
		if (err)
			goto out;
	}

	if (info->attrs[MLXDEVM_ATTR_EXT_RATE_TX_MAX]) {
		rate = nla_get_u64(info->attrs[MLXDEVM_ATTR_EXT_RATE_TX_MAX]);
		err = mlxdevm_port_fn_leaf_tx_max(dev, port, rate, extack);
		if (err)
			goto out;
	}

	if (info->attrs[MLXDEVM_ATTR_EXT_RATE_PARENT_NODE_NAME]) {
		group = nla_strdup(info->attrs[MLXDEVM_ATTR_EXT_RATE_PARENT_NODE_NAME], GFP_KERNEL);
		if (!group) {
			err = -ENOMEM;
			goto out;
		}

		err = mlxdevm_port_fn_leaf_group(dev, port, group, extack);
		if (err)
			goto leaf_group_err;
	}

	goto out;

leaf_group_err:
	kfree(group);
out:
	up_write(&dev->port_list_rwsem);
	return err;
}

static int mlxdevm_cmd_rate_set_node(struct genl_info *info, struct mlxdevm *dev)
{
	struct netlink_ext_ack *extack = info->extack;
	const char *group;
	int err = 0;
	u64 rate;

	if (!info->attrs[MLXDEVM_ATTR_EXT_RATE_NODE_NAME])
		return -EINVAL;

	group = nla_strdup(info->attrs[MLXDEVM_ATTR_EXT_RATE_NODE_NAME], GFP_KERNEL);
	if (!group)
		return -ENOMEM;

	if (info->attrs[MLXDEVM_ATTR_EXT_RATE_TX_SHARE]) {
		rate = nla_get_u64(info->attrs[MLXDEVM_ATTR_EXT_RATE_TX_SHARE]);
		err = mlxdevm_port_fn_node_tx_share(dev, group, rate, extack);
		if (err)
			goto out;
	}

	if (info->attrs[MLXDEVM_ATTR_EXT_RATE_TX_MAX]) {
		rate = nla_get_u64(info->attrs[MLXDEVM_ATTR_EXT_RATE_TX_MAX]);
		err = mlxdevm_port_fn_node_tx_max(dev, group, rate, extack);
	}

out:
	kfree(group);
	return err;
}

static int mlxdevm_nl_cmd_rate_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	enum mlxdevm_rate_type rate_type;
	struct mlxdevm *dev;
	int err = 0;

	if (!info->attrs[MLXDEVM_ATTR_EXT_RATE_TYPE])
		return -EINVAL;
	rate_type = nla_get_u16(info->attrs[MLXDEVM_ATTR_EXT_RATE_TYPE]);

	mutex_lock(&mlxdevm_mutex);
	dev = mlxdevm_dev_get_from_attr(info->attrs);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto out;
	}

	if (rate_type == MLXDEVM_RATE_EXT_TYPE_LEAF)
		err = mlxdevm_cmd_rate_set_leaf(info, dev);
	else
		err = mlxdevm_cmd_rate_set_node(info, dev);

out:
	mutex_unlock(&mlxdevm_mutex);
	return err;
}

static const char *mlxdevm_node_get_group_name(struct genl_info *info)
{
	enum mlxdevm_rate_type rate_type;
	const char *group;

	if (!info->attrs[MLXDEVM_ATTR_EXT_RATE_TYPE])
		return ERR_PTR(-EINVAL);

	rate_type = nla_get_u16(info->attrs[MLXDEVM_ATTR_EXT_RATE_TYPE]);
	if (rate_type != MLXDEVM_RATE_EXT_TYPE_NODE)
		return ERR_PTR(-EINVAL);

	if (!info->attrs[MLXDEVM_ATTR_EXT_RATE_NODE_NAME])
		return ERR_PTR(-EINVAL);

	group = nla_strdup(info->attrs[MLXDEVM_ATTR_EXT_RATE_NODE_NAME], GFP_KERNEL);
	if (!group)
		return ERR_PTR(-ENOMEM);

	return group;
}

static int mlxdevm_nl_cmd_rate_new_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct netlink_ext_ack *extack = info->extack;
	const struct mlxdevm_ops *ops;
	struct mlxdevm *dev;
	const char *group;
	int err;

	group = mlxdevm_node_get_group_name(info);
	if (IS_ERR(group))
		return PTR_ERR(group);

	mutex_lock(&mlxdevm_mutex);
	dev = mlxdevm_dev_get_from_attr(info->attrs);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto out;
	}

	ops = dev->ops;
	if (!ops || !ops->rate_node_new) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Function does not support new rate node");
		err = -EOPNOTSUPP;
		goto out;
	}

	err = ops->rate_node_new(dev, group, extack);
out:
	mutex_unlock(&mlxdevm_mutex);
	kfree(group);
	return err;
}

static int mlxdevm_nl_cmd_rate_del_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct netlink_ext_ack *extack = info->extack;
	const struct mlxdevm_ops *ops;
	struct mlxdevm *dev;
	const char *group;
	int err;

	group = mlxdevm_node_get_group_name(info);
	if (IS_ERR(group))
		return PTR_ERR(group);

	mutex_lock(&mlxdevm_mutex);
	dev = mlxdevm_dev_get_from_attr(info->attrs);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto out;
	}

	ops = dev->ops;
	if (!ops || !ops->rate_node_del) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Function does not support del rate node");
		err = -EOPNOTSUPP;
		goto out;
	}

	err = ops->rate_node_del(dev, group, extack);

out:
	mutex_unlock(&mlxdevm_mutex);
	kfree(group);
	return err;
}

static int mlxdevm_port_new_notifiy(struct mlxdevm *dev,
				    unsigned int port_index,
				    struct genl_info *info)
{
	struct mlxdevm_port *port;
	struct sk_buff *msg;
	int err;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	port = mlxdevm_port_get_by_index(dev, port_index);
	if (!port) {
		err = -ENODEV;
		goto out;
	}

	err = mlxdevm_nl_port_fill(msg, dev, port,
				   MLXDEVM_CMD_PORT_NEW, info->snd_portid,
				   info->snd_seq, 0, NULL);
	if (err)
		goto out;

	err = genlmsg_reply(msg, info);
	return err;

out:
	nlmsg_free(msg);
	return err;
}

static int
mlxdevm_port_fn_hw_addr_set(struct mlxdevm *dev,
			    struct mlxdevm_port *port,
			    const struct nlattr *attr,
			    struct netlink_ext_ack *extack)
{
	const struct mlxdevm_ops *ops;
	const u8 *hw_addr;
	int hw_addr_len;

	hw_addr = nla_data(attr);
	hw_addr_len = nla_len(attr);
	if (hw_addr_len > MAX_ADDR_LEN) {
		NL_SET_ERR_MSG_MOD(extack, "Port function hardware address too long");
		return -EINVAL;
	}
	if (port->type == MLXDEVM_PORT_TYPE_ETH) {
		if (hw_addr_len != ETH_ALEN) {
			NL_SET_ERR_MSG_MOD(extack, "Address must be 6 bytes for Ethernet device");
			return -EINVAL;
		}
		if (!is_unicast_ether_addr(hw_addr)) {
			NL_SET_ERR_MSG_MOD(extack, "Non-unicast hardware address unsupported");
			return -EINVAL;
		}
	}

	ops = dev->ops;
	if (!ops->port_fn_hw_addr_set) {
		NL_SET_ERR_MSG_MOD(extack, "Port doesn't support function attributes");
		return -EOPNOTSUPP;
	}

	return ops->port_fn_hw_addr_set(dev, port, hw_addr, hw_addr_len, extack);
}

static int mlxdevm_port_fn_state_set(struct mlxdevm *dev,
				     struct mlxdevm_port *port,
				     const struct nlattr *attr,
				     struct netlink_ext_ack *extack)
{
	enum mlxdevm_port_fn_state state;
	const struct mlxdevm_ops *ops;

	state = nla_get_u8(attr);

	ops = dev->ops;
	if (!ops->port_fn_state_set) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Function does not support state setting");
		return -EOPNOTSUPP;
	}
	return ops->port_fn_state_set(dev, port, state, extack);
}

static int
mlxdevm_port_fn_set(struct mlxdevm *dev, struct mlxdevm_port *port,
		    const struct nlattr *attr, struct netlink_ext_ack *extack)
{
	struct nlattr *tb[MLXDEVM_PORT_FUNCTION_ATTR_MAX + 1];
	int err;

	if (!dev->ops)
		return -EOPNOTSUPP;

	err = nla_parse_nested(tb, MLXDEVM_PORT_FUNCTION_ATTR_MAX, attr,
			       mlxdevm_function_nl_policy, extack);
	if (err < 0) {
		NL_SET_ERR_MSG_MOD(extack, "Fail to parse port function attributes");
		return err;
	}

	attr = tb[MLXDEVM_PORT_FUNCTION_ATTR_HW_ADDR];
	if (attr) {
		err = mlxdevm_port_fn_hw_addr_set(dev, port, attr, extack);
		if (err)
			return err;
	}
	/* Keep this as the last function attribute set, so that when
	 * multiple port function attributes are set along with state,
	 * Those can be applied first before activating the state.
	 */
	attr = tb[MLXDEVM_PORT_FN_ATTR_STATE];
	if (attr) {
		if (!mlxdevm_port_fn_state_valid(nla_get_u8(attr)))
			return -EINVAL;
		err = mlxdevm_port_fn_state_set(dev, port, attr, extack);
	}

	return err;
}

static int
mlxdevm_nl_cmd_port_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm *dev;
	struct mlxdevm_port *port;
	int err = 0;

	mutex_lock(&mlxdevm_mutex);
	dev = mlxdevm_dev_get_from_attr(info->attrs);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto out;
	}

	port = mlxdevm_port_get_from_attrs(dev, info->attrs);
	if (IS_ERR(port)) {
		err = PTR_ERR(port);
		goto out;
	}

	if (info->attrs[MLXDEVM_ATTR_PORT_FUNCTION]) {
		struct nlattr *attr = info->attrs[MLXDEVM_ATTR_PORT_FUNCTION];
		struct netlink_ext_ack *extack = info->extack;

		err = mlxdevm_port_fn_set(dev, port, attr, extack);
		if (err)
			goto out;
	}

out:
	mutex_unlock(&mlxdevm_mutex);
	return err;
}

static int
mlxdevm_nl_cmd_port_new_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct netlink_ext_ack *extack = info->extack;
	struct mlxdevm_port_new_attrs new_attrs = {};
	struct mlxdevm *dev;
	unsigned int new_port_index;
	int err;

	mutex_lock(&mlxdevm_mutex);
	dev = mlxdevm_dev_get_from_attr(info->attrs);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto out;
	}

	if (!dev->ops) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!dev->ops->port_new || !dev->ops->port_del) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!info->attrs[MLXDEVM_ATTR_PORT_FLAVOUR] ||
	    !info->attrs[MLXDEVM_ATTR_PORT_PCI_PF_NUMBER]) {
		NL_SET_ERR_MSG_MOD(extack, "Port flavour or PCI PF are not specified");
		err = -EINVAL;
		goto out;
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

	err = dev->ops->port_new(dev, &new_attrs, extack, &new_port_index);
	if (err)
		goto out;

	err = mlxdevm_port_new_notifiy(dev, new_port_index, info);
	if (err && err != -ENODEV) {
		/* Fail to send the response; destroy newly created port. */
		dev->ops->port_del(dev, new_port_index, extack);
	}
out:
	mutex_unlock(&mlxdevm_mutex);
	return err;
}

static int
mlxdevm_nl_cmd_port_del_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct netlink_ext_ack *extack = info->extack;
	struct mlxdevm *dev;
	unsigned int port_index;
	int err;

	mutex_lock(&mlxdevm_mutex);
	dev = mlxdevm_dev_get_from_attr(info->attrs);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto out;
	}
	if (!dev->ops || !dev->ops->port_del) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!info->attrs[MLXDEVM_ATTR_PORT_INDEX]) {
		NL_SET_ERR_MSG_MOD(extack, "Port index is not specified");
		err = -EINVAL;
		goto out;
	}
	port_index = nla_get_u32(info->attrs[MLXDEVM_ATTR_PORT_INDEX]);

	err = dev->ops->port_del(dev, port_index, extack);
out:
	mutex_unlock(&mlxdevm_mutex);
	return err;
}

static int
mlxdevm_port_fn_cap_set(struct mlxdevm *dev, struct mlxdevm_port *port,
			const struct nlattr *attr,
			struct netlink_ext_ack *extack)
{
	struct nlattr *tb[MLXDEVM_PORT_FUNCTION_ATTR_MAX + 1];
	struct mlxdevm_port_fn_cap cap = {};
	const struct mlxdevm_ops *ops;
	int err;

	ops = dev->ops;
	if (!ops)
		return -EOPNOTSUPP;

	if (!ops->port_fn_cap_set) {
		NL_SET_ERR_MSG_MOD(extack, "Function capability does not support setting");
		return -EOPNOTSUPP;
	}

	err = nla_parse_nested(tb, MLXDEVM_PORT_FUNCTION_ATTR_MAX, attr,
			       mlxdevm_function_nl_policy, extack);
	if (err < 0) {
		NL_SET_ERR_MSG_MOD(extack, "Fail to parse port function cap attributes");
		return err;
	}

	attr = tb[MLXDEVM_PORT_FN_ATTR_EXT_CAP_ROCE];
	if (attr) {
		cap.roce = nla_get_u8(attr);

		if (!mlxdevm_port_fn_cap_roce_valid(cap.roce))
			return -EINVAL;

		cap.roce_cap_valid = true;
	}
	attr = tb[MLXDEVM_PORT_FN_ATTR_EXT_CAP_UC_LIST];
	if (attr) {
		cap.max_uc_list = nla_get_u32(attr);
		cap.uc_list_cap_valid = true;
	}
	return ops->port_fn_cap_set(dev, port, &cap, extack);
}

static int
mlxdevm_nl_cmd_port_fn_cap_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mlxdevm *dev;
	struct mlxdevm_port *port;
	int err = 0;

	mutex_lock(&mlxdevm_mutex);
	dev = mlxdevm_dev_get_from_attr(info->attrs);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto out;
	}

	port = mlxdevm_port_get_from_attrs(dev, info->attrs);
	if (IS_ERR(port)) {
		err = PTR_ERR(port);
		goto out;
	}

	if (info->attrs[MLXDEVM_ATTR_EXT_PORT_FN_CAP]) {
		struct nlattr *attr = info->attrs[MLXDEVM_ATTR_EXT_PORT_FN_CAP];
		struct netlink_ext_ack *extack = info->extack;

		err = mlxdevm_port_fn_cap_set(dev, port, attr, extack);
		if (err)
			goto out;
	}

out:
	mutex_unlock(&mlxdevm_mutex);
	return err;
}

static const struct nla_policy mlxdevm_nl_policy[MLXDEVM_ATTR_MAX + 1] = {
	[MLXDEVM_ATTR_DEV_BUS_NAME] = { .type = NLA_STRING },
	[MLXDEVM_ATTR_DEV_NAME] = { .type = NLA_STRING },
	[MLXDEVM_ATTR_PORT_INDEX] = { .type = NLA_U32 },
	[MLXDEVM_ATTR_PORT_FLAVOUR] = { .type = NLA_U16 },
	[MLXDEVM_ATTR_PORT_PCI_PF_NUMBER] = { .type = NLA_U16 },
	[MLXDEVM_ATTR_PORT_PCI_SF_NUMBER] = { .type = NLA_U32 },
	[MLXDEVM_ATTR_PORT_CONTROLLER_NUMBER] = { .type = NLA_U32 },
};

static const struct genl_ops mlxdevm_nl_ops[] = {
	{
		.cmd = MLXDEVM_CMD_DEV_GET,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = mlxdevm_nl_cmd_dev_get_doit,
		.dumpit = mlxdevm_nl_cmd_dev_get_dumpit,
	},
	{
		.cmd = MLXDEVM_CMD_PORT_SET,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = mlxdevm_nl_cmd_port_set_doit,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MLXDEVM_CMD_PORT_GET,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = mlxdevm_nl_cmd_port_get_doit,
		.dumpit = mlxdevm_nl_cmd_port_get_dumpit,
		/* can be retrieved by unprivileged users */
	},
	{
		.cmd = MLXDEVM_CMD_PORT_NEW,
		.doit = mlxdevm_nl_cmd_port_new_doit,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MLXDEVM_CMD_PORT_DEL,
		.doit = mlxdevm_nl_cmd_port_del_doit,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MLXDEVM_CMD_PARAM_GET,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = mlxdevm_nl_cmd_param_get_doit,
		.dumpit = mlxdevm_nl_cmd_param_get_dumpit,
		/* can be retrieved by unprivileged users */
	},
	{
		.cmd = MLXDEVM_CMD_PARAM_SET,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = mlxdevm_nl_cmd_param_set_doit,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MLXDEVM_CMD_EXT_CAP_SET,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = mlxdevm_nl_cmd_port_fn_cap_set_doit,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MLXDEVM_CMD_EXT_RATE_SET,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = mlxdevm_nl_cmd_rate_set_doit,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MLXDEVM_CMD_EXT_RATE_GET,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = mlxdevm_nl_cmd_rate_get_doit,
		.dumpit = mlxdevm_nl_cmd_rate_get_dumpit,
		/* can be retrieved by unprivileged users */
	},
	{
		.cmd = MLXDEVM_CMD_EXT_RATE_NEW,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = mlxdevm_nl_cmd_rate_new_doit,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = MLXDEVM_CMD_EXT_RATE_DEL,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = mlxdevm_nl_cmd_rate_del_doit,
		.flags = GENL_ADMIN_PERM,
	},
};

static struct genl_family mlxdevm_nl_family __ro_after_init = {
	.name = MLXDEVM_GENL_NAME,
	.version = MLXDEVM_GENL_VERSION,
	.maxattr = MLXDEVM_ATTR_MAX,
	.policy = mlxdevm_nl_policy,
	.netnsok = false,
	.module = THIS_MODULE,
	.ops = mlxdevm_nl_ops,
	.n_ops = ARRAY_SIZE(mlxdevm_nl_ops),
};

static int __init mlxdevm_init(void)
{
	return genl_register_family(&mlxdevm_nl_family);
}

static void __exit mlxdevm_cleanup(void)
{
	genl_unregister_family(&mlxdevm_nl_family);
}

module_init(mlxdevm_init);
module_exit(mlxdevm_cleanup);
