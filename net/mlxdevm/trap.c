// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2016 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2016 Jiri Pirko <jiri@mellanox.com>
 */

#include <trace/events/devlink.h>

#include "devl_internal.h"

struct mlxdevm_stats {
	u64_stats_t rx_bytes;
	u64_stats_t rx_packets;
	struct u64_stats_sync syncp;
};

/**
 * struct mlxdevm_trap_policer_item - Packet trap policer attributes.
 * @policer: Immutable packet trap policer attributes.
 * @rate: Rate in packets / sec.
 * @burst: Burst size in packets.
 * @list: trap_policer_list member.
 *
 * Describes packet trap policer attributes. Created by mlxdevm during trap
 * policer registration.
 */
struct mlxdevm_trap_policer_item {
	const struct mlxdevm_trap_policer *policer;
	u64 rate;
	u64 burst;
	struct list_head list;
};

/**
 * struct mlxdevm_trap_group_item - Packet trap group attributes.
 * @group: Immutable packet trap group attributes.
 * @policer_item: Associated policer item. Can be NULL.
 * @list: trap_group_list member.
 * @stats: Trap group statistics.
 *
 * Describes packet trap group attributes. Created by mlxdevm during trap
 * group registration.
 */
struct mlxdevm_trap_group_item {
	const struct mlxdevm_trap_group *group;
	struct mlxdevm_trap_policer_item *policer_item;
	struct list_head list;
	struct mlxdevm_stats __percpu *stats;
};

/**
 * struct mlxdevm_trap_item - Packet trap attributes.
 * @trap: Immutable packet trap attributes.
 * @group_item: Associated group item.
 * @list: trap_list member.
 * @action: Trap action.
 * @stats: Trap statistics.
 * @priv: Driver private information.
 *
 * Describes both mutable and immutable packet trap attributes. Created by
 * mlxdevm during trap registration and used for all trap related operations.
 */
struct mlxdevm_trap_item {
	const struct mlxdevm_trap *trap;
	struct mlxdevm_trap_group_item *group_item;
	struct list_head list;
	enum mlxdevm_trap_action action;
	struct mlxdevm_stats __percpu *stats;
	void *priv;
};

static struct mlxdevm_trap_policer_item *
mlxdevm_trap_policer_item_lookup(struct mlxdevm *mlxdevm, u32 id)
{
	struct mlxdevm_trap_policer_item *policer_item;

	list_for_each_entry(policer_item, &mlxdevm->trap_policer_list, list) {
		if (policer_item->policer->id == id)
			return policer_item;
	}

	return NULL;
}

static struct mlxdevm_trap_item *
mlxdevm_trap_item_lookup(struct mlxdevm *mlxdevm, const char *name)
{
	struct mlxdevm_trap_item *trap_item;

	list_for_each_entry(trap_item, &mlxdevm->trap_list, list) {
		if (!strcmp(trap_item->trap->name, name))
			return trap_item;
	}

	return NULL;
}

static struct mlxdevm_trap_item *
mlxdevm_trap_item_get_from_info(struct mlxdevm *mlxdevm,
				struct genl_info *info)
{
	struct nlattr *attr;

	if (!info->attrs[MLXDEVM_ATTR_TRAP_NAME])
		return NULL;
	attr = info->attrs[MLXDEVM_ATTR_TRAP_NAME];

	return mlxdevm_trap_item_lookup(mlxdevm, nla_data(attr));
}

static int
mlxdevm_trap_action_get_from_info(struct genl_info *info,
				  enum mlxdevm_trap_action *p_trap_action)
{
	u8 val;

	val = nla_get_u8(info->attrs[MLXDEVM_ATTR_TRAP_ACTION]);
	switch (val) {
	case MLXDEVM_TRAP_ACTION_DROP:
	case MLXDEVM_TRAP_ACTION_TRAP:
	case MLXDEVM_TRAP_ACTION_MIRROR:
		*p_trap_action = val;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int mlxdevm_trap_metadata_put(struct sk_buff *msg,
				     const struct mlxdevm_trap *trap)
{
	struct nlattr *attr;

	attr = nla_nest_start(msg, MLXDEVM_ATTR_TRAP_METADATA);
	if (!attr)
		return -EMSGSIZE;

	if ((trap->metadata_cap & MLXDEVM_TRAP_METADATA_TYPE_F_IN_PORT) &&
	    nla_put_flag(msg, MLXDEVM_ATTR_TRAP_METADATA_TYPE_IN_PORT))
		goto nla_put_failure;
	if ((trap->metadata_cap & MLXDEVM_TRAP_METADATA_TYPE_F_FA_COOKIE) &&
	    nla_put_flag(msg, MLXDEVM_ATTR_TRAP_METADATA_TYPE_FA_COOKIE))
		goto nla_put_failure;

	nla_nest_end(msg, attr);

	return 0;

nla_put_failure:
	nla_nest_cancel(msg, attr);
	return -EMSGSIZE;
}

static void mlxdevm_trap_stats_read(struct mlxdevm_stats __percpu *trap_stats,
				    struct mlxdevm_stats *stats)
{
	int i;

	memset(stats, 0, sizeof(*stats));
	for_each_possible_cpu(i) {
		struct mlxdevm_stats *cpu_stats;
		u64 rx_packets, rx_bytes;
		unsigned int start;

		cpu_stats = per_cpu_ptr(trap_stats, i);
		do {
			start = u64_stats_fetch_begin(&cpu_stats->syncp);
			rx_packets = u64_stats_read(&cpu_stats->rx_packets);
			rx_bytes = u64_stats_read(&cpu_stats->rx_bytes);
		} while (u64_stats_fetch_retry(&cpu_stats->syncp, start));

		u64_stats_add(&stats->rx_packets, rx_packets);
		u64_stats_add(&stats->rx_bytes, rx_bytes);
	}
}

static int
mlxdevm_trap_group_stats_put(struct sk_buff *msg,
			     struct mlxdevm_stats __percpu *trap_stats)
{
	struct mlxdevm_stats stats;
	struct nlattr *attr;

	mlxdevm_trap_stats_read(trap_stats, &stats);

	attr = nla_nest_start(msg, MLXDEVM_ATTR_STATS);
	if (!attr)
		return -EMSGSIZE;

	if (mlxdevm_nl_put_u64(msg, MLXDEVM_ATTR_STATS_RX_PACKETS,
			       u64_stats_read(&stats.rx_packets)))
		goto nla_put_failure;

	if (mlxdevm_nl_put_u64(msg, MLXDEVM_ATTR_STATS_RX_BYTES,
			       u64_stats_read(&stats.rx_bytes)))
		goto nla_put_failure;

	nla_nest_end(msg, attr);

	return 0;

nla_put_failure:
	nla_nest_cancel(msg, attr);
	return -EMSGSIZE;
}

static int mlxdevm_trap_stats_put(struct sk_buff *msg, struct mlxdevm *mlxdevm,
				  const struct mlxdevm_trap_item *trap_item)
{
	struct mlxdevm_stats stats;
	struct nlattr *attr;
	u64 drops = 0;
	int err;

	if (mlxdevm->ops->trap_drop_counter_get) {
		err = mlxdevm->ops->trap_drop_counter_get(mlxdevm,
							  trap_item->trap,
							  &drops);
		if (err)
			return err;
	}

	mlxdevm_trap_stats_read(trap_item->stats, &stats);

	attr = nla_nest_start(msg, MLXDEVM_ATTR_STATS);
	if (!attr)
		return -EMSGSIZE;

	if (mlxdevm->ops->trap_drop_counter_get &&
	    mlxdevm_nl_put_u64(msg, MLXDEVM_ATTR_STATS_RX_DROPPED, drops))
		goto nla_put_failure;

	if (mlxdevm_nl_put_u64(msg, MLXDEVM_ATTR_STATS_RX_PACKETS,
			       u64_stats_read(&stats.rx_packets)))
		goto nla_put_failure;

	if (mlxdevm_nl_put_u64(msg, MLXDEVM_ATTR_STATS_RX_BYTES,
			       u64_stats_read(&stats.rx_bytes)))
		goto nla_put_failure;

	nla_nest_end(msg, attr);

	return 0;

nla_put_failure:
	nla_nest_cancel(msg, attr);
	return -EMSGSIZE;
}

static int mlxdevm_nl_trap_fill(struct sk_buff *msg, struct mlxdevm *mlxdevm,
				const struct mlxdevm_trap_item *trap_item,
				enum mlxdevm_command cmd, u32 portid, u32 seq,
				int flags)
{
	struct mlxdevm_trap_group_item *group_item = trap_item->group_item;
	void *hdr;
	int err;

	hdr = genlmsg_put(msg, portid, seq, &mlxdevm_nl_family, flags, cmd);
	if (!hdr)
		return -EMSGSIZE;

	if (mlxdevm_nl_put_handle(msg, mlxdevm))
		goto nla_put_failure;

	if (nla_put_string(msg, MLXDEVM_ATTR_TRAP_GROUP_NAME,
			   group_item->group->name))
		goto nla_put_failure;

	if (nla_put_string(msg, MLXDEVM_ATTR_TRAP_NAME, trap_item->trap->name))
		goto nla_put_failure;

	if (nla_put_u8(msg, MLXDEVM_ATTR_TRAP_TYPE, trap_item->trap->type))
		goto nla_put_failure;

	if (trap_item->trap->generic &&
	    nla_put_flag(msg, MLXDEVM_ATTR_TRAP_GENERIC))
		goto nla_put_failure;

	if (nla_put_u8(msg, MLXDEVM_ATTR_TRAP_ACTION, trap_item->action))
		goto nla_put_failure;

	err = mlxdevm_trap_metadata_put(msg, trap_item->trap);
	if (err)
		goto nla_put_failure;

	err = mlxdevm_trap_stats_put(msg, mlxdevm, trap_item);
	if (err)
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

int mlxdevm_nl_trap_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct netlink_ext_ack *extack = info->extack;
	struct mlxdevm *mlxdevm = info->user_ptr[0];
	struct mlxdevm_trap_item *trap_item;
	struct sk_buff *msg;
	int err;

	if (list_empty(&mlxdevm->trap_list))
		return -EOPNOTSUPP;

	trap_item = mlxdevm_trap_item_get_from_info(mlxdevm, info);
	if (!trap_item) {
		NL_SET_ERR_MSG(extack, "Device did not register this trap");
		return -ENOENT;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	err = mlxdevm_nl_trap_fill(msg, mlxdevm, trap_item,
				   MLXDEVM_CMD_TRAP_NEW, info->snd_portid,
				   info->snd_seq, 0);
	if (err)
		goto err_trap_fill;

	return genlmsg_reply(msg, info);

err_trap_fill:
	nlmsg_free(msg);
	return err;
}

static int mlxdevm_nl_trap_get_dump_one(struct sk_buff *msg,
					struct mlxdevm *mlxdevm,
					struct netlink_callback *cb, int flags)
{
	struct mlxdevm_nl_dump_state *state = mlxdevm_dump_state(cb);
	struct mlxdevm_trap_item *trap_item;
	int idx = 0;
	int err = 0;

	list_for_each_entry(trap_item, &mlxdevm->trap_list, list) {
		if (idx < state->idx) {
			idx++;
			continue;
		}
		err = mlxdevm_nl_trap_fill(msg, mlxdevm, trap_item,
					   MLXDEVM_CMD_TRAP_NEW,
					   NETLINK_CB(cb->skb).portid,
					   cb->nlh->nlmsg_seq, flags);
		if (err) {
			state->idx = idx;
			break;
		}
		idx++;
	}

	return err;
}

int mlxdevm_nl_trap_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	return mlxdevm_nl_dumpit(skb, cb, mlxdevm_nl_trap_get_dump_one);
}

static int __mlxdevm_trap_action_set(struct mlxdevm *mlxdevm,
				     struct mlxdevm_trap_item *trap_item,
				     enum mlxdevm_trap_action trap_action,
				     struct netlink_ext_ack *extack)
{
	int err;

	if (trap_item->action != trap_action &&
	    trap_item->trap->type != MLXDEVM_TRAP_TYPE_DROP) {
		NL_SET_ERR_MSG(extack, "Cannot change action of non-drop traps. Skipping");
		return 0;
	}

	err = mlxdevm->ops->trap_action_set(mlxdevm, trap_item->trap,
					    trap_action, extack);
	if (err)
		return err;

	trap_item->action = trap_action;

	return 0;
}

static int mlxdevm_trap_action_set(struct mlxdevm *mlxdevm,
				   struct mlxdevm_trap_item *trap_item,
				   struct genl_info *info)
{
	enum mlxdevm_trap_action trap_action;
	int err;

	if (!info->attrs[MLXDEVM_ATTR_TRAP_ACTION])
		return 0;

	err = mlxdevm_trap_action_get_from_info(info, &trap_action);
	if (err) {
		NL_SET_ERR_MSG(info->extack, "Invalid trap action");
		return -EINVAL;
	}

	return __mlxdevm_trap_action_set(mlxdevm, trap_item, trap_action,
					 info->extack);
}

int mlxdevm_nl_trap_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct netlink_ext_ack *extack = info->extack;
	struct mlxdevm *mlxdevm = info->user_ptr[0];
	struct mlxdevm_trap_item *trap_item;

	if (list_empty(&mlxdevm->trap_list))
		return -EOPNOTSUPP;

	trap_item = mlxdevm_trap_item_get_from_info(mlxdevm, info);
	if (!trap_item) {
		NL_SET_ERR_MSG(extack, "Device did not register this trap");
		return -ENOENT;
	}

	return mlxdevm_trap_action_set(mlxdevm, trap_item, info);
}

static struct mlxdevm_trap_group_item *
mlxdevm_trap_group_item_lookup(struct mlxdevm *mlxdevm, const char *name)
{
	struct mlxdevm_trap_group_item *group_item;

	list_for_each_entry(group_item, &mlxdevm->trap_group_list, list) {
		if (!strcmp(group_item->group->name, name))
			return group_item;
	}

	return NULL;
}

static struct mlxdevm_trap_group_item *
mlxdevm_trap_group_item_lookup_by_id(struct mlxdevm *mlxdevm, u16 id)
{
	struct mlxdevm_trap_group_item *group_item;

	list_for_each_entry(group_item, &mlxdevm->trap_group_list, list) {
		if (group_item->group->id == id)
			return group_item;
	}

	return NULL;
}

static struct mlxdevm_trap_group_item *
mlxdevm_trap_group_item_get_from_info(struct mlxdevm *mlxdevm,
				      struct genl_info *info)
{
	char *name;

	if (!info->attrs[MLXDEVM_ATTR_TRAP_GROUP_NAME])
		return NULL;
	name = nla_data(info->attrs[MLXDEVM_ATTR_TRAP_GROUP_NAME]);

	return mlxdevm_trap_group_item_lookup(mlxdevm, name);
}

static int
mlxdevm_nl_trap_group_fill(struct sk_buff *msg, struct mlxdevm *mlxdevm,
			   const struct mlxdevm_trap_group_item *group_item,
			   enum mlxdevm_command cmd, u32 portid, u32 seq,
			   int flags)
{
	void *hdr;
	int err;

	hdr = genlmsg_put(msg, portid, seq, &mlxdevm_nl_family, flags, cmd);
	if (!hdr)
		return -EMSGSIZE;

	if (mlxdevm_nl_put_handle(msg, mlxdevm))
		goto nla_put_failure;

	if (nla_put_string(msg, MLXDEVM_ATTR_TRAP_GROUP_NAME,
			   group_item->group->name))
		goto nla_put_failure;

	if (group_item->group->generic &&
	    nla_put_flag(msg, MLXDEVM_ATTR_TRAP_GENERIC))
		goto nla_put_failure;

	if (group_item->policer_item &&
	    nla_put_u32(msg, MLXDEVM_ATTR_TRAP_POLICER_ID,
			group_item->policer_item->policer->id))
		goto nla_put_failure;

	err = mlxdevm_trap_group_stats_put(msg, group_item->stats);
	if (err)
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

int mlxdevm_nl_trap_group_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct netlink_ext_ack *extack = info->extack;
	struct mlxdevm *mlxdevm = info->user_ptr[0];
	struct mlxdevm_trap_group_item *group_item;
	struct sk_buff *msg;
	int err;

	if (list_empty(&mlxdevm->trap_group_list))
		return -EOPNOTSUPP;

	group_item = mlxdevm_trap_group_item_get_from_info(mlxdevm, info);
	if (!group_item) {
		NL_SET_ERR_MSG(extack, "Device did not register this trap group");
		return -ENOENT;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	err = mlxdevm_nl_trap_group_fill(msg, mlxdevm, group_item,
					 MLXDEVM_CMD_TRAP_GROUP_NEW,
					 info->snd_portid, info->snd_seq, 0);
	if (err)
		goto err_trap_group_fill;

	return genlmsg_reply(msg, info);

err_trap_group_fill:
	nlmsg_free(msg);
	return err;
}

static int mlxdevm_nl_trap_group_get_dump_one(struct sk_buff *msg,
					      struct mlxdevm *mlxdevm,
					      struct netlink_callback *cb,
					      int flags)
{
	struct mlxdevm_nl_dump_state *state = mlxdevm_dump_state(cb);
	struct mlxdevm_trap_group_item *group_item;
	int idx = 0;
	int err = 0;

	list_for_each_entry(group_item, &mlxdevm->trap_group_list, list) {
		if (idx < state->idx) {
			idx++;
			continue;
		}
		err = mlxdevm_nl_trap_group_fill(msg, mlxdevm, group_item,
						 MLXDEVM_CMD_TRAP_GROUP_NEW,
						 NETLINK_CB(cb->skb).portid,
						 cb->nlh->nlmsg_seq, flags);
		if (err) {
			state->idx = idx;
			break;
		}
		idx++;
	}

	return err;
}

int mlxdevm_nl_trap_group_get_dumpit(struct sk_buff *skb,
				     struct netlink_callback *cb)
{
	return mlxdevm_nl_dumpit(skb, cb, mlxdevm_nl_trap_group_get_dump_one);
}

static int
__mlxdevm_trap_group_action_set(struct mlxdevm *mlxdevm,
				struct mlxdevm_trap_group_item *group_item,
				enum mlxdevm_trap_action trap_action,
				struct netlink_ext_ack *extack)
{
	const char *group_name = group_item->group->name;
	struct mlxdevm_trap_item *trap_item;
	int err;

	if (mlxdevm->ops->trap_group_action_set) {
		err = mlxdevm->ops->trap_group_action_set(mlxdevm, group_item->group,
							  trap_action, extack);
		if (err)
			return err;

		list_for_each_entry(trap_item, &mlxdevm->trap_list, list) {
			if (strcmp(trap_item->group_item->group->name, group_name))
				continue;
			if (trap_item->action != trap_action &&
			    trap_item->trap->type != MLXDEVM_TRAP_TYPE_DROP)
				continue;
			trap_item->action = trap_action;
		}

		return 0;
	}

	list_for_each_entry(trap_item, &mlxdevm->trap_list, list) {
		if (strcmp(trap_item->group_item->group->name, group_name))
			continue;
		err = __mlxdevm_trap_action_set(mlxdevm, trap_item,
						trap_action, extack);
		if (err)
			return err;
	}

	return 0;
}

static int
mlxdevm_trap_group_action_set(struct mlxdevm *mlxdevm,
			      struct mlxdevm_trap_group_item *group_item,
			      struct genl_info *info, bool *p_modified)
{
	enum mlxdevm_trap_action trap_action;
	int err;

	if (!info->attrs[MLXDEVM_ATTR_TRAP_ACTION])
		return 0;

	err = mlxdevm_trap_action_get_from_info(info, &trap_action);
	if (err) {
		NL_SET_ERR_MSG(info->extack, "Invalid trap action");
		return -EINVAL;
	}

	err = __mlxdevm_trap_group_action_set(mlxdevm, group_item, trap_action,
					      info->extack);
	if (err)
		return err;

	*p_modified = true;

	return 0;
}

static int mlxdevm_trap_group_set(struct mlxdevm *mlxdevm,
				  struct mlxdevm_trap_group_item *group_item,
				  struct genl_info *info)
{
	struct mlxdevm_trap_policer_item *policer_item;
	struct netlink_ext_ack *extack = info->extack;
	const struct mlxdevm_trap_policer *policer;
	struct nlattr **attrs = info->attrs;
	u32 policer_id;
	int err;

	if (!attrs[MLXDEVM_ATTR_TRAP_POLICER_ID])
		return 0;

	if (!mlxdevm->ops->trap_group_set)
		return -EOPNOTSUPP;

	policer_id = nla_get_u32(attrs[MLXDEVM_ATTR_TRAP_POLICER_ID]);
	policer_item = mlxdevm_trap_policer_item_lookup(mlxdevm, policer_id);
	if (policer_id && !policer_item) {
		NL_SET_ERR_MSG(extack, "Device did not register this trap policer");
		return -ENOENT;
	}
	policer = policer_item ? policer_item->policer : NULL;

	err = mlxdevm->ops->trap_group_set(mlxdevm, group_item->group, policer,
					   extack);
	if (err)
		return err;

	group_item->policer_item = policer_item;

	return 0;
}

int mlxdevm_nl_trap_group_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct netlink_ext_ack *extack = info->extack;
	struct mlxdevm *mlxdevm = info->user_ptr[0];
	struct mlxdevm_trap_group_item *group_item;
	bool modified = false;
	int err;

	if (list_empty(&mlxdevm->trap_group_list))
		return -EOPNOTSUPP;

	group_item = mlxdevm_trap_group_item_get_from_info(mlxdevm, info);
	if (!group_item) {
		NL_SET_ERR_MSG(extack, "Device did not register this trap group");
		return -ENOENT;
	}

	err = mlxdevm_trap_group_action_set(mlxdevm, group_item, info,
					    &modified);
	if (err)
		return err;

	err = mlxdevm_trap_group_set(mlxdevm, group_item, info);
	if (err)
		goto err_trap_group_set;

	return 0;

err_trap_group_set:
	if (modified)
		NL_SET_ERR_MSG(extack, "Trap group set failed, but some changes were committed already");
	return err;
}
#ifdef HAVE_BLOCKED_DEVLINK_CODE

static struct devlink_trap_policer_item *
devlink_trap_policer_item_get_from_info(struct devlink *devlink,
					struct genl_info *info)
{
	u32 id;

	if (!info->attrs[DEVLINK_ATTR_TRAP_POLICER_ID])
		return NULL;
	id = nla_get_u32(info->attrs[DEVLINK_ATTR_TRAP_POLICER_ID]);

	return devlink_trap_policer_item_lookup(devlink, id);
}

static int
devlink_trap_policer_stats_put(struct sk_buff *msg, struct devlink *devlink,
			       const struct devlink_trap_policer *policer)
{
	struct nlattr *attr;
	u64 drops;
	int err;

	if (!devlink->ops->trap_policer_counter_get)
		return 0;

	err = devlink->ops->trap_policer_counter_get(devlink, policer, &drops);
	if (err)
		return err;

	attr = nla_nest_start(msg, DEVLINK_ATTR_STATS);
	if (!attr)
		return -EMSGSIZE;

	if (devlink_nl_put_u64(msg, DEVLINK_ATTR_STATS_RX_DROPPED, drops))
		goto nla_put_failure;

	nla_nest_end(msg, attr);

	return 0;

nla_put_failure:
	nla_nest_cancel(msg, attr);
	return -EMSGSIZE;
}

static int
devlink_nl_trap_policer_fill(struct sk_buff *msg, struct devlink *devlink,
			     const struct devlink_trap_policer_item *policer_item,
			     enum devlink_command cmd, u32 portid, u32 seq,
			     int flags)
{
	void *hdr;
	int err;

	hdr = genlmsg_put(msg, portid, seq, &devlink_nl_family, flags, cmd);
	if (!hdr)
		return -EMSGSIZE;

	if (devlink_nl_put_handle(msg, devlink))
		goto nla_put_failure;

	if (nla_put_u32(msg, DEVLINK_ATTR_TRAP_POLICER_ID,
			policer_item->policer->id))
		goto nla_put_failure;

	if (devlink_nl_put_u64(msg, DEVLINK_ATTR_TRAP_POLICER_RATE,
			       policer_item->rate))
		goto nla_put_failure;

	if (devlink_nl_put_u64(msg, DEVLINK_ATTR_TRAP_POLICER_BURST,
			       policer_item->burst))
		goto nla_put_failure;

	err = devlink_trap_policer_stats_put(msg, devlink,
					     policer_item->policer);
	if (err)
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

int devlink_nl_trap_policer_get_doit(struct sk_buff *skb,
				     struct genl_info *info)
{
	struct devlink_trap_policer_item *policer_item;
	struct netlink_ext_ack *extack = info->extack;
	struct devlink *devlink = info->user_ptr[0];
	struct sk_buff *msg;
	int err;

	if (list_empty(&devlink->trap_policer_list))
		return -EOPNOTSUPP;

	policer_item = devlink_trap_policer_item_get_from_info(devlink, info);
	if (!policer_item) {
		NL_SET_ERR_MSG(extack, "Device did not register this trap policer");
		return -ENOENT;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	err = devlink_nl_trap_policer_fill(msg, devlink, policer_item,
					   DEVLINK_CMD_TRAP_POLICER_NEW,
					   info->snd_portid, info->snd_seq, 0);
	if (err)
		goto err_trap_policer_fill;

	return genlmsg_reply(msg, info);

err_trap_policer_fill:
	nlmsg_free(msg);
	return err;
}

static int devlink_nl_trap_policer_get_dump_one(struct sk_buff *msg,
						struct devlink *devlink,
						struct netlink_callback *cb,
						int flags)
{
	struct devlink_nl_dump_state *state = devlink_dump_state(cb);
	struct devlink_trap_policer_item *policer_item;
	int idx = 0;
	int err = 0;

	list_for_each_entry(policer_item, &devlink->trap_policer_list, list) {
		if (idx < state->idx) {
			idx++;
			continue;
		}
		err = devlink_nl_trap_policer_fill(msg, devlink, policer_item,
						   DEVLINK_CMD_TRAP_POLICER_NEW,
						   NETLINK_CB(cb->skb).portid,
						   cb->nlh->nlmsg_seq, flags);
		if (err) {
			state->idx = idx;
			break;
		}
		idx++;
	}

	return err;
}

int devlink_nl_trap_policer_get_dumpit(struct sk_buff *skb,
				       struct netlink_callback *cb)
{
	return devlink_nl_dumpit(skb, cb, devlink_nl_trap_policer_get_dump_one);
}

static int
devlink_trap_policer_set(struct devlink *devlink,
			 struct devlink_trap_policer_item *policer_item,
			 struct genl_info *info)
{
	struct netlink_ext_ack *extack = info->extack;
	struct nlattr **attrs = info->attrs;
	u64 rate, burst;
	int err;

	rate = policer_item->rate;
	burst = policer_item->burst;

	if (attrs[DEVLINK_ATTR_TRAP_POLICER_RATE])
		rate = nla_get_u64(attrs[DEVLINK_ATTR_TRAP_POLICER_RATE]);

	if (attrs[DEVLINK_ATTR_TRAP_POLICER_BURST])
		burst = nla_get_u64(attrs[DEVLINK_ATTR_TRAP_POLICER_BURST]);

	if (rate < policer_item->policer->min_rate) {
		NL_SET_ERR_MSG(extack, "Policer rate lower than limit");
		return -EINVAL;
	}

	if (rate > policer_item->policer->max_rate) {
		NL_SET_ERR_MSG(extack, "Policer rate higher than limit");
		return -EINVAL;
	}

	if (burst < policer_item->policer->min_burst) {
		NL_SET_ERR_MSG(extack, "Policer burst size lower than limit");
		return -EINVAL;
	}

	if (burst > policer_item->policer->max_burst) {
		NL_SET_ERR_MSG(extack, "Policer burst size higher than limit");
		return -EINVAL;
	}

	err = devlink->ops->trap_policer_set(devlink, policer_item->policer,
					     rate, burst, info->extack);
	if (err)
		return err;

	policer_item->rate = rate;
	policer_item->burst = burst;

	return 0;
}

int devlink_nl_trap_policer_set_doit(struct sk_buff *skb,
				     struct genl_info *info)
{
	struct devlink_trap_policer_item *policer_item;
	struct netlink_ext_ack *extack = info->extack;
	struct devlink *devlink = info->user_ptr[0];

	if (list_empty(&devlink->trap_policer_list))
		return -EOPNOTSUPP;

	if (!devlink->ops->trap_policer_set)
		return -EOPNOTSUPP;

	policer_item = devlink_trap_policer_item_get_from_info(devlink, info);
	if (!policer_item) {
		NL_SET_ERR_MSG(extack, "Device did not register this trap policer");
		return -ENOENT;
	}

	return devlink_trap_policer_set(devlink, policer_item, info);
}
#endif

#define MLXDEVM_TRAP(_id, _type)					      \
	{								      \
		.type = MLXDEVM_TRAP_TYPE_##_type,			      \
		.id = MLXDEVM_TRAP_GENERIC_ID_##_id,			      \
		.name = MLXDEVM_TRAP_GENERIC_NAME_##_id,		      \
	}

static const struct mlxdevm_trap mlxdevm_trap_generic[] = {
	MLXDEVM_TRAP(SMAC_MC, DROP),
	MLXDEVM_TRAP(VLAN_TAG_MISMATCH, DROP),
	MLXDEVM_TRAP(INGRESS_VLAN_FILTER, DROP),
	MLXDEVM_TRAP(INGRESS_STP_FILTER, DROP),
	MLXDEVM_TRAP(EMPTY_TX_LIST, DROP),
	MLXDEVM_TRAP(PORT_LOOPBACK_FILTER, DROP),
	MLXDEVM_TRAP(BLACKHOLE_ROUTE, DROP),
	MLXDEVM_TRAP(TTL_ERROR, EXCEPTION),
	MLXDEVM_TRAP(TAIL_DROP, DROP),
	MLXDEVM_TRAP(NON_IP_PACKET, DROP),
	MLXDEVM_TRAP(UC_DIP_MC_DMAC, DROP),
	MLXDEVM_TRAP(DIP_LB, DROP),
	MLXDEVM_TRAP(SIP_MC, DROP),
	MLXDEVM_TRAP(SIP_LB, DROP),
	MLXDEVM_TRAP(CORRUPTED_IP_HDR, DROP),
	MLXDEVM_TRAP(IPV4_SIP_BC, DROP),
	MLXDEVM_TRAP(IPV6_MC_DIP_RESERVED_SCOPE, DROP),
	MLXDEVM_TRAP(IPV6_MC_DIP_INTERFACE_LOCAL_SCOPE, DROP),
	MLXDEVM_TRAP(MTU_ERROR, EXCEPTION),
	MLXDEVM_TRAP(UNRESOLVED_NEIGH, EXCEPTION),
	MLXDEVM_TRAP(RPF, EXCEPTION),
	MLXDEVM_TRAP(REJECT_ROUTE, EXCEPTION),
	MLXDEVM_TRAP(IPV4_LPM_UNICAST_MISS, EXCEPTION),
	MLXDEVM_TRAP(IPV6_LPM_UNICAST_MISS, EXCEPTION),
	MLXDEVM_TRAP(NON_ROUTABLE, DROP),
	MLXDEVM_TRAP(DECAP_ERROR, EXCEPTION),
	MLXDEVM_TRAP(OVERLAY_SMAC_MC, DROP),
	MLXDEVM_TRAP(INGRESS_FLOW_ACTION_DROP, DROP),
	MLXDEVM_TRAP(EGRESS_FLOW_ACTION_DROP, DROP),
	MLXDEVM_TRAP(STP, CONTROL),
	MLXDEVM_TRAP(LACP, CONTROL),
	MLXDEVM_TRAP(LLDP, CONTROL),
	MLXDEVM_TRAP(IGMP_QUERY, CONTROL),
	MLXDEVM_TRAP(IGMP_V1_REPORT, CONTROL),
	MLXDEVM_TRAP(IGMP_V2_REPORT, CONTROL),
	MLXDEVM_TRAP(IGMP_V3_REPORT, CONTROL),
	MLXDEVM_TRAP(IGMP_V2_LEAVE, CONTROL),
	MLXDEVM_TRAP(MLD_QUERY, CONTROL),
	MLXDEVM_TRAP(MLD_V1_REPORT, CONTROL),
	MLXDEVM_TRAP(MLD_V2_REPORT, CONTROL),
	MLXDEVM_TRAP(MLD_V1_DONE, CONTROL),
	MLXDEVM_TRAP(IPV4_DHCP, CONTROL),
	MLXDEVM_TRAP(IPV6_DHCP, CONTROL),
	MLXDEVM_TRAP(ARP_REQUEST, CONTROL),
	MLXDEVM_TRAP(ARP_RESPONSE, CONTROL),
	MLXDEVM_TRAP(ARP_OVERLAY, CONTROL),
	MLXDEVM_TRAP(IPV6_NEIGH_SOLICIT, CONTROL),
	MLXDEVM_TRAP(IPV6_NEIGH_ADVERT, CONTROL),
	MLXDEVM_TRAP(IPV4_BFD, CONTROL),
	MLXDEVM_TRAP(IPV6_BFD, CONTROL),
	MLXDEVM_TRAP(IPV4_OSPF, CONTROL),
	MLXDEVM_TRAP(IPV6_OSPF, CONTROL),
	MLXDEVM_TRAP(IPV4_BGP, CONTROL),
	MLXDEVM_TRAP(IPV6_BGP, CONTROL),
	MLXDEVM_TRAP(IPV4_VRRP, CONTROL),
	MLXDEVM_TRAP(IPV6_VRRP, CONTROL),
	MLXDEVM_TRAP(IPV4_PIM, CONTROL),
	MLXDEVM_TRAP(IPV6_PIM, CONTROL),
	MLXDEVM_TRAP(UC_LB, CONTROL),
	MLXDEVM_TRAP(LOCAL_ROUTE, CONTROL),
	MLXDEVM_TRAP(EXTERNAL_ROUTE, CONTROL),
	MLXDEVM_TRAP(IPV6_UC_DIP_LINK_LOCAL_SCOPE, CONTROL),
	MLXDEVM_TRAP(IPV6_DIP_ALL_NODES, CONTROL),
	MLXDEVM_TRAP(IPV6_DIP_ALL_ROUTERS, CONTROL),
	MLXDEVM_TRAP(IPV6_ROUTER_SOLICIT, CONTROL),
	MLXDEVM_TRAP(IPV6_ROUTER_ADVERT, CONTROL),
	MLXDEVM_TRAP(IPV6_REDIRECT, CONTROL),
	MLXDEVM_TRAP(IPV4_ROUTER_ALERT, CONTROL),
	MLXDEVM_TRAP(IPV6_ROUTER_ALERT, CONTROL),
	MLXDEVM_TRAP(PTP_EVENT, CONTROL),
	MLXDEVM_TRAP(PTP_GENERAL, CONTROL),
	MLXDEVM_TRAP(FLOW_ACTION_SAMPLE, CONTROL),
	MLXDEVM_TRAP(FLOW_ACTION_TRAP, CONTROL),
	MLXDEVM_TRAP(EARLY_DROP, DROP),
	MLXDEVM_TRAP(VXLAN_PARSING, DROP),
	MLXDEVM_TRAP(LLC_SNAP_PARSING, DROP),
	MLXDEVM_TRAP(VLAN_PARSING, DROP),
	MLXDEVM_TRAP(PPPOE_PPP_PARSING, DROP),
	MLXDEVM_TRAP(MPLS_PARSING, DROP),
	MLXDEVM_TRAP(ARP_PARSING, DROP),
	MLXDEVM_TRAP(IP_1_PARSING, DROP),
	MLXDEVM_TRAP(IP_N_PARSING, DROP),
	MLXDEVM_TRAP(GRE_PARSING, DROP),
	MLXDEVM_TRAP(UDP_PARSING, DROP),
	MLXDEVM_TRAP(TCP_PARSING, DROP),
	MLXDEVM_TRAP(IPSEC_PARSING, DROP),
	MLXDEVM_TRAP(SCTP_PARSING, DROP),
	MLXDEVM_TRAP(DCCP_PARSING, DROP),
	MLXDEVM_TRAP(GTP_PARSING, DROP),
	MLXDEVM_TRAP(ESP_PARSING, DROP),
	MLXDEVM_TRAP(BLACKHOLE_NEXTHOP, DROP),
	MLXDEVM_TRAP(DMAC_FILTER, DROP),
	MLXDEVM_TRAP(EAPOL, CONTROL),
	MLXDEVM_TRAP(LOCKED_PORT, DROP),
};

#define MLXDEVM_TRAP_GROUP(_id)						      \
	{								      \
		.id = MLXDEVM_TRAP_GROUP_GENERIC_ID_##_id,		      \
		.name = MLXDEVM_TRAP_GROUP_GENERIC_NAME_##_id,		      \
	}

static const struct mlxdevm_trap_group mlxdevm_trap_group_generic[] = {
	MLXDEVM_TRAP_GROUP(L2_DROPS),
	MLXDEVM_TRAP_GROUP(L3_DROPS),
	MLXDEVM_TRAP_GROUP(L3_EXCEPTIONS),
	MLXDEVM_TRAP_GROUP(BUFFER_DROPS),
	MLXDEVM_TRAP_GROUP(TUNNEL_DROPS),
	MLXDEVM_TRAP_GROUP(ACL_DROPS),
	MLXDEVM_TRAP_GROUP(STP),
	MLXDEVM_TRAP_GROUP(LACP),
	MLXDEVM_TRAP_GROUP(LLDP),
	MLXDEVM_TRAP_GROUP(MC_SNOOPING),
	MLXDEVM_TRAP_GROUP(DHCP),
	MLXDEVM_TRAP_GROUP(NEIGH_DISCOVERY),
	MLXDEVM_TRAP_GROUP(BFD),
	MLXDEVM_TRAP_GROUP(OSPF),
	MLXDEVM_TRAP_GROUP(BGP),
	MLXDEVM_TRAP_GROUP(VRRP),
	MLXDEVM_TRAP_GROUP(PIM),
	MLXDEVM_TRAP_GROUP(UC_LB),
	MLXDEVM_TRAP_GROUP(LOCAL_DELIVERY),
	MLXDEVM_TRAP_GROUP(EXTERNAL_DELIVERY),
	MLXDEVM_TRAP_GROUP(IPV6),
	MLXDEVM_TRAP_GROUP(PTP_EVENT),
	MLXDEVM_TRAP_GROUP(PTP_GENERAL),
	MLXDEVM_TRAP_GROUP(ACL_SAMPLE),
	MLXDEVM_TRAP_GROUP(ACL_TRAP),
	MLXDEVM_TRAP_GROUP(PARSER_ERROR_DROPS),
	MLXDEVM_TRAP_GROUP(EAPOL),
};

static int mlxdevm_trap_generic_verify(const struct mlxdevm_trap *trap)
{
	if (trap->id > MLXDEVM_TRAP_GENERIC_ID_MAX)
		return -EINVAL;

	if (strcmp(trap->name, mlxdevm_trap_generic[trap->id].name))
		return -EINVAL;

	if (trap->type != mlxdevm_trap_generic[trap->id].type)
		return -EINVAL;

	return 0;
}

static int mlxdevm_trap_driver_verify(const struct mlxdevm_trap *trap)
{
	int i;

	if (trap->id <= MLXDEVM_TRAP_GENERIC_ID_MAX)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(mlxdevm_trap_generic); i++) {
		if (!strcmp(trap->name, mlxdevm_trap_generic[i].name))
			return -EEXIST;
	}

	return 0;
}

static int mlxdevm_trap_verify(const struct mlxdevm_trap *trap)
{
	if (!trap || !trap->name)
		return -EINVAL;

	if (trap->generic)
		return mlxdevm_trap_generic_verify(trap);
	else
		return mlxdevm_trap_driver_verify(trap);
}

static int
mlxdevm_trap_group_generic_verify(const struct mlxdevm_trap_group *group)
{
	if (group->id > MLXDEVM_TRAP_GROUP_GENERIC_ID_MAX)
		return -EINVAL;

	if (strcmp(group->name, mlxdevm_trap_group_generic[group->id].name))
		return -EINVAL;

	return 0;
}

static int
mlxdevm_trap_group_driver_verify(const struct mlxdevm_trap_group *group)
{
	int i;

	if (group->id <= MLXDEVM_TRAP_GROUP_GENERIC_ID_MAX)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(mlxdevm_trap_group_generic); i++) {
		if (!strcmp(group->name, mlxdevm_trap_group_generic[i].name))
			return -EEXIST;
	}

	return 0;
}

static int mlxdevm_trap_group_verify(const struct mlxdevm_trap_group *group)
{
	if (group->generic)
		return mlxdevm_trap_group_generic_verify(group);
	else
		return mlxdevm_trap_group_driver_verify(group);
}

static void
mlxdevm_trap_group_notify(struct mlxdevm *mlxdevm,
			  const struct mlxdevm_trap_group_item *group_item,
			  enum mlxdevm_command cmd)
{
	struct sk_buff *msg;
	int err;

	WARN_ON_ONCE(cmd != MLXDEVM_CMD_TRAP_GROUP_NEW &&
		     cmd != MLXDEVM_CMD_TRAP_GROUP_DEL);

	if (!devm_is_registered(mlxdevm) || !mlxdevm_nl_notify_need(mlxdevm))
		return;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	err = mlxdevm_nl_trap_group_fill(msg, mlxdevm, group_item, cmd, 0, 0,
					 0);
	if (err) {
		nlmsg_free(msg);
		return;
	}

	mlxdevm_nl_notify_send(mlxdevm, msg);
}
#ifdef HAVE_BLOCKED_DEVLINK_CODE

void devlink_trap_groups_notify_register(struct devlink *devlink)
{
	struct devlink_trap_group_item *group_item;

	list_for_each_entry(group_item, &devlink->trap_group_list, list)
		devlink_trap_group_notify(devlink, group_item,
					  DEVLINK_CMD_TRAP_GROUP_NEW);
}

void devlink_trap_groups_notify_unregister(struct devlink *devlink)
{
	struct devlink_trap_group_item *group_item;

	list_for_each_entry_reverse(group_item, &devlink->trap_group_list, list)
		devlink_trap_group_notify(devlink, group_item,
					  DEVLINK_CMD_TRAP_GROUP_DEL);
}
#endif

static int
mlxdevm_trap_item_group_link(struct mlxdevm *mlxdevm,
			     struct mlxdevm_trap_item *trap_item)
{
	u16 group_id = trap_item->trap->init_group_id;
	struct mlxdevm_trap_group_item *group_item;

	group_item = mlxdevm_trap_group_item_lookup_by_id(mlxdevm, group_id);
	if (WARN_ON_ONCE(!group_item))
		return -EINVAL;

	trap_item->group_item = group_item;

	return 0;
}

static void mlxdevm_trap_notify(struct mlxdevm *mlxdevm,
				const struct mlxdevm_trap_item *trap_item,
				enum mlxdevm_command cmd)
{
	struct sk_buff *msg;
	int err;

	WARN_ON_ONCE(cmd != MLXDEVM_CMD_TRAP_NEW &&
		     cmd != MLXDEVM_CMD_TRAP_DEL);

	if (!devm_is_registered(mlxdevm) || !mlxdevm_nl_notify_need(mlxdevm))
		return;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	err = mlxdevm_nl_trap_fill(msg, mlxdevm, trap_item, cmd, 0, 0, 0);
	if (err) {
		nlmsg_free(msg);
		return;
	}

	mlxdevm_nl_notify_send(mlxdevm, msg);
}
#ifdef HAVE_BLOCKED_DEVLINK_CODE

void devlink_traps_notify_register(struct devlink *devlink)
{
	struct devlink_trap_item *trap_item;

	list_for_each_entry(trap_item, &devlink->trap_list, list)
		devlink_trap_notify(devlink, trap_item, DEVLINK_CMD_TRAP_NEW);
}

void devlink_traps_notify_unregister(struct devlink *devlink)
{
	struct devlink_trap_item *trap_item;

	list_for_each_entry_reverse(trap_item, &devlink->trap_list, list)
		devlink_trap_notify(devlink, trap_item, DEVLINK_CMD_TRAP_DEL);
}
#endif

static int
mlxdevm_trap_register(struct mlxdevm *mlxdevm,
		      const struct mlxdevm_trap *trap, void *priv)
{
	struct mlxdevm_trap_item *trap_item;
	int err;

	if (mlxdevm_trap_item_lookup(mlxdevm, trap->name))
		return -EEXIST;

	trap_item = kzalloc(sizeof(*trap_item), GFP_KERNEL);
	if (!trap_item)
		return -ENOMEM;

	trap_item->stats = netdev_alloc_pcpu_stats(struct mlxdevm_stats);
	if (!trap_item->stats) {
		err = -ENOMEM;
		goto err_stats_alloc;
	}

	trap_item->trap = trap;
	trap_item->action = trap->init_action;
	trap_item->priv = priv;

	err = mlxdevm_trap_item_group_link(mlxdevm, trap_item);
	if (err)
		goto err_group_link;

	err = mlxdevm->ops->trap_init(mlxdevm, trap, trap_item);
	if (err)
		goto err_trap_init;

	list_add_tail(&trap_item->list, &mlxdevm->trap_list);
	mlxdevm_trap_notify(mlxdevm, trap_item, MLXDEVM_CMD_TRAP_NEW);

	return 0;

err_trap_init:
err_group_link:
	free_percpu(trap_item->stats);
err_stats_alloc:
	kfree(trap_item);
	return err;
}

static void mlxdevm_trap_unregister(struct mlxdevm *mlxdevm,
				    const struct mlxdevm_trap *trap)
{
	struct mlxdevm_trap_item *trap_item;

	trap_item = mlxdevm_trap_item_lookup(mlxdevm, trap->name);
	if (WARN_ON_ONCE(!trap_item))
		return;

	mlxdevm_trap_notify(mlxdevm, trap_item, MLXDEVM_CMD_TRAP_DEL);
	list_del(&trap_item->list);
	if (mlxdevm->ops->trap_fini)
		mlxdevm->ops->trap_fini(mlxdevm, trap, trap_item);
	free_percpu(trap_item->stats);
	kfree(trap_item);
}

static void mlxdevm_trap_disable(struct mlxdevm *mlxdevm,
				 const struct mlxdevm_trap *trap)
{
	struct mlxdevm_trap_item *trap_item;

	trap_item = mlxdevm_trap_item_lookup(mlxdevm, trap->name);
	if (WARN_ON_ONCE(!trap_item))
		return;

	mlxdevm->ops->trap_action_set(mlxdevm, trap, MLXDEVM_TRAP_ACTION_DROP,
				      NULL);
	trap_item->action = MLXDEVM_TRAP_ACTION_DROP;
}

/**
 * devm_traps_register - Register packet traps with mlxdevm.
 * @mlxdevm: mlxdevm.
 * @traps: Packet traps.
 * @traps_count: Count of provided packet traps.
 * @priv: Driver private information.
 *
 * Return: Non-zero value on failure.
 */
int devm_traps_register(struct mlxdevm *mlxdevm,
			const struct mlxdevm_trap *traps,
			size_t traps_count, void *priv)
{
	int i, err;

	if (!mlxdevm->ops->trap_init || !mlxdevm->ops->trap_action_set)
		return -EINVAL;

	devm_assert_locked(mlxdevm);
	for (i = 0; i < traps_count; i++) {
		const struct mlxdevm_trap *trap = &traps[i];

		err = mlxdevm_trap_verify(trap);
		if (err)
			goto err_trap_verify;

		err = mlxdevm_trap_register(mlxdevm, trap, priv);
		if (err)
			goto err_trap_register;
	}

	return 0;

err_trap_register:
err_trap_verify:
	for (i--; i >= 0; i--)
		mlxdevm_trap_unregister(mlxdevm, &traps[i]);
	return err;
}
EXPORT_SYMBOL_GPL(devm_traps_register);
#ifdef HAVE_BLOCKED_DEVLINK_CODE

/**
 * devlink_traps_register - Register packet traps with devlink.
 * @devlink: devlink.
 * @traps: Packet traps.
 * @traps_count: Count of provided packet traps.
 * @priv: Driver private information.
 *
 * Context: Takes and release devlink->lock <mutex>.
 *
 * Return: Non-zero value on failure.
 */
int devlink_traps_register(struct devlink *devlink,
			   const struct devlink_trap *traps,
			   size_t traps_count, void *priv)
{
	int err;

	devl_lock(devlink);
	err = devl_traps_register(devlink, traps, traps_count, priv);
	devl_unlock(devlink);
	return err;
}
EXPORT_SYMBOL_GPL(devlink_traps_register);
#endif

/**
 * devm_traps_unregister - Unregister packet traps from mlxdevm.
 * @mlxdevm: mlxdevm.
 * @traps: Packet traps.
 * @traps_count: Count of provided packet traps.
 */
void devm_traps_unregister(struct mlxdevm *mlxdevm,
			   const struct mlxdevm_trap *traps,
			   size_t traps_count)
{
	int i;

	devm_assert_locked(mlxdevm);
	/* Make sure we do not have any packets in-flight while unregistering
	 * traps by disabling all of them and waiting for a grace period.
	 */
	for (i = traps_count - 1; i >= 0; i--)
		mlxdevm_trap_disable(mlxdevm, &traps[i]);
	synchronize_rcu();
	for (i = traps_count - 1; i >= 0; i--)
		mlxdevm_trap_unregister(mlxdevm, &traps[i]);
}
EXPORT_SYMBOL_GPL(devm_traps_unregister);
#ifdef HAVE_BLOCKED_DEVLINK_CODE

/**
 * devlink_traps_unregister - Unregister packet traps from devlink.
 * @devlink: devlink.
 * @traps: Packet traps.
 * @traps_count: Count of provided packet traps.
 *
 * Context: Takes and release devlink->lock <mutex>.
 */
void devlink_traps_unregister(struct devlink *devlink,
			      const struct devlink_trap *traps,
			      size_t traps_count)
{
	devl_lock(devlink);
	devl_traps_unregister(devlink, traps, traps_count);
	devl_unlock(devlink);
}
EXPORT_SYMBOL_GPL(devlink_traps_unregister);

static void
devlink_trap_stats_update(struct devlink_stats __percpu *trap_stats,
			  size_t skb_len)
{
	struct devlink_stats *stats;

	stats = this_cpu_ptr(trap_stats);
	u64_stats_update_begin(&stats->syncp);
	u64_stats_add(&stats->rx_bytes, skb_len);
	u64_stats_inc(&stats->rx_packets);
	u64_stats_update_end(&stats->syncp);
}

static void
devlink_trap_report_metadata_set(struct devlink_trap_metadata *metadata,
				 const struct devlink_trap_item *trap_item,
				 struct devlink_port *in_devlink_port,
				 const struct flow_action_cookie *fa_cookie)
{
	metadata->trap_name = trap_item->trap->name;
	metadata->trap_group_name = trap_item->group_item->group->name;
	metadata->fa_cookie = fa_cookie;
	metadata->trap_type = trap_item->trap->type;

	spin_lock(&in_devlink_port->type_lock);
	if (in_devlink_port->type == DEVLINK_PORT_TYPE_ETH)
		metadata->input_dev = in_devlink_port->type_eth.netdev;
	spin_unlock(&in_devlink_port->type_lock);
}

/**
 * devlink_trap_report - Report trapped packet to drop monitor.
 * @devlink: devlink.
 * @skb: Trapped packet.
 * @trap_ctx: Trap context.
 * @in_devlink_port: Input devlink port.
 * @fa_cookie: Flow action cookie. Could be NULL.
 */
void devlink_trap_report(struct devlink *devlink, struct sk_buff *skb,
			 void *trap_ctx, struct devlink_port *in_devlink_port,
			 const struct flow_action_cookie *fa_cookie)

{
	struct devlink_trap_item *trap_item = trap_ctx;

	devlink_trap_stats_update(trap_item->stats, skb->len);
	devlink_trap_stats_update(trap_item->group_item->stats, skb->len);

	if (tracepoint_enabled(devlink_trap_report)) {
		struct devlink_trap_metadata metadata = {};

		devlink_trap_report_metadata_set(&metadata, trap_item,
						 in_devlink_port, fa_cookie);
		trace_devlink_trap_report(devlink, skb, &metadata);
	}
}
EXPORT_SYMBOL_GPL(devlink_trap_report);

/**
 * devlink_trap_ctx_priv - Trap context to driver private information.
 * @trap_ctx: Trap context.
 *
 * Return: Driver private information passed during registration.
 */
void *devlink_trap_ctx_priv(void *trap_ctx)
{
	struct devlink_trap_item *trap_item = trap_ctx;

	return trap_item->priv;
}
EXPORT_SYMBOL_GPL(devlink_trap_ctx_priv);
#endif

static int
mlxdevm_trap_group_item_policer_link(struct mlxdevm *mlxdevm,
				     struct mlxdevm_trap_group_item *group_item)
{
	u32 policer_id = group_item->group->init_policer_id;
	struct mlxdevm_trap_policer_item *policer_item;

	if (policer_id == 0)
		return 0;

	policer_item = mlxdevm_trap_policer_item_lookup(mlxdevm, policer_id);
	if (WARN_ON_ONCE(!policer_item))
		return -EINVAL;

	group_item->policer_item = policer_item;

	return 0;
}

static int
mlxdevm_trap_group_register(struct mlxdevm *mlxdevm,
			    const struct mlxdevm_trap_group *group)
{
	struct mlxdevm_trap_group_item *group_item;
	int err;

	if (mlxdevm_trap_group_item_lookup(mlxdevm, group->name))
		return -EEXIST;

	group_item = kzalloc(sizeof(*group_item), GFP_KERNEL);
	if (!group_item)
		return -ENOMEM;

	group_item->stats = netdev_alloc_pcpu_stats(struct mlxdevm_stats);
	if (!group_item->stats) {
		err = -ENOMEM;
		goto err_stats_alloc;
	}

	group_item->group = group;

	err = mlxdevm_trap_group_item_policer_link(mlxdevm, group_item);
	if (err)
		goto err_policer_link;

	if (mlxdevm->ops->trap_group_init) {
		err = mlxdevm->ops->trap_group_init(mlxdevm, group);
		if (err)
			goto err_group_init;
	}

	list_add_tail(&group_item->list, &mlxdevm->trap_group_list);
	mlxdevm_trap_group_notify(mlxdevm, group_item,
				  MLXDEVM_CMD_TRAP_GROUP_NEW);

	return 0;

err_group_init:
err_policer_link:
	free_percpu(group_item->stats);
err_stats_alloc:
	kfree(group_item);
	return err;
}

static void
mlxdevm_trap_group_unregister(struct mlxdevm *mlxdevm,
			      const struct mlxdevm_trap_group *group)
{
	struct mlxdevm_trap_group_item *group_item;

	group_item = mlxdevm_trap_group_item_lookup(mlxdevm, group->name);
	if (WARN_ON_ONCE(!group_item))
		return;

	mlxdevm_trap_group_notify(mlxdevm, group_item,
				  MLXDEVM_CMD_TRAP_GROUP_DEL);
	list_del(&group_item->list);
	free_percpu(group_item->stats);
	kfree(group_item);
}

/**
 * devl_trap_groups_register - Register packet trap groups with mlxdevm.
 * @mlxdevm: mlxdevm.
 * @groups: Packet trap groups.
 * @groups_count: Count of provided packet trap groups.
 *
 * Return: Non-zero value on failure.
 */
int devm_trap_groups_register(struct mlxdevm *mlxdevm,
			      const struct mlxdevm_trap_group *groups,
			      size_t groups_count)
{
	int i, err;

	devm_assert_locked(mlxdevm);
	for (i = 0; i < groups_count; i++) {
		const struct mlxdevm_trap_group *group = &groups[i];

		err = mlxdevm_trap_group_verify(group);
		if (err)
			goto err_trap_group_verify;

		err = mlxdevm_trap_group_register(mlxdevm, group);
		if (err)
			goto err_trap_group_register;
	}

	return 0;

err_trap_group_register:
err_trap_group_verify:
	for (i--; i >= 0; i--)
		mlxdevm_trap_group_unregister(mlxdevm, &groups[i]);
	return err;
}
EXPORT_SYMBOL_GPL(devm_trap_groups_register);
#ifdef HAVE_BLOCKED_DEVLINK_CODE

/**
 * devlink_trap_groups_register - Register packet trap groups with devlink.
 * @devlink: devlink.
 * @groups: Packet trap groups.
 * @groups_count: Count of provided packet trap groups.
 *
 * Context: Takes and release devlink->lock <mutex>.
 *
 * Return: Non-zero value on failure.
 */
int devlink_trap_groups_register(struct devlink *devlink,
				 const struct devlink_trap_group *groups,
				 size_t groups_count)
{
	int err;

	devl_lock(devlink);
	err = devl_trap_groups_register(devlink, groups, groups_count);
	devl_unlock(devlink);
	return err;
}
EXPORT_SYMBOL_GPL(devlink_trap_groups_register);
#endif

/**
 * devm_trap_groups_unregister - Unregister packet trap groups from mlxdevm.
 * @mlxdevm: mlxdevm.
 * @groups: Packet trap groups.
 * @groups_count: Count of provided packet trap groups.
 */
void devm_trap_groups_unregister(struct mlxdevm *mlxdevm,
				 const struct mlxdevm_trap_group *groups,
				 size_t groups_count)
{
	int i;

	devm_assert_locked(mlxdevm);
	for (i = groups_count - 1; i >= 0; i--)
		mlxdevm_trap_group_unregister(mlxdevm, &groups[i]);
}
EXPORT_SYMBOL_GPL(devm_trap_groups_unregister);
#ifdef HAVE_BLOCKED_DEVLINK_CODE

/**
 * devlink_trap_groups_unregister - Unregister packet trap groups from devlink.
 * @devlink: devlink.
 * @groups: Packet trap groups.
 * @groups_count: Count of provided packet trap groups.
 *
 * Context: Takes and release devlink->lock <mutex>.
 */
void devlink_trap_groups_unregister(struct devlink *devlink,
				    const struct devlink_trap_group *groups,
				    size_t groups_count)
{
	devl_lock(devlink);
	devl_trap_groups_unregister(devlink, groups, groups_count);
	devl_unlock(devlink);
}
EXPORT_SYMBOL_GPL(devlink_trap_groups_unregister);

static void
devlink_trap_policer_notify(struct devlink *devlink,
			    const struct devlink_trap_policer_item *policer_item,
			    enum devlink_command cmd)
{
	struct sk_buff *msg;
	int err;

	WARN_ON_ONCE(cmd != DEVLINK_CMD_TRAP_POLICER_NEW &&
		     cmd != DEVLINK_CMD_TRAP_POLICER_DEL);

	if (!devl_is_registered(devlink) || !devlink_nl_notify_need(devlink))
		return;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	err = devlink_nl_trap_policer_fill(msg, devlink, policer_item, cmd, 0,
					   0, 0);
	if (err) {
		nlmsg_free(msg);
		return;
	}

	devlink_nl_notify_send(devlink, msg);
}

void devlink_trap_policers_notify_register(struct devlink *devlink)
{
	struct devlink_trap_policer_item *policer_item;

	list_for_each_entry(policer_item, &devlink->trap_policer_list, list)
		devlink_trap_policer_notify(devlink, policer_item,
					    DEVLINK_CMD_TRAP_POLICER_NEW);
}

void devlink_trap_policers_notify_unregister(struct devlink *devlink)
{
	struct devlink_trap_policer_item *policer_item;

	list_for_each_entry_reverse(policer_item, &devlink->trap_policer_list,
				    list)
		devlink_trap_policer_notify(devlink, policer_item,
					    DEVLINK_CMD_TRAP_POLICER_DEL);
}

static int
devlink_trap_policer_register(struct devlink *devlink,
			      const struct devlink_trap_policer *policer)
{
	struct devlink_trap_policer_item *policer_item;
	int err;

	if (devlink_trap_policer_item_lookup(devlink, policer->id))
		return -EEXIST;

	policer_item = kzalloc(sizeof(*policer_item), GFP_KERNEL);
	if (!policer_item)
		return -ENOMEM;

	policer_item->policer = policer;
	policer_item->rate = policer->init_rate;
	policer_item->burst = policer->init_burst;

	if (devlink->ops->trap_policer_init) {
		err = devlink->ops->trap_policer_init(devlink, policer);
		if (err)
			goto err_policer_init;
	}

	list_add_tail(&policer_item->list, &devlink->trap_policer_list);
	devlink_trap_policer_notify(devlink, policer_item,
				    DEVLINK_CMD_TRAP_POLICER_NEW);

	return 0;

err_policer_init:
	kfree(policer_item);
	return err;
}

static void
devlink_trap_policer_unregister(struct devlink *devlink,
				const struct devlink_trap_policer *policer)
{
	struct devlink_trap_policer_item *policer_item;

	policer_item = devlink_trap_policer_item_lookup(devlink, policer->id);
	if (WARN_ON_ONCE(!policer_item))
		return;

	devlink_trap_policer_notify(devlink, policer_item,
				    DEVLINK_CMD_TRAP_POLICER_DEL);
	list_del(&policer_item->list);
	if (devlink->ops->trap_policer_fini)
		devlink->ops->trap_policer_fini(devlink, policer);
	kfree(policer_item);
}

/**
 * devl_trap_policers_register - Register packet trap policers with devlink.
 * @devlink: devlink.
 * @policers: Packet trap policers.
 * @policers_count: Count of provided packet trap policers.
 *
 * Return: Non-zero value on failure.
 */
int
devl_trap_policers_register(struct devlink *devlink,
			    const struct devlink_trap_policer *policers,
			    size_t policers_count)
{
	int i, err;

	devl_assert_locked(devlink);
	for (i = 0; i < policers_count; i++) {
		const struct devlink_trap_policer *policer = &policers[i];

		if (WARN_ON(policer->id == 0 ||
			    policer->max_rate < policer->min_rate ||
			    policer->max_burst < policer->min_burst)) {
			err = -EINVAL;
			goto err_trap_policer_verify;
		}

		err = devlink_trap_policer_register(devlink, policer);
		if (err)
			goto err_trap_policer_register;
	}
	return 0;

err_trap_policer_register:
err_trap_policer_verify:
	for (i--; i >= 0; i--)
		devlink_trap_policer_unregister(devlink, &policers[i]);
	return err;
}
EXPORT_SYMBOL_GPL(devl_trap_policers_register);

/**
 * devl_trap_policers_unregister - Unregister packet trap policers from devlink.
 * @devlink: devlink.
 * @policers: Packet trap policers.
 * @policers_count: Count of provided packet trap policers.
 */
void
devl_trap_policers_unregister(struct devlink *devlink,
			      const struct devlink_trap_policer *policers,
			      size_t policers_count)
{
	int i;

	devl_assert_locked(devlink);
	for (i = policers_count - 1; i >= 0; i--)
		devlink_trap_policer_unregister(devlink, &policers[i]);
}
EXPORT_SYMBOL_GPL(devl_trap_policers_unregister);
#endif
