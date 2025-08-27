/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2016 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2016 Jiri Pirko <jiri@mellanox.com>
 */

#include <linux/device.h>
#include <linux/etherdevice.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>
#include <net/net_namespace.h>
#include <net/rtnetlink.h>
#include <rdma/ib_verbs.h>

#include "netlink_gen.h"
#include <net/mlxdevm.h>

struct devlink_rel;

#define MLXDEVM_REGISTERED XA_MARK_1

#define MLXDEVM_RELOAD_STATS_ARRAY_SIZE \
	(__MLXDEVM_RELOAD_LIMIT_MAX * __MLXDEVM_RELOAD_ACTION_MAX)

struct mlxdevm_dev_stats {
	u32 reload_stats[MLXDEVM_RELOAD_STATS_ARRAY_SIZE];
	u32 remote_reload_stats[MLXDEVM_RELOAD_STATS_ARRAY_SIZE];
};

struct mlxdevm {
	u32 index;
	struct xarray ports;
	struct list_head rate_list;
	struct list_head sb_list;
	struct list_head dpipe_table_list;
	struct list_head resource_list;
	struct xarray params;
	struct list_head region_list;
	struct list_head reporter_list;
	struct mlxdevm_dpipe_headers *dpipe_headers;
	struct list_head trap_list;
	struct list_head trap_group_list;
	struct list_head trap_policer_list;
	struct list_head linecard_list;
	const struct mlxdevm_ops *ops;
	struct xarray snapshot_ids;
	struct mlxdevm_dev_stats stats;
	struct device *dev;
	possible_net_t _net;
	/* Serializes access to devlink instance specific objects such as
	 * port, sb, dpipe, resource, params, region, traps and more.
	 */
	struct mutex lock;
	struct lock_class_key lock_key;
	u8 reload_failed:1;
	refcount_t refcount;
	struct rcu_work rwork;
	struct mlxdevm_rel *rel;
	struct xarray nested_rels;
	struct devlink *devlink;
	bool mlxdevm_flow;
	char priv[] __aligned(NETDEV_ALIGN);
};

extern struct xarray mlxdevms;
extern struct genl_family mlxdevm_nl_family;

/* devlink instances are open to the access from the user space after
 * devlink_register() call. Such logical barrier allows us to have certain
 * expectations related to locking.
 *
 * Before *_register() - we are in initialization stage and no parallel
 * access possible to the devlink instance. All drivers perform that phase
 * by implicitly holding device_lock.
 *
 * After *_register() - users and driver can access devlink instance at
 * the same time.
 */
#define ASSERT_MLXDEVM_REGISTERED(d)                                           \
	WARN_ON_ONCE(!xa_get_mark(&mlxdevms, (d)->index, MLXDEVM_REGISTERED))
#define ASSERT_MLXDEVM_NOT_REGISTERED(d)                                       \
	WARN_ON_ONCE(xa_get_mark(&mlxdevms, (d)->index, MLXDEVM_REGISTERED))

/* Iterate over mlxdevm pointers which were possible to get reference to.
 * mlxdevm_put() needs to be called for each iterated mlxdevm pointer
 * in loop body in order to release the reference.
 */
#define mlxdevms_xa_for_each_registered_get(net, index, mlxdevm)	\
	for (index = 0; (mlxdevm = mlxdevms_xa_find_get(net, &index)); index++)

struct mlxdevm *mlxdevms_xa_find_get(struct net *net, unsigned long *indexp);

static inline bool __devm_is_registered(struct mlxdevm *mlxdevm)
{
	return xa_get_mark(&mlxdevms, mlxdevm->index, MLXDEVM_REGISTERED);
}

static inline bool devm_is_registered(struct mlxdevm *mlxdevm)
{
	devm_assert_locked(mlxdevm);
	return __devm_is_registered(mlxdevm);
}

static inline void devm_dev_lock(struct mlxdevm *mlxdevm, bool dev_lock)
{
	if (dev_lock)
		device_lock(mlxdevm->dev);
	devm_lock(mlxdevm);
}

static inline void devm_dev_unlock(struct mlxdevm *mlxdevm, bool dev_lock)
{
	devm_unlock(mlxdevm);
	if (dev_lock)
		device_unlock(mlxdevm->dev);
}

typedef void mlxdevm_rel_notify_cb_t(struct mlxdevm *mlxdevm, u32 obj_index);
typedef void mlxdevm_rel_cleanup_cb_t(struct mlxdevm *mlxdevm, u32 obj_index,
				      u32 rel_index);

#ifdef HAVE_BLOCKED_DEVLINK_CODE
void devlink_rel_nested_in_clear(u32 rel_index);
int devlink_rel_nested_in_add(u32 *rel_index, u32 devlink_index,
			      u32 obj_index, devlink_rel_notify_cb_t *notify_cb,
			      devlink_rel_cleanup_cb_t *cleanup_cb,
			      struct devlink *devlink);
#endif
void mlxdevm_rel_nested_in_notify(struct mlxdevm *mlxdevm);
int mlxdevm_rel_mlxdevm_handle_put(struct sk_buff *msg, struct mlxdevm *mlxdevm,
				   u32 rel_index, int attrtype,
				   bool *msg_updated);

/* Netlink */
enum mlxdevm_multicast_groups {
	MLXDEVM_MCGRP_CONFIG,
};

/* state held across netlink dumps */
struct mlxdevm_nl_dump_state {
	unsigned long instance;
	int idx;
	union {
		/* MLXDEVM_CMD_REGION_READ */
		struct {
			u64 start_offset;
		};
		/* MLXDEVM_CMD_HEALTH_REPORTER_DUMP_GET */
		struct {
			u64 dump_ts;
		};
	};
};

typedef int mlxdevm_nl_dump_one_func_t(struct sk_buff *msg,
				       struct mlxdevm *mlxdevm,
				       struct netlink_callback *cb,
				       int flags);

struct mlxdevm *
mlxdevm_get_from_attrs_lock(struct net *net, struct nlattr **attrs,
			    bool dev_lock);

int mlxdevm_nl_dumpit(struct sk_buff *msg, struct netlink_callback *cb,
		      mlxdevm_nl_dump_one_func_t *dump_one);

static inline struct mlxdevm_nl_dump_state *
mlxdevm_dump_state(struct netlink_callback *cb)
{
	NL_ASSERT_CTX_FITS(struct mlxdevm_nl_dump_state);

	return (struct mlxdevm_nl_dump_state *)cb->ctx;
}

static inline int
mlxdevm_nl_put_handle(struct sk_buff *msg, struct mlxdevm *mlxdevm)
{
	if (nla_put_string(msg, MLXDEVM_ATTR_BUS_NAME, mlxdevm->dev->bus->name))
		return -EMSGSIZE;
	if (nla_put_string(msg, MLXDEVM_ATTR_DEV_NAME, dev_name(mlxdevm->dev)))
		return -EMSGSIZE;
	return 0;
}

static inline int mlxdevm_nl_put_u64(struct sk_buff *msg, int attrtype, u64 val)
{
	return nla_put_u64_64bit(msg, attrtype, val, MLXDEVM_ATTR_PAD);
}

int mlxdevm_nl_put_nested_handle(struct sk_buff *msg, struct net *net,
				 struct mlxdevm *mlxdevm, int attrtype);
int mlxdevm_nl_msg_reply_and_new(struct sk_buff **msg, struct genl_info *info);

static inline bool mlxdevm_nl_notify_need(struct mlxdevm *mlxdevm)
{
	return genl_has_listeners(&mlxdevm_nl_family, mlxdevm_net(mlxdevm),
				  MLXDEVM_MCGRP_CONFIG);
}

struct mlxdevm_obj_desc {
	struct rcu_head rcu;
	const char *bus_name;
	const char *dev_name;
	unsigned int port_index;
	bool port_index_valid;
	long data[];
};

static inline void mlxdevm_nl_obj_desc_init(struct mlxdevm_obj_desc *desc,
					    struct mlxdevm *mlxdevm)
{
	memset(desc, 0, sizeof(*desc));
	desc->bus_name = mlxdevm->dev->bus->name;
	desc->dev_name = dev_name(mlxdevm->dev);
}

static inline void mlxdevm_nl_obj_desc_port_set(struct mlxdevm_obj_desc *desc,
						struct mlxdevm_port *mlxdevm_port)
{
	desc->port_index = mlxdevm_port->index;
	desc->port_index_valid = true;
}

int mlxdevm_nl_notify_filter(struct sock *dsk, struct sk_buff *skb, void *data);

static inline void mlxdevm_nl_notify_send_desc(struct mlxdevm *mlxdevm,
					       struct sk_buff *msg,
					       struct mlxdevm_obj_desc *desc)
{
	genlmsg_multicast_netns_filtered(&mlxdevm_nl_family,
					 mlxdevm_net(mlxdevm),
					 msg, 0, MLXDEVM_MCGRP_CONFIG,
					 GFP_KERNEL,
					 mlxdevm_nl_notify_filter, desc);
}

static inline void mlxdevm_nl_notify_send(struct mlxdevm *mlxdevm,
					  struct sk_buff *msg)
{
	struct mlxdevm_obj_desc desc;

	mlxdevm_nl_obj_desc_init(&desc, mlxdevm);
	mlxdevm_nl_notify_send_desc(mlxdevm, msg, &desc);
}
#ifdef HAVE_BLOCKED_DEVLINK_CODE

/* Notify */
void devlink_notify_register(struct devlink *devlink);
void devlink_notify_unregister(struct devlink *devlink);
void devlink_ports_notify_register(struct devlink *devlink);
void devlink_ports_notify_unregister(struct devlink *devlink);
void devlink_params_notify_register(struct devlink *devlink);
void devlink_params_notify_unregister(struct devlink *devlink);
void devlink_regions_notify_register(struct devlink *devlink);
void devlink_regions_notify_unregister(struct devlink *devlink);
void devlink_trap_policers_notify_register(struct devlink *devlink);
void devlink_trap_policers_notify_unregister(struct devlink *devlink);
void devlink_trap_groups_notify_register(struct devlink *devlink);
void devlink_trap_groups_notify_unregister(struct devlink *devlink);
void devlink_traps_notify_register(struct devlink *devlink);
void devlink_traps_notify_unregister(struct devlink *devlink);
void devlink_rates_notify_register(struct devlink *devlink);
void devlink_rates_notify_unregister(struct devlink *devlink);
void devlink_linecards_notify_register(struct devlink *devlink);
void devlink_linecards_notify_unregister(struct devlink *devlink);

/* Ports */
#define ASSERT_DEVLINK_PORT_INITIALIZED(devlink_port)				\
	WARN_ON_ONCE(!(devlink_port)->initialized)
#endif

struct mlxdevm_port *mlxdevm_port_get_by_index(struct mlxdevm *mlxdevm,
					       unsigned int port_index);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
int devlink_port_netdevice_event(struct notifier_block *nb,
				 unsigned long event, void *ptr);
#endif
struct mlxdevm_port *
mlxdevm_port_get_from_info(struct mlxdevm *mlxdevm, struct genl_info *info);
struct mlxdevm_port *mlxdevm_port_get_from_attrs(struct mlxdevm *mlxdevm,
						 struct nlattr **attrs);
#ifdef HAVE_BLOCKED_DEVLINK_CODE

/* Reload */
bool devlink_reload_actions_valid(const struct devlink_ops *ops);
#endif
int mlxdevm_reload(struct mlxdevm *mlxdevm, struct net *dest_net,
		   enum mlxdevm_reload_action action,
		   enum mlxdevm_reload_limit limit,
		   u32 *actions_performed, struct netlink_ext_ack *extack);

static inline bool mlxdevm_reload_supported(const struct mlxdevm_ops *ops)
{
	return ops->reload_down && ops->reload_up;
}

/* Params */
void mlxdevm_params_driverinit_load_new(struct mlxdevm *mlxdevm);

/* Resources */
struct mlxdevm_resource;
int mlxdevm_resources_validate(struct mlxdevm *mlxdevm,
			       struct mlxdevm_resource *resource,
			       struct genl_info *info);

/* Rates */
int mlxdevm_rate_nodes_check(struct mlxdevm *mlxdevm, u16 mode,
			     struct netlink_ext_ack *extack);

/* Linecards */
unsigned int mlxdevm_linecard_index(struct mlxdevm_linecard *linecard);

/* mlxdevm global work queue replacing system_wq*/
bool mlxdevm_schedule_delayed_work(struct delayed_work *dwork, unsigned long delay);
