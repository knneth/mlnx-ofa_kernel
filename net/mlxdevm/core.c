// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2016 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2016 Jiri Pirko <jiri@mellanox.com>
 */

#include <net/genetlink.h>
#ifdef HAVE_BLOCKED_DEVLINK_CODE
#define CREATE_TRACE_POINTS
#include <trace/events/devlink.h>
#endif

MODULE_AUTHOR("Oren Sidi");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Nvidia's device manager module");
MODULE_INFO(supported, "external");

#include "devl_internal.h"
#ifdef HAVE_BLOCKED_DEVLINK_CODE

EXPORT_TRACEPOINT_SYMBOL_GPL(devlink_hwmsg);
EXPORT_TRACEPOINT_SYMBOL_GPL(devlink_hwerr);
EXPORT_TRACEPOINT_SYMBOL_GPL(devlink_trap_report);
#endif

DEFINE_XARRAY_FLAGS(mlxdevms, XA_FLAGS_ALLOC);
static struct workqueue_struct *mlxdevm_global_wq;

/**
 * schedule_delayed_work - put work task in global workqueue after delay
 * @dwork: job to be done
 * @delay: number of jiffies to wait or 0 for immediate execution
 *
 * After waiting for a given time this puts a job in the kernel-global
 * workqueue.
 */
bool mlxdevm_schedule_delayed_work(struct delayed_work *dwork, unsigned long delay)
{
	return queue_delayed_work(mlxdevm_global_wq, dwork, delay);
}

static struct mlxdevm *mlxdevms_xa_get(unsigned long index)
{
	struct mlxdevm *mlxdevm;

	rcu_read_lock();
	mlxdevm = xa_find(&mlxdevms, &index, index, MLXDEVM_REGISTERED);
	if (!mlxdevm || !mlxdevm_try_get(mlxdevm))
		mlxdevm = NULL;
	rcu_read_unlock();
	return mlxdevm;
}

/* mlxdevm_rels xarray contains 1:1 relationships between
 * mlxdevm object and related nested mlxdevm instance.
 * The xarray index is used to get the nested object from
 * the nested-in object code.
 */
static DEFINE_XARRAY_FLAGS(mlxdevm_rels, XA_FLAGS_ALLOC1);

#define MLXDEVM_REL_IN_USE XA_MARK_0

struct mlxdevm_rel {
	u32 index;
	refcount_t refcount;
	u32 mlxdevm_index;
	struct {
		u32 mlxdevm_index;
		u32 obj_index;
		mlxdevm_rel_notify_cb_t *notify_cb;
		mlxdevm_rel_cleanup_cb_t *cleanup_cb;
		struct delayed_work notify_work;
	} nested_in;
};
static void mlxdevm_rel_free(struct mlxdevm_rel *rel)
{
	xa_erase(&mlxdevm_rels, rel->index);
	kfree(rel);
}

static void __mlxdevm_rel_get(struct mlxdevm_rel *rel)
{
	refcount_inc(&rel->refcount);
}

static void __mlxdevm_rel_put(struct mlxdevm_rel *rel)
{
	if (refcount_dec_and_test(&rel->refcount))
		mlxdevm_rel_free(rel);
}

struct mlxdevm *__must_check mlxdevm_nested_in_get_lock(struct mlxdevm *mlxdevm)
{
	devm_assert_locked(mlxdevm);
	if (!mlxdevm->rel)
		return NULL;
	mlxdevm = mlxdevms_xa_get(mlxdevm->rel->nested_in.mlxdevm_index);
	if (!mlxdevm)
		return NULL;
	devm_lock(mlxdevm);
	if (devm_is_registered(mlxdevm))
		return mlxdevm;
	devm_unlock(mlxdevm);
	mlxdevm_put(mlxdevm);
	return NULL;
}

static void mlxdevm_rel_nested_in_notify_work(struct work_struct *work)
{
	struct mlxdevm_rel *rel = container_of(work, struct mlxdevm_rel,
					       nested_in.notify_work.work);
	struct mlxdevm *mlxdevm;

	mlxdevm = mlxdevms_xa_get(rel->nested_in.mlxdevm_index);
	if (!mlxdevm)
		goto rel_put;
	if (!devm_trylock(mlxdevm)) {
		mlxdevm_put(mlxdevm);
		goto reschedule_work;
	}
	if (!devm_is_registered(mlxdevm)) {
		devm_unlock(mlxdevm);
		mlxdevm_put(mlxdevm);
		goto rel_put;
	}
	if (!xa_get_mark(&mlxdevm_rels, rel->index, MLXDEVM_REL_IN_USE))
		rel->nested_in.cleanup_cb(mlxdevm, rel->nested_in.obj_index, rel->index);
	rel->nested_in.notify_cb(mlxdevm, rel->nested_in.obj_index);
	devm_unlock(mlxdevm);
	mlxdevm_put(mlxdevm);

rel_put:
	__mlxdevm_rel_put(rel);
	return;

reschedule_work:
	mlxdevm_schedule_delayed_work(&rel->nested_in.notify_work, 1);
}

static void mlxdevm_rel_nested_in_notify_work_schedule(struct mlxdevm_rel *rel)
{
	__mlxdevm_rel_get(rel);
	mlxdevm_schedule_delayed_work(&rel->nested_in.notify_work, 0);
}
static struct mlxdevm_rel *mlxdevm_rel_alloc(void)
{
	struct mlxdevm_rel *rel;
	static u32 next;
	int err;

	rel = kzalloc_obj(*rel);
	if (!rel)
		return ERR_PTR(-ENOMEM);

	err = xa_alloc_cyclic(&mlxdevm_rels, &rel->index, rel,
			      xa_limit_32b, &next, GFP_KERNEL);
	if (err < 0) {
		kfree(rel);
		return ERR_PTR(err);
	}

	refcount_set(&rel->refcount, 1);
	INIT_DELAYED_WORK(&rel->nested_in.notify_work,
			  &mlxdevm_rel_nested_in_notify_work);
	return rel;
}

static void mlxdevm_rel_put(struct mlxdevm *mlxdevm)
{
	struct mlxdevm_rel *rel = mlxdevm->rel;

	if (!rel)
		return;
	xa_clear_mark(&mlxdevm_rels, rel->index, MLXDEVM_REL_IN_USE);
	mlxdevm_rel_nested_in_notify_work_schedule(rel);
	__mlxdevm_rel_put(rel);
	mlxdevm->rel = NULL;
}
void mlxdevm_rel_nested_in_clear(u32 rel_index)
{
	xa_clear_mark(&mlxdevm_rels, rel_index, MLXDEVM_REL_IN_USE);
}

int mlxdevm_rel_nested_in_add(u32 *rel_index, u32 mlxdevm_index,
			      u32 obj_index, mlxdevm_rel_notify_cb_t *notify_cb,
			      mlxdevm_rel_cleanup_cb_t *cleanup_cb,
			      struct mlxdevm *mlxdevm)
{
	struct mlxdevm_rel *rel = mlxdevm_rel_alloc();

	ASSERT_MLXDEVM_NOT_REGISTERED(mlxdevm);

	if (IS_ERR(rel))
		return PTR_ERR(rel);

	rel->mlxdevm_index = mlxdevm->index;
	rel->nested_in.mlxdevm_index = mlxdevm_index;
	rel->nested_in.obj_index = obj_index;
	rel->nested_in.notify_cb = notify_cb;
	rel->nested_in.cleanup_cb = cleanup_cb;
	*rel_index = rel->index;
	xa_set_mark(&mlxdevm_rels, rel->index, MLXDEVM_REL_IN_USE);
	mlxdevm->rel = rel;
	return 0;
}

/**
 * mlxdevm_rel_nested_in_notify - Notify the object this mlxdevm
 *				  instance is nested in.
 * @mlxdevm: mlxdevm
 *
 * This is called upon network namespace change of mlxdevm instance.
 * In case this mlxdevm instance is nested in another mlxdevm object,
 * a notification of a change of this object should be sent
 * over netlink. The parent mlxdevm instance lock needs to be
 * taken during the notification preparation.
 * Since the parent may or may not be locked, 'work' is utilized.
 */
void mlxdevm_rel_nested_in_notify(struct mlxdevm *mlxdevm)
{
	struct mlxdevm_rel *rel = mlxdevm->rel;

	if (!rel)
		return;
	mlxdevm_rel_nested_in_notify_work_schedule(rel);
}

static struct mlxdevm_rel *mlxdevm_rel_find(unsigned long rel_index)
{
	return xa_find(&mlxdevm_rels, &rel_index, rel_index,
		       MLXDEVM_REL_IN_USE);
}

static struct mlxdevm *mlxdevm_rel_mlxdevm_get(u32 rel_index)
{
	struct mlxdevm_rel *rel;
	u32 mlxdevm_index;

	if (!rel_index)
		return NULL;
	xa_lock(&mlxdevm_rels);
	rel = mlxdevm_rel_find(rel_index);
	if (rel)
		mlxdevm_index = rel->mlxdevm_index;
	xa_unlock(&mlxdevm_rels);
	if (!rel)
		return NULL;
	return mlxdevms_xa_get(mlxdevm_index);
}

int mlxdevm_rel_mlxdevm_handle_put(struct sk_buff *msg, struct mlxdevm *mlxdevm,
				   u32 rel_index, int attrtype,
				   bool *msg_updated)
{
	struct net *net = mlxdevm_net(mlxdevm);
	struct mlxdevm *rel_mlxdevm;
	int err;

	rel_mlxdevm = mlxdevm_rel_mlxdevm_get(rel_index);
	if (!rel_mlxdevm)
		return 0;
	err = mlxdevm_nl_put_nested_handle(msg, net, rel_mlxdevm, attrtype);
	mlxdevm_put(rel_mlxdevm);
	if (!err && msg_updated)
		*msg_updated = true;
	return err;
}
void *mlxdevm_priv(struct mlxdevm *mlxdevm)
{
	return &mlxdevm->priv;
}
EXPORT_SYMBOL_GPL(mlxdevm_priv);

struct mlxdevm *priv_to_mlxdevm(void *priv)
{
	return container_of(priv, struct mlxdevm, priv);
}
EXPORT_SYMBOL_GPL(priv_to_mlxdevm);

struct device *mlxdevm_to_dev(const struct mlxdevm *mlxdevm)
{
	return mlxdevm->dev;
}
EXPORT_SYMBOL_GPL(mlxdevm_to_dev);

const char *mlxdevm_bus_name(const struct mlxdevm *mlxdevm)
{
	return mlxdevm->dev ? mlxdevm->dev->bus->name : MLXDEVM_INDEX_BUS_NAME;
}
EXPORT_SYMBOL_GPL(mlxdevm_bus_name);

const char *mlxdevm_dev_name(const struct mlxdevm *mlxdevm)
{
	return mlxdevm->dev ? dev_name(mlxdevm->dev) : mlxdevm->dev_name_index;
}
EXPORT_SYMBOL_GPL(mlxdevm_dev_name);
#ifdef HAVE_BLOCKED_DEVLINK_CODE

const char *devlink_dev_driver_name(const struct devlink *devlink)
{
	return devlink->dev_driver->name;
}
EXPORT_SYMBOL_GPL(devlink_dev_driver_name);
#endif

struct net *mlxdevm_net(const struct mlxdevm *mlxdevm)
{
	return read_pnet(&mlxdevm->_net);
}
EXPORT_SYMBOL_GPL(mlxdevm_net);

void devm_assert_locked(struct mlxdevm *mlxdevm)
{
	if (mlxdevm->devlink) {
		devl_assert_locked(mlxdevm->devlink);
		return;
	}
	lockdep_assert_held(&mlxdevm->lock);
}
EXPORT_SYMBOL_GPL(devm_assert_locked);
#ifdef HAVE_BLOCKED_DEVLINK_CODE

#ifdef CONFIG_LOCKDEP
/* For use in conjunction with LOCKDEP only e.g. rcu_dereference_protected() */
bool devl_lock_is_held(struct devlink *devlink)
{
	return lockdep_is_held(&devlink->lock);
}
EXPORT_SYMBOL_GPL(devl_lock_is_held);
#endif

#endif
void devm_lock(struct mlxdevm *mlxdevm)
{
	if (mlxdevm->devlink) {
		devl_lock(mlxdevm->devlink);
		return;
	}
	mutex_lock(&mlxdevm->lock);
}
EXPORT_SYMBOL_GPL(devm_lock);

#ifndef HAVE_DEVL_TRAP_GROUPS_REGISTER
int devm_trylock(struct mlxdevm *mlxdevm)
{
	if (mlxdevm->devlink)
		return devl_trylock(mlxdevm->devlink);
	return mutex_trylock(&mlxdevm->lock);
}
EXPORT_SYMBOL_GPL(devm_trylock);
#endif

void devm_unlock(struct mlxdevm *mlxdevm)
{
	if (mlxdevm->devlink) {
		devl_unlock(mlxdevm->devlink);
		return;
	}
	mutex_unlock(&mlxdevm->lock);
}
EXPORT_SYMBOL_GPL(devm_unlock);

/**
 * mlxdevm_try_get() - try to obtain a reference on a mlxdevm instance
 * @mlxdevm: instance to reference
 *
 * Obtain a reference on a mlxdevm instance. A reference on a mlxdevm instance
 * only implies that it's safe to take the instance lock. It does not imply
 * that the instance is registered, use devl_is_registered() after taking
 * the instance lock to check registration status.
 */
struct mlxdevm *__must_check mlxdevm_try_get(struct mlxdevm *mlxdevm)
{
	if (refcount_inc_not_zero(&mlxdevm->refcount))
		return mlxdevm;
	return NULL;
}

static void mlxdevm_release(struct work_struct *work)
{
	struct mlxdevm *mlxdevm;

	mlxdevm = container_of(to_rcu_work(work), struct mlxdevm, rwork);

	mutex_destroy(&mlxdevm->lock);
	lockdep_unregister_key(&mlxdevm->lock_key);
	if (mlxdevm->dev)
		put_device(mlxdevm->dev);
	else
		kfree(mlxdevm->dev_name_index);
	kvfree(mlxdevm);
}

void mlxdevm_put(struct mlxdevm *mlxdevm)
{
	if (refcount_dec_and_test(&mlxdevm->refcount))
		queue_rcu_work(mlxdevm_global_wq, &mlxdevm->rwork);
}
EXPORT_SYMBOL_GPL(mlxdevm_put);

static struct mlxdevm *__mlxdevms_xa_find_get(struct net *net,
					      unsigned long *indexp,
					      unsigned long end)
{
	struct mlxdevm *mlxdevm = NULL;

	rcu_read_lock();
retry:
	mlxdevm = xa_find(&mlxdevms, indexp, end, MLXDEVM_REGISTERED);
	if (!mlxdevm)
		goto unlock;

	if (!mlxdevm_try_get(mlxdevm))
		goto next;
	if (!net_eq(mlxdevm_net(mlxdevm), net)) {
		mlxdevm_put(mlxdevm);
		goto next;
	}
unlock:
	rcu_read_unlock();
	return mlxdevm;

next:
	(*indexp)++;
	goto retry;
}

struct mlxdevm *mlxdevms_xa_find_get(struct net *net, unsigned long *indexp)
{
	return __mlxdevms_xa_find_get(net, indexp, ULONG_MAX);
}

struct mlxdevm *mlxdevms_xa_lookup_get(struct net *net, unsigned long index)
{
	return __mlxdevms_xa_find_get(net, &index, index);
}

/**
 * devm_register - Register mlxdevm instance
 * @mlxdevm: mlxdevm
 */
int devm_register(struct mlxdevm *mlxdevm)
{
	ASSERT_MLXDEVM_NOT_REGISTERED(mlxdevm);
	devm_assert_locked(mlxdevm);

	xa_set_mark(&mlxdevms, mlxdevm->index, MLXDEVM_REGISTERED);
	//mlxdevm_notify_register(mlxdevm);
	mlxdevm_rel_nested_in_notify(mlxdevm);

	return 0;
}
EXPORT_SYMBOL_GPL(devm_register);

int mlxdevm_register(struct mlxdevm *mlxdevm)
{
	int err;

	if (mlxdevm->devlink)
		return devm_register(mlxdevm);
	devm_lock(mlxdevm);
	err = devm_register(mlxdevm);
	devm_unlock(mlxdevm);
	return err;
}
EXPORT_SYMBOL_GPL(mlxdevm_register);

/**
 * devm_unregister - Unregister mlxdevm instance
 * @mlxdevm: mlxdevm
 */
void devm_unregister(struct mlxdevm *mlxdevm)
{
	ASSERT_MLXDEVM_REGISTERED(mlxdevm);
	devm_assert_locked(mlxdevm);

	//mlxdevm_notify_unregister(mlxdevm);
	xa_clear_mark(&mlxdevms, mlxdevm->index, MLXDEVM_REGISTERED);
	mlxdevm_rel_put(mlxdevm);
}
EXPORT_SYMBOL_GPL(devm_unregister);

void mlxdevm_unregister(struct mlxdevm *mlxdevm)
{
	if (mlxdevm->devlink) {
		devm_unregister(mlxdevm);
		return;
	}
	devm_lock(mlxdevm);
	devm_unregister(mlxdevm);
	devm_unlock(mlxdevm);
}
EXPORT_SYMBOL_GPL(mlxdevm_unregister);
struct mlxdevm *__mlxdevm_alloc(const struct mlxdevm_ops *ops, size_t priv_size,
				struct net *net, struct device *dev,
				const struct device_driver *dev_driver)
{
	struct mlxdevm *mlxdevm;
	static u32 last_id;
	int ret;

	WARN_ON(!ops || !dev_driver);
	if (!mlxdevm_reload_actions_valid(ops))
		return NULL;

	mlxdevm = kvzalloc_flex(*mlxdevm, priv, priv_size);
	if (!mlxdevm)
		return NULL;

	ret = xa_alloc_cyclic(&mlxdevms, &mlxdevm->index, mlxdevm, xa_limit_31b,
			      &last_id, GFP_KERNEL);
	if (ret < 0)
		goto err_xa_alloc;

	if (dev) {
		mlxdevm->dev = get_device(dev);
	} else {
		mlxdevm->dev_name_index = kasprintf(GFP_KERNEL, "%u", mlxdevm->index);
		if (!mlxdevm->dev_name_index)
			goto err_kasprintf;
	}

	mlxdevm->ops = ops;
	mlxdevm->dev_driver = dev_driver;
	xa_init_flags(&mlxdevm->ports, XA_FLAGS_ALLOC);
	xa_init_flags(&mlxdevm->params, XA_FLAGS_ALLOC);
	xa_init_flags(&mlxdevm->snapshot_ids, XA_FLAGS_ALLOC);
	xa_init_flags(&mlxdevm->nested_rels, XA_FLAGS_ALLOC);
	write_pnet(&mlxdevm->_net, net);
	INIT_LIST_HEAD(&mlxdevm->rate_list);
	INIT_LIST_HEAD(&mlxdevm->linecard_list);
	INIT_LIST_HEAD(&mlxdevm->sb_list);
	INIT_LIST_HEAD_RCU(&mlxdevm->dpipe_table_list);
	INIT_LIST_HEAD(&mlxdevm->resource_list);
	INIT_LIST_HEAD(&mlxdevm->region_list);
	INIT_LIST_HEAD(&mlxdevm->reporter_list);
	INIT_LIST_HEAD(&mlxdevm->trap_list);
	INIT_LIST_HEAD(&mlxdevm->trap_group_list);
	INIT_LIST_HEAD(&mlxdevm->trap_policer_list);
	INIT_RCU_WORK(&mlxdevm->rwork, mlxdevm_release);
	lockdep_register_key(&mlxdevm->lock_key);
	mutex_init(&mlxdevm->lock);
	lockdep_set_class(&mlxdevm->lock, &mlxdevm->lock_key);
	refcount_set(&mlxdevm->refcount, 1);

	return mlxdevm;

err_kasprintf:
	xa_erase(&mlxdevms, mlxdevm->index);
err_xa_alloc:
	kvfree(mlxdevm);
	return NULL;
}

/**
 *	mlxdevm_alloc_ns - Allocate new mlxdevm instance resources
 *	in specific namespace
 *
 *	@ops: ops
 *	@priv_size: size of user private data
 *	@net: net namespace
 *	@dev: parent device
 *
 *	Allocate new mlxdevm instance resources, including mlxdevm index
 *	and name.
 */
struct mlxdevm *mlxdevm_alloc_ns(const struct mlxdevm_ops *ops,
				 size_t priv_size, struct net *net,
				 struct device *dev)
{
	WARN_ON(!dev);
	return __mlxdevm_alloc(ops, priv_size, net, dev, dev->driver);
}
EXPORT_SYMBOL_GPL(mlxdevm_alloc_ns);

/**
 *	mlxdevm_free - Free mlxdevm instance resources
 *
 *	@mlxdevm: mlxdevm
 */
void mlxdevm_free(struct mlxdevm *mlxdevm)
{
	ASSERT_MLXDEVM_NOT_REGISTERED(mlxdevm);

	devm_lock(mlxdevm);
	WARN_ON(mlxdevm_rates_check(mlxdevm, NULL, NULL));
	devm_unlock(mlxdevm);
	mlxdevm_rel_put(mlxdevm);

	WARN_ON(!list_empty(&mlxdevm->trap_policer_list));
	WARN_ON(!list_empty(&mlxdevm->trap_group_list));
	WARN_ON(!list_empty(&mlxdevm->trap_list));
	WARN_ON(!list_empty(&mlxdevm->reporter_list));
	WARN_ON(!list_empty(&mlxdevm->region_list));
	WARN_ON(!list_empty(&mlxdevm->resource_list));
	WARN_ON(!list_empty(&mlxdevm->dpipe_table_list));
	WARN_ON(!list_empty(&mlxdevm->sb_list));
	WARN_ON(!list_empty(&mlxdevm->linecard_list));
	WARN_ON(!xa_empty(&mlxdevm->ports));

	xa_destroy(&mlxdevm->nested_rels);
	xa_destroy(&mlxdevm->snapshot_ids);
	xa_destroy(&mlxdevm->params);
	xa_destroy(&mlxdevm->ports);

	xa_erase(&mlxdevms, mlxdevm->index);

	mlxdevm_put(mlxdevm);
}
EXPORT_SYMBOL_GPL(mlxdevm_free);
#ifdef HAVE_BLOCKED_DEVLINK_CODE

static void __net_exit devlink_pernet_pre_exit(struct net *net)
{
	struct devlink *devlink;
	u32 actions_performed;
	unsigned long index;
	int err;

	/* In case network namespace is getting destroyed, reload
	 * all devlink instances from this namespace into init_net.
	 */
	devlinks_xa_for_each_registered_get(net, index, devlink) {
		devl_dev_lock(devlink, true);
		err = 0;
		if (devl_is_registered(devlink))
			err = devlink_reload(devlink, &init_net,
					     DEVLINK_RELOAD_ACTION_DRIVER_REINIT,
					     DEVLINK_RELOAD_LIMIT_UNSPEC,
					     &actions_performed, NULL);
		devl_dev_unlock(devlink, true);
		devlink_put(devlink);
		if (err && err != -EOPNOTSUPP)
			pr_warn("Failed to reload devlink instance into init_net\n");
	}
}

static struct pernet_operations devlink_pernet_ops __net_initdata = {
	.pre_exit = devlink_pernet_pre_exit,
};

static struct notifier_block devlink_port_netdevice_nb = {
	.notifier_call = devlink_port_netdevice_event,
};

static int __init devlink_init(void)
{
	int err;

	err = register_pernet_subsys(&devlink_pernet_ops);
	if (err)
		goto out;
	err = genl_register_family(&devlink_nl_family);
	if (err)
		goto out_unreg_pernet_subsys;
	err = register_netdevice_notifier(&devlink_port_netdevice_nb);
	if (!err)
		return 0;

	genl_unregister_family(&devlink_nl_family);

out_unreg_pernet_subsys:
	unregister_pernet_subsys(&devlink_pernet_ops);
out:
	WARN_ON(err);
	return err;
}

subsys_initcall(devlink_init);
#endif

static int __init mlxdevm_init_module(void)
{
	char *wq_name = "mlxdevm global work queue";
	int err;

	mlxdevm_global_wq = alloc_workqueue(wq_name, 0, 0);
	if (!mlxdevm_global_wq)
		return -ENOMEM;

	err = genl_register_family(&mlxdevm_nl_family);
	if (err)
		destroy_workqueue(mlxdevm_global_wq);

	return err;

}

static void __exit mlxdevm_cleanup(void)
{
	genl_unregister_family(&mlxdevm_nl_family);
	flush_workqueue(mlxdevm_global_wq);
	destroy_workqueue(mlxdevm_global_wq);
}

module_init(mlxdevm_init_module);
module_exit(mlxdevm_cleanup);
