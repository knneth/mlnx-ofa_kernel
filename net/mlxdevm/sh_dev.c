// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include <net/devlink.h>

#include "devl_internal.h"

static LIST_HEAD(shd_list);
static DEFINE_MUTEX(shd_mutex); /* Protects shd_list and shd->list */

/* This structure represents a shared mlxdevm instance,
 * there is one created per identifier (e.g., serial number).
 */
struct mlxdevm_shd {
	struct list_head list; /* Node in shd list */
	const char *id; /* Identifier string (e.g., serial number) */
	refcount_t refcount; /* Reference count */
	size_t priv_size; /* Size of driver private data */
	char priv[] __aligned(NETDEV_ALIGN) __counted_by(priv_size);
};

static struct mlxdevm_shd *mlxdevm_shd_lookup(const char *id)
{
	struct mlxdevm_shd *shd;

	list_for_each_entry(shd, &shd_list, list) {
		if (!strcmp(shd->id, id))
			return shd;
	}

	return NULL;
}

static struct mlxdevm_shd *mlxdevm_shd_create(const char *id,
					      const struct mlxdevm_ops *ops,
					      size_t priv_size,
					      const struct device_driver *driver,
					      struct devlink *shd_devlink)
{
	struct mlxdevm_shd *shd;
	struct mlxdevm *mlxdevm;

	mlxdevm = __mlxdevm_alloc(ops, sizeof(struct mlxdevm_shd) + priv_size,
				  &init_net, NULL, driver);
	if (!mlxdevm)
		return NULL;
	shd = mlxdevm_priv(mlxdevm);

	shd->id = kstrdup(id, GFP_KERNEL);
	if (!shd->id)
		goto err_mlxdevm_free;
	shd->priv_size = priv_size;
	refcount_set(&shd->refcount, 1);

	/* Twin with the caller's shared devlink instance, set before register so
	 * the shared lock is already in effect (devm_lock dispatches to it).
	 */
	mlxdevm->devlink = shd_devlink;

	devm_lock(mlxdevm);
	devm_register(mlxdevm);
	devm_unlock(mlxdevm);

	list_add_tail(&shd->list, &shd_list);

	return shd;

err_mlxdevm_free:
	mlxdevm_free(mlxdevm);
	return NULL;
}

static void mlxdevm_shd_destroy(struct mlxdevm_shd *shd)
{
	struct mlxdevm *mlxdevm = priv_to_mlxdevm(shd);

	list_del(&shd->list);
	devm_lock(mlxdevm);
	devm_unregister(mlxdevm);
	devm_unlock(mlxdevm);
	kfree(shd->id);
	mlxdevm_free(mlxdevm);
}

/**
 * mlxdevm_shd_get - Get or create a shared mlxdevm instance
 * @id: Identifier string (e.g., serial number) for the shared instance
 * @ops: mlxdevm operations structure
 * @priv_size: Size of private data structure
 * @driver: Driver associated with the shared mlxdevm instance
 * @shd_devlink: shared devlink instance to twin with (shares its lock)
 *
 * Get an existing shared mlxdevm instance identified by @id, or create
 * a new one if it doesn't exist. Return the mlxdevm instance with a
 * reference held. The caller must call mlxdevm_shd_put() when done.
 *
 * All callers sharing the same @id must pass identical @ops, @priv_size
 * and @driver. A mismatch triggers a warning and returns NULL.
 *
 * Return: Pointer to the shared mlxdevm instance on success,
 *         NULL on failure
 */
struct mlxdevm *mlxdevm_shd_get(const char *id,
				const struct mlxdevm_ops *ops,
				size_t priv_size,
				const struct device_driver *driver,
				struct devlink *shd_devlink)
{
	struct mlxdevm *mlxdevm;
	struct mlxdevm_shd *shd;

	mutex_lock(&shd_mutex);

	shd = mlxdevm_shd_lookup(id);
	if (!shd) {
		shd = mlxdevm_shd_create(id, ops, priv_size, driver, shd_devlink);
		goto unlock;
	}

	mlxdevm = priv_to_mlxdevm(shd);
	if (WARN_ON_ONCE(mlxdevm->ops != ops ||
			 shd->priv_size != priv_size ||
			 mlxdevm->dev_driver != driver)) {
		shd = NULL;
		goto unlock;
	}
	refcount_inc(&shd->refcount);

unlock:
	mutex_unlock(&shd_mutex);
	return shd ? priv_to_mlxdevm(shd) : NULL;
}
EXPORT_SYMBOL_GPL(mlxdevm_shd_get);

/**
 * mlxdevm_shd_put - Release a reference on a shared mlxdevm instance
 * @mlxdevm: Shared mlxdevm instance
 *
 * Release a reference on a shared mlxdevm instance obtained via
 * mlxdevm_shd_get().
 */
void mlxdevm_shd_put(struct mlxdevm *mlxdevm)
{
	struct mlxdevm_shd *shd;

	mutex_lock(&shd_mutex);
	shd = mlxdevm_priv(mlxdevm);
	if (refcount_dec_and_test(&shd->refcount))
		mlxdevm_shd_destroy(shd);
	mutex_unlock(&shd_mutex);
}
EXPORT_SYMBOL_GPL(mlxdevm_shd_put);

/**
 * mlxdevm_shd_get_priv - Get private data from shared mlxdevm instance
 * @mlxdevm: mlxdevm instance
 *
 * Returns a pointer to the driver's private data structure within
 * the shared mlxdevm instance.
 *
 * Return: Pointer to private data
 */
void *mlxdevm_shd_get_priv(struct mlxdevm *mlxdevm)
{
	struct mlxdevm_shd *shd = mlxdevm_priv(mlxdevm);

	return shd->priv;
}
EXPORT_SYMBOL_GPL(mlxdevm_shd_get_priv);
