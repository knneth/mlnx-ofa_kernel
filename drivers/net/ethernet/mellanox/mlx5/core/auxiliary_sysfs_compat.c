// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#if !defined(HAVE_AUX_DEV_IRQS_SYSFS) && !defined(CONFIG_AUXILIARY_BUS)

#include <linux/auxiliary_bus.h>
#include <linux/slab.h>
#include "sf/dev/dev.h"

#define AUXILIARY_MAX_IRQ_NAME 11

struct auxiliary_irq_info {
	struct device_attribute sysfs_attr;
	char name[AUXILIARY_MAX_IRQ_NAME];
};

static struct attribute *auxiliary_irq_attrs[] = {
	NULL
};

static const struct attribute_group auxiliary_irqs_group = {
	.name = "irqs",
	.attrs = auxiliary_irq_attrs,
};

static int auxiliary_irq_dir_prepare(struct auxiliary_device *auxdev)
{
	struct mlx5_sf_dev *mlx5_sf_device = container_of(auxdev, struct mlx5_sf_dev, adev);
	int ret = 0;

#ifdef	HAVE_CLEANUP_H
	guard(mutex)(&mlx5_sf_device->sysfs.lock);
#else
	mutex_lock(&mlx5_sf_device->sysfs.lock);
#endif
	if (mlx5_sf_device->sysfs.irq_dir_exists)
	{
#ifndef	HAVE_CLEANUP_H
		mutex_unlock(&mlx5_sf_device->sysfs.lock);
#endif
		return 0;
	}

	ret = devm_device_add_group(&auxdev->dev, &auxiliary_irqs_group);
	if (ret)
	{
#ifndef	HAVE_CLEANUP_H
		mutex_unlock(&mlx5_sf_device->sysfs.lock);
#endif
		return ret;
	}

	mlx5_sf_device->sysfs.irq_dir_exists = true;
	xa_init(&mlx5_sf_device->sysfs.irqs);
#ifndef	HAVE_CLEANUP_H
	mutex_unlock(&mlx5_sf_device->sysfs.lock);
#endif
	return 0;
}

/**
 * mlx5_compat_sf_auxiliary_device_sysfs_irq_add - add a sysfs entry for the given IRQ
 * @auxdev: auxiliary bus device to add the sysfs entry, must be an auxiliary device of a SF.
 * @irq: The associated interrupt number.
 *
 * This function should be called after auxiliary device have successfully
 * received the irq.
 * The driver is responsible to add a unique irq for the auxiliary device. The
 * driver can invoke this function from multiple thread context safely for
 * unique irqs of the auxiliary devices. The driver must not invoke this API
 * multiple times if the irq is already added previously.
 *
 * Return: zero on success or an error code on failure.
 */
int mlx5_compat_sf_auxiliary_device_sysfs_irq_add(struct auxiliary_device *auxdev, int irq)
{
	struct mlx5_sf_dev *mlx5_sf_device = container_of(auxdev, struct mlx5_sf_dev, adev);
#ifdef HAVE_CLEANUP_H
	struct auxiliary_irq_info *info __free(kfree) = NULL;
#else
	struct auxiliary_irq_info *info = NULL;
#endif
	struct device *dev = &auxdev->dev;
	int ret;

	ret = auxiliary_irq_dir_prepare(auxdev);
	if (ret)
		return ret;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	sysfs_attr_init(&info->sysfs_attr.attr);
	snprintf(info->name, AUXILIARY_MAX_IRQ_NAME, "%d", irq);

	ret = xa_insert(&mlx5_sf_device->sysfs.irqs, irq, info, GFP_KERNEL);
	if (ret)
	{
#ifndef HAVE_CLEANUP_H
		kfree(info);
#endif
		return ret;
	}

	info->sysfs_attr.attr.name = info->name;
	ret = sysfs_add_file_to_group(&dev->kobj, &info->sysfs_attr.attr,
				      auxiliary_irqs_group.name);
	if (ret)
		goto sysfs_add_err;

#ifdef HAVE_CLEANUP_H
	xa_store(&mlx5_sf_device->sysfs.irqs, irq, no_free_ptr(info), GFP_KERNEL);
#else
	xa_store(&mlx5_sf_device->sysfs.irqs, irq, info, GFP_KERNEL);
#endif
	return 0;

sysfs_add_err:
	xa_erase(&mlx5_sf_device->sysfs.irqs, irq);
#ifndef HAVE_CLEANUP_H
	kfree(info);
#endif
	return ret;
}

/**
 * mlx5_compat_sf_auxiliary_device_sysfs_irq_remove - remove a sysfs entry for the given IRQ
 * @auxdev: auxiliary bus device to add the sysfs entry, must be an auxiliary device of a SF.
 * @irq: the IRQ to remove.
 *
 * This function should be called to remove an IRQ sysfs entry.
 * The driver must invoke this API when IRQ is released by the device.
 */
void mlx5_compat_sf_auxiliary_device_sysfs_irq_remove(struct auxiliary_device *auxdev, int irq)
{
	struct mlx5_sf_dev *mlx5_sf_device = container_of(auxdev, struct mlx5_sf_dev, adev);
#ifdef HAVE_CLEANUP_H
	struct auxiliary_irq_info *info __free(kfree) = xa_load(&mlx5_sf_device->sysfs.irqs, irq);
#else
	struct auxiliary_irq_info *info = xa_load(&mlx5_sf_device->sysfs.irqs, irq);
#endif
	struct device *dev = &auxdev->dev;

	if (!info) {
		dev_err(&auxdev->dev, "IRQ %d doesn't exist\n", irq);
		return;
	}
	sysfs_remove_file_from_group(&dev->kobj, &info->sysfs_attr.attr,
				     auxiliary_irqs_group.name);
	xa_erase(&mlx5_sf_device->sysfs.irqs, irq);
#ifndef HAVE_CLEANUP_H
	kfree(info);
#endif
}
#endif
