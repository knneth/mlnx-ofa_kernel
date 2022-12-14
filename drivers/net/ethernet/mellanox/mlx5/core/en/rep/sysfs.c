// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021 Mellanox Technologies. */

#include "en/rep/sysfs.h"
#include "en/rep/meter.h"
#include "en_rep.h"
#include "eswitch.h"

static ssize_t rep_attr_show(struct kobject *kobj,
			     struct attribute *attr, char *buf)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->show)
		ret = kattr->show(kobj, kattr, buf);
	return ret;
}

static ssize_t rep_attr_store(struct kobject *kobj,
			      struct attribute *attr,
			      const char *buf, size_t count)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->store)
		ret = kattr->store(kobj, kattr, buf, count);
	return ret;
}

static ssize_t miss_rl_cfg_store(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf,
				 size_t count)
{
	struct mlx5_rep_sysfs *tmp =
		container_of(kobj, struct mlx5_rep_sysfs, kobj);
	struct mlx5_eswitch *esw = tmp->esw;
	struct mlx5e_rep_priv *rep_priv;
	struct mlx5_eswitch_rep *rep;
	u64 rate, burst;
	int err;

	err = sscanf(buf, "%llu %llu", &rate, &burst);
	if (err != 2)
		return -EINVAL;

	if (rate < 0 || burst < 0)
		return -EINVAL;

	rep = mlx5_eswitch_vport_rep(esw, tmp->vport);
	rep_priv = mlx5e_rep_to_rep_priv(rep);

	err = mlx5_rep_set_miss_meter(esw->dev, rep_priv, tmp->vport,
				      rate, burst);

	return err ? err : count;
}

static ssize_t miss_rl_cfg_show(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	struct mlx5_rep_sysfs *tmp =
		container_of(kobj, struct mlx5_rep_sysfs, kobj);
	struct mlx5_eswitch *esw = tmp->esw;
	struct mlx5e_rep_priv *rep_priv;
	struct mlx5_eswitch_rep *rep;

	rep = mlx5_eswitch_vport_rep(esw, tmp->vport);
	rep_priv = mlx5e_rep_to_rep_priv(rep);

	return sprintf(buf,
		       "rate: %llu[packes/s] burst: %llu[packets]\n",
		       rep_priv->rep_meter.rate, rep_priv->rep_meter.burst);
}

static ssize_t miss_rl_dropped_show_common(struct kobject *kobj,
					   int drop_type,
					   char *buf)
{
	struct mlx5_rep_sysfs *tmp =
		container_of(kobj, struct mlx5_rep_sysfs, kobj);
	struct mlx5_eswitch *esw = tmp->esw;
	struct mlx5e_rep_priv *rep_priv;
	struct mlx5_eswitch_rep *rep;
	u64 data;
	int err;

	rep = mlx5_eswitch_vport_rep(esw, tmp->vport);
	rep_priv = mlx5e_rep_to_rep_priv(rep);

	err = mlx5_rep_get_miss_meter_data(esw->dev, rep_priv,
					   drop_type, &data);
	if (err)
		return err;

	return sprintf(buf, "%llu\n", data);
}

static ssize_t miss_rl_dropped_packets_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *buf)
{
	return miss_rl_dropped_show_common(kobj, MLX5_RATE_LIMIT_DATA_PACKETS_DROPPED, buf);
}

static ssize_t miss_rl_dropped_bytes_show(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *buf)
{
	return miss_rl_dropped_show_common(kobj, MLX5_RATE_LIMIT_DATA_BYTES_DROPPED, buf);
}

static struct kobj_attribute attr_miss_rl_cfg = {
	.attr = {.name = "miss_rl_cfg",
		 .mode = 0644 },
	.show = miss_rl_cfg_show,
	.store = miss_rl_cfg_store,
};

static struct kobj_attribute attr_miss_rl_dropped_packets = {
	.attr = {.name = "miss_rl_dropped_packets",
		 .mode = 0444 },
	.show = miss_rl_dropped_packets_show,
};

static struct kobj_attribute attr_miss_rl_dropped_bytes = {
	.attr = {.name = "miss_rl_dropped_bytes",
		 .mode = 0444 },
	.show = miss_rl_dropped_bytes_show,
};

static struct attribute *rep_attrs[] = {
	&attr_miss_rl_cfg.attr,
	&attr_miss_rl_dropped_packets.attr,
	&attr_miss_rl_dropped_bytes.attr,
	NULL,
};

static const struct sysfs_ops rep_sysfs_ops = {
	.show   = rep_attr_show,
	.store  = rep_attr_store
};

static struct kobj_type rep_type = {
	.sysfs_ops     = &rep_sysfs_ops,
	.default_attrs = rep_attrs
};

void mlx5_rep_sysfs_init(struct mlx5e_rep_priv *rpriv)
{
	struct mlx5e_priv *priv = netdev_priv(rpriv->netdev);
	struct mlx5_core_dev *dev = priv->mdev;
	struct mlx5_rep_sysfs *tmp;
	struct mlx5_eswitch *esw;
	int err;

	 if (!(MLX5_CAP_GEN_64(dev, general_obj_types) &
	       MLX5_HCA_CAP_GENERAL_OBJECT_TYPES_FLOW_METER_ASO))
		 return;

	esw = dev->priv.eswitch;

	tmp = &rpriv->rep_sysfs;
	tmp->esw = esw;
	tmp->vport = rpriv->rep->vport;
	err = kobject_init_and_add(&tmp->kobj, &rep_type,
				   &rpriv->netdev->dev.kobj, "rep_config");

	if (err)
		tmp->esw = NULL;
}

void mlx5_rep_sysfs_cleanup(struct mlx5e_rep_priv *rpriv)
{
	struct mlx5_rep_sysfs *tmp;

	tmp = &rpriv->rep_sysfs;
	if (!tmp->esw)
		return;

	kobject_put(&tmp->kobj);
}
