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

static ssize_t miss_rl_stats_clr_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf,
				       size_t count)
{
	struct mlx5_rep_sysfs *tmp =
		container_of(kobj, struct mlx5_rep_sysfs, kobj);
	struct mlx5_eswitch *esw = tmp->esw;
	struct mlx5e_rep_priv *rep_priv;
	struct mlx5_eswitch_rep *rep;
	int clr_set;
	int err;

	err = sscanf(buf, "%d", &clr_set);
	if (err != 1 || clr_set != 1)
		return -EINVAL;

	rep = mlx5_eswitch_vport_rep(esw, tmp->vport);
	rep_priv = mlx5e_rep_to_rep_priv(rep);

	err = mlx5_rep_clear_miss_meter_data(esw->dev, rep_priv);

	return err ? err : count;
}

static struct kobj_attribute attr_miss_rl_stats_clr = {
	.attr = {.name = "miss_rl_stats_clr",
		 .mode = 0200 },
	.store = miss_rl_stats_clr_store,
};

static ssize_t page_limit_show(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       char *buf)
{
	struct mlx5_rep_sysfs *tmp =
		container_of(kobj, struct mlx5_rep_sysfs, paging_kobj);
	struct mlx5_eswitch *esw = tmp->esw;
	struct mlx5_vport *evport;
	u32 page_limit;
	u16 vhca_id;
	int err;

	if (mlx5_vhca_icm_ctrl_supported(esw->dev)) {
		err = mlx5_esw_query_vport_vhca_id(esw, tmp->vport, &vhca_id);
		if (err)
			return err;

		err = mlx5_get_max_alloc_icm_th(esw->dev, vhca_id, &page_limit);
		if (err)
			return err;
		goto out;
	}

	evport = mlx5_eswitch_get_vport(esw, tmp->vport);
	spin_lock(&evport->pg_counters_lock);
	page_limit = evport->page_limit;
	spin_unlock(&evport->pg_counters_lock);
out:
	return sprintf(buf, "limit: %u\n", page_limit);
}

#define PAGE_LIMIT_UNLIMITED UINT_MAX
static ssize_t page_limit_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf,
				size_t count)
{
	struct mlx5_rep_sysfs *tmp =
		container_of(kobj, struct mlx5_rep_sysfs, paging_kobj);
	struct mlx5_eswitch *esw = tmp->esw;
	struct mlx5_vport *evport;
	u16 vhca_id;
	u32 limit;
	int err;

	err = sscanf(buf, "%u", &limit);
	if (err != 1)
		return -EINVAL;

	if (mlx5_vhca_icm_ctrl_supported(esw->dev)) {
		err = mlx5_esw_query_vport_vhca_id(esw, tmp->vport, &vhca_id);
		if (err)
			return err;

		if (!limit)
			limit = PAGE_LIMIT_UNLIMITED;

		err = mlx5_set_max_alloc_icm_th(esw->dev, vhca_id, limit);
		if (err)
			return err;
		goto out;
	}

	evport = mlx5_eswitch_get_vport(esw, tmp->vport);
	spin_lock(&evport->pg_counters_lock);
	evport->page_limit = limit;
	spin_unlock(&evport->pg_counters_lock);
out:
	return count;
}

static ssize_t num_pages_show(struct kobject *kobj,
			      struct kobj_attribute *attr,
			      char *buf)
{
	struct mlx5_rep_sysfs *tmp =
		container_of(kobj, struct mlx5_rep_sysfs, paging_kobj);
	struct mlx5_eswitch *esw = tmp->esw;
	struct mlx5_vport *evport;
	u32 fw_pages;

	evport = mlx5_eswitch_get_vport(esw, tmp->vport);
	spin_lock(&evport->pg_counters_lock);
	fw_pages = evport->fw_pages;
	spin_unlock(&evport->pg_counters_lock);
	return sprintf(buf, "fw_pages: %u\n", fw_pages);
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

static struct kobj_attribute attr_page_limit = {
	.attr = {.name = "page_limit",
		 .mode = 0644 },
	.show = page_limit_show,
	.store = page_limit_store,
};

static struct kobj_attribute attr_num_pages = {
	.attr = {.name = "num_pages",
		 .mode = 0644 },
	.show = num_pages_show,
};

static struct attribute *rep_attrs[] = {
	&attr_miss_rl_cfg.attr,
	&attr_miss_rl_dropped_packets.attr,
	&attr_miss_rl_dropped_bytes.attr,
	&attr_miss_rl_stats_clr.attr,
	NULL,
};

static const struct sysfs_ops rep_sysfs_ops = {
	.show   = rep_attr_show,
	.store  = rep_attr_store
};

ATTRIBUTE_GROUPS(rep);

static struct kobj_type rep_type = {
	.sysfs_ops     = &rep_sysfs_ops,
	.default_groups = rep_groups
};

static struct attribute *rep_paging_attrs[] = {
	&attr_page_limit.attr,
	&attr_num_pages.attr,
	NULL,
};
ATTRIBUTE_GROUPS(rep_paging);


static struct kobj_type rep_paging = {
	.sysfs_ops     = &rep_sysfs_ops,
	.default_groups = rep_paging_groups
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

	if (err) {
		tmp->esw = NULL;
		return;
	}

	if (mlx5_eswitch_is_vf_vport(esw, tmp->vport)) {
		err = kobject_init_and_add(&tmp->paging_kobj, &rep_paging,
					   &tmp->kobj, "paging_control");
		if (err) {
			kobject_put(&tmp->kobj);
			tmp->esw = NULL;
		}
	}
}

void mlx5_rep_sysfs_cleanup(struct mlx5e_rep_priv *rpriv)
{
	struct mlx5_rep_sysfs *tmp;

	tmp = &rpriv->rep_sysfs;
	if (!tmp->esw)
		return;

	if (mlx5_eswitch_is_vf_vport(tmp->esw, tmp->vport)) {
		kobject_put(&tmp->paging_kobj);
	}

	kobject_put(&tmp->kobj);
}
