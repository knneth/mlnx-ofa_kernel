// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021 Mellanox Technologies. */

#include "tc_ct.h"

#include "en_tc.h"

#define ct_dbg(fmt, args...)\
	netdev_dbg(fs->netdev, "ct_fs_dmfs debug: " fmt "\n", ##args)

struct mlx5_ct_fs_dmfs {
};

struct mlx5_ct_fs_dmfs_zone_rule {
	struct mlx5_flow_handle *fs_rule;
};

struct mlx5_ct_fs_dmfs_counter {
	struct mlx5_ct_fs_counter fs_counter;
	struct mlx5dr_action *count_action;
};

static int
mlx5_ct_fs_dmfs_init(struct mlx5_ct_fs *fs)
{
	return 0;
}

static void
mlx5_ct_fs_dmfs_destroy(struct mlx5_ct_fs *fs)
{
}

static int
mlx5_ct_fs_dmfs_ct_rule_add(struct mlx5_ct_fs *fs, void *conn_priv, struct mlx5_flow_spec *spec,
			    struct mlx5_flow_attr *attr, struct mlx5_ct_fs_counter *fs_counter,
			    struct flow_rule *rule)
{
	struct mlx5_ct_fs_dmfs_zone_rule *zone_rule = conn_priv;
	struct mlx5e_priv *priv = netdev_priv(fs->netdev);
	int err;

	zone_rule->fs_rule = mlx5_tc_rule_insert(priv, spec, attr);
	if (IS_ERR(zone_rule->fs_rule)) {
		err = PTR_ERR(zone_rule->fs_rule);
		ct_dbg("Failed to add ct entry fs rule");
		return err;
	}

	return 0;
}

static void
mlx5_ct_fs_dmfs_ct_rule_del(struct mlx5_ct_fs *fs, void *conn_priv, struct mlx5_flow_attr *attr)
{
	struct mlx5_ct_fs_dmfs_zone_rule *zone_rule = conn_priv;

	mlx5_tc_rule_delete(netdev_priv(fs->netdev), zone_rule->fs_rule, attr);
}

static struct mlx5_ct_fs_counter *
mlx5_ct_fs_dmfs_ct_counter_create(struct mlx5_ct_fs *fs)
{
	struct mlx5_ct_fs_dmfs_counter *dmfs_counter;
	int err = 0;

	dmfs_counter = kzalloc(sizeof(*dmfs_counter), GFP_KERNEL);
	if (!dmfs_counter)
		return ERR_PTR(-ENOMEM);

	dmfs_counter->fs_counter.counter = mlx5_fc_create(fs->dev, true);
	if (IS_ERR(dmfs_counter->fs_counter.counter)) {
		err = PTR_ERR(dmfs_counter->fs_counter.counter);
		goto err_create;
	}

	return &dmfs_counter->fs_counter;

err_create:
	kfree(dmfs_counter);
	return ERR_PTR(err);
}

static void
mlx5_ct_fs_dmfs_ct_counter_destroy(struct mlx5_ct_fs *fs, struct mlx5_ct_fs_counter *fs_counter)
{
	struct mlx5_ct_fs_dmfs_counter *dmfs_counter;

	dmfs_counter = container_of(fs_counter, struct mlx5_ct_fs_dmfs_counter, fs_counter);
	mlx5_fc_destroy(fs->dev, dmfs_counter->fs_counter.counter);
	kfree(dmfs_counter);
}

static struct mlx5_ct_fs_ops dmfs_ops = {
	.ct_counter_create = mlx5_ct_fs_dmfs_ct_counter_create,
	.ct_counter_destroy = mlx5_ct_fs_dmfs_ct_counter_destroy,

	.ct_rule_add = mlx5_ct_fs_dmfs_ct_rule_add,
	.ct_rule_del = mlx5_ct_fs_dmfs_ct_rule_del,

	.init = mlx5_ct_fs_dmfs_init,
	.destroy = mlx5_ct_fs_dmfs_destroy,

	.conn_priv_size = sizeof(struct mlx5_ct_fs_dmfs_zone_rule),
	.priv_size = sizeof(struct mlx5_ct_fs_dmfs),
};

struct mlx5_ct_fs_ops *mlx5_ct_fs_dmfs_ops_get(void)
{
	return &dmfs_ops;
}
