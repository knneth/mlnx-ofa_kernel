// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Mellanox Technologies

#include <linux/netdevice.h>
#include <linux/kref.h>
#include <linux/list.h>

#include "eswitch.h"
#include "en_rep.h"

struct mlx5e_rep_bond_shadow_entry {
   struct list_head list;
   struct net_device *netdev;
};

struct mlx5e_rep_bond_metadata {
	struct list_head list; /* link to global list of rep_bond_metadata */
	struct mlx5_eswitch *esw;
	struct net_device *lag_dev;
	u32 metadata_reg_c_0;

	struct list_head slaves_list; /* slaves list */
	rwlock_t slaves_list_lock;
	struct kref refcnt;
};

static struct mlx5e_rep_bond_metadata *
mlx5e_lookup_master_rep_bond_metadata(struct mlx5_eswitch *esw,
				      const struct net_device *lag_dev)
{
	struct mlx5e_rep_bond_metadata *cur, *found = NULL;
	struct list_head *tmp, *e;

	list_for_each_safe(e, tmp, &esw->offloads.rep_bond_metadata_list) {
		cur = list_entry(e, struct mlx5e_rep_bond_metadata, list);
		if (cur->lag_dev == lag_dev) {
			found = cur;
			break;
		}
	}

	return found;
}

static struct mlx5e_rep_bond_shadow_entry *
mlx5e_lookup_rep_bond_shadow_entry(const struct mlx5e_rep_bond_metadata *mdata,
				   const struct net_device *netdev)
{
	struct mlx5e_rep_bond_shadow_entry *cur, *found = NULL;
	struct list_head *tmp, *e;

	list_for_each_safe(e, tmp, &mdata->slaves_list) {
		cur = list_entry(e, struct mlx5e_rep_bond_shadow_entry, list);
		if (cur->netdev == netdev) {
			found = cur;
			break;
		}
	}

	return found;
}

static void mlx5e_rep_bond_metadata_release(struct kref *kref)
{
	struct mlx5e_rep_bond_metadata *mdata =
		container_of(kref, struct mlx5e_rep_bond_metadata, refcnt);
	struct mlx5_eswitch *esw = mdata->esw;

	write_lock(&esw->offloads.rep_bond_metadata_lock);
	esw_free_unique_match_id(GEN_MATCH_ID(mdata->metadata_reg_c_0));
	list_del(&mdata->list);
	write_unlock(&esw->offloads.rep_bond_metadata_lock);
	kfree(mdata);
	WARN_ON(!list_empty(&mdata->slaves_list));
}

int mlx5e_enslave_rep(struct mlx5_eswitch *esw, struct net_device *netdev,
		      struct net_device *lag_dev)
{
	struct mlx5e_rep_bond_shadow_entry *s_entry, *first;
	struct mlx5e_rep_priv *rpriv1, *rpriv2;
	struct mlx5e_rep_bond_metadata *mdata;
	struct mlx5e_priv *priv1, *priv2;
	u16 match_id;

	mdata = mlx5e_lookup_master_rep_bond_metadata(esw, lag_dev);
	if (!mdata) {
		mdata = kzalloc(sizeof(*mdata), GFP_KERNEL);
		if (!mdata)
			return -ENOMEM;

		mdata->lag_dev = lag_dev;
		mdata->esw = esw;
		kref_init(&mdata->refcnt);
		INIT_LIST_HEAD(&mdata->slaves_list);
		rwlock_init(&mdata->slaves_list_lock);
		write_lock(&esw->offloads.rep_bond_metadata_lock);
		match_id = esw_get_unique_match_id();
		if (match_id < 0) {
			write_unlock(&esw->offloads.rep_bond_metadata_lock);
			kfree(mdata);
			return -ENOSPC;
		}
		mdata->metadata_reg_c_0 = GEN_METADATA(match_id);
		list_add(&mdata->list, &esw->offloads.rep_bond_metadata_list);
		write_unlock(&esw->offloads.rep_bond_metadata_lock);
		esw_debug(esw->dev,
			  "added rep_bond_metadata for lag_dev(%s) metadata(0x%x)\n",
			  lag_dev->name, mdata->metadata_reg_c_0);
	} else {
		kref_get(&mdata->refcnt);
	}

	s_entry = kzalloc(sizeof(*s_entry), GFP_KERNEL);
	if (!s_entry) {
		kref_put(&mdata->refcnt, mlx5e_rep_bond_metadata_release);
		return -ENOMEM;
	}

	s_entry->netdev = netdev;
	write_lock(&mdata->slaves_list_lock);
	list_add_tail(&s_entry->list, &mdata->slaves_list);
	first = list_first_entry(&mdata->slaves_list,
				 struct mlx5e_rep_bond_shadow_entry, list);
	write_unlock(&mdata->slaves_list_lock);

	/* Elect first to be the primary rep */
	if (s_entry == first) {
		priv1 = netdev_priv(netdev);
		rpriv1 = priv1->ppriv;
		esw_modify_vport_ingress(esw, mdata->metadata_reg_c_0,
					 rpriv1->rep);
		esw_debug(esw->dev,
			  "Primary rep(%s) metadata(%d) modify_ingress vport(%d)\n",
			  netdev->name, mdata->metadata_reg_c_0, rpriv1->rep->vport);
	} else {
		priv1 = netdev_priv(first->netdev);
		rpriv1 = priv1->ppriv;
		priv2 = netdev_priv(s_entry->netdev);
		rpriv2 = priv2->ppriv;
		/* Modify the slave rep and bond it with the primary rep */
		esw_modify_vport_ingress(esw, mdata->metadata_reg_c_0,
					 rpriv2->rep);
		esw_bond_vports_ingress(esw, rpriv1->rep, rpriv2->rep);
		esw_debug(esw->dev, "Bond p-rep(%s) s-rep(%s) metadata(%d)\n",
			  first->netdev->name, s_entry->netdev->name, mdata->metadata_reg_c_0);
	}

	return 0;
}

void mlx5e_unslave_rep(struct mlx5_eswitch *esw, const struct net_device *netdev,
		       const struct net_device *lag_dev)
{
	struct mlx5e_rep_bond_shadow_entry *s_entry, *first;
	struct mlx5e_rep_bond_metadata *mdata;
	struct mlx5e_rep_priv *rpriv;
	struct mlx5e_priv *priv;

	mdata = mlx5e_lookup_master_rep_bond_metadata(esw, lag_dev);
	if (!mdata)
		return;

	s_entry = mlx5e_lookup_rep_bond_shadow_entry(mdata, netdev);
	if (!s_entry)
		return;

	write_lock(&mdata->slaves_list_lock);
	first = list_first_entry(&mdata->slaves_list,
				 struct mlx5e_rep_bond_shadow_entry, list);
	list_del(&s_entry->list);
	write_unlock(&mdata->slaves_list_lock);

	if (s_entry == first && !list_empty(&mdata->slaves_list)) {
		/* Unslave the primary rep, elect the new primary */
		first = list_first_entry(&mdata->slaves_list,
					 struct mlx5e_rep_bond_shadow_entry, list);
		priv = netdev_priv(first->netdev);
		rpriv = priv->ppriv;
		/* First, reset this primary rep metadata and ingress */
		esw_modify_vport_ingress(esw, 0, rpriv->rep);
		esw_modify_vport_ingress(esw, mdata->metadata_reg_c_0,
					 rpriv->rep);
		esw_debug(esw->dev,
			  "New primary rep(%s) metadata(%d) modify_ingress vport(%d)\n",
			  first->netdev->name, mdata->metadata_reg_c_0, rpriv->rep->vport);
	}

	priv = netdev_priv(netdev);
	rpriv = priv->ppriv;
	/* Reset this slave rep metadata and ingress */
	esw_modify_vport_ingress(esw, 0, rpriv->rep);
	esw_debug(esw->dev,
		  "Unslave rep(%s) metadata(%d) reset_ingress vport(%d)\n",
		  s_entry->netdev->name, mdata->metadata_reg_c_0, rpriv->rep->vport);

	kref_put(&mdata->refcnt, mlx5e_rep_bond_metadata_release);
	kfree(s_entry);
}
