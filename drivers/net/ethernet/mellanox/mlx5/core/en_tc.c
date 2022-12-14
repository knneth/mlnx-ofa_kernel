/*
 * Copyright (c) 2016, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <net/flow_dissector.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_skbedit.h>
#include <linux/mlx5/fs.h>
#include <linux/mlx5/device.h>
#include <linux/rhashtable.h>
#include <linux/refcount.h>
#include <net/switchdev.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_vlan.h>
#include <net/tc_act/tc_tunnel_key.h>
#include <net/tc_act/tc_pedit.h>
#include <net/tc_act/tc_csum.h>
#include <net/vxlan.h>
#include <net/arp.h>
#include "en.h"
#include "en_rep.h"
#include "en_tc.h"
#include "eswitch.h"
#include "lib/vxlan.h"
#include "fs_core.h"
#include "en/port.h"
#include <linux/mlx5/devcom.h>

struct mlx5_nic_flow_attr {
	u32 action;
	u32 flow_tag;
	u32 mod_hdr_id;
	u32 hairpin_tirn;
	u8 match_level;
	struct mlx5_flow_table	*hairpin_ft;
	struct mlx5_fc		*counter;
};

#define MLX5E_TC_FLOW_BASE (MLX5E_TC_LAST_EXPORTED_BIT + 1)

enum {
	MLX5E_TC_FLOW_INGRESS	= MLX5E_TC_INGRESS,
	MLX5E_TC_FLOW_EGRESS	= MLX5E_TC_EGRESS,
	MLX5E_TC_FLOW_ESWITCH	= MLX5E_TC_ESW_OFFLOAD,
	MLX5E_TC_FLOW_NIC	= MLX5E_TC_NIC_OFFLOAD,
	MLX5E_TC_FLOW_OFFLOADED	= BIT(MLX5E_TC_FLOW_BASE),
	MLX5E_TC_FLOW_HAIRPIN	= BIT(MLX5E_TC_FLOW_BASE + 1),
	MLX5E_TC_FLOW_HAIRPIN_RSS = BIT(MLX5E_TC_FLOW_BASE + 2),
	MLX5E_TC_FLOW_SLOW	  = BIT(MLX5E_TC_FLOW_BASE + 3),
	MLX5E_TC_FLOW_DUP         = BIT(MLX5E_TC_FLOW_BASE + 4),
	MLX5E_TC_FLOW_NOT_READY   = BIT(MLX5E_TC_FLOW_BASE + 5),
	MLX5E_TC_FLOW_INIT_DONE	  = BIT(MLX5E_TC_FLOW_BASE + 6),
};

#define MLX5E_TC_MAX_SPLITS 1

struct mlx5e_tc_flow {
	struct rhash_head	node;
	struct mlx5e_priv	*priv;
	u64			cookie;
	atomic_t		flags;
	struct mlx5_flow_handle *rule[MLX5E_TC_MAX_SPLITS + 1];
	struct mlx5e_encap_entry *e; /* attached encap instance */
	struct mlx5e_tc_flow    *peer_flow;
	struct list_head	encap;   /* flows sharing the same encap ID */
	unsigned long encap_init_jiffies;
	struct mlx5e_mod_hdr_entry *mh; /* attached mod header instance */
	struct list_head	mod_hdr; /* flows sharing the same mod hdr ID */
	struct mlx5e_hairpin_entry *hpe; /* attached hairpin instance */
	struct list_head	hairpin; /* flows sharing the same hairpin */
	struct list_head	peer; /* flows with peer flow */
	struct list_head	unready; /* flows not ready to be offloaded (e.g due to missing route) */
	refcount_t		refcnt;
	struct list_head        tmp_list;
	struct rcu_head		rcu_head;
	union {
		struct mlx5_esw_flow_attr esw_attr[0];
		struct mlx5_nic_flow_attr nic_attr[0];
	};
};

struct mlx5e_tc_flow_parse_attr {
	struct ip_tunnel_info tun_info;
	struct mlx5_flow_spec spec;
	int num_mod_hdr_actions;
	int max_mod_hdr_actions;
	void *mod_hdr_actions;
	int mirred_ifindex;
};

#define MLX5E_TC_TABLE_NUM_GROUPS 4
#define MLX5E_TC_TABLE_MAX_GROUP_SIZE BIT(16)

struct mlx5e_hairpin {
	struct mlx5_hairpin *pair;

	struct mlx5_core_dev *func_mdev;
	struct mlx5e_priv *func_priv;
	u32 tdn;
	u32 tirn;

	int num_channels;
	struct mlx5e_rqt indir_rqt;
	u32 indir_tirn[MLX5E_NUM_INDIR_TIRS];
	struct mlx5e_ttc_table ttc;
};

struct mlx5e_hairpin_entry {
	/* a node of a hash table which keeps all the  hairpin entries */
	struct hlist_node hairpin_hlist;

	/* protects flows list */
	spinlock_t flows_lock;
	/* flows sharing the same hairpin */
	struct list_head flows;

	u16 peer_vhca_id;
	u8 prio;
	struct mlx5e_hairpin *hp;
	refcount_t refcnt;
	struct rcu_head rcu;
};

struct mod_hdr_key {
	int num_actions;
	void *actions;
};

struct mlx5e_mod_hdr_entry {
	/* a node of a hash table which keeps all the mod_hdr entries */
	struct hlist_node mod_hdr_hlist;

	/* protects flows list */
	spinlock_t flows_lock;
	/* flows sharing the same mod_hdr entry */
	struct list_head flows;

	struct mod_hdr_key key;

	u32 mod_hdr_id;

	refcount_t refcnt;
	struct rcu_head rcu;
};

#define MLX5_MH_ACT_SZ MLX5_UN_SZ_BYTES(set_action_in_add_action_in_auto)

static void mlx5e_tc_del_flow(struct mlx5e_priv *priv,
			      struct mlx5e_tc_flow *flow);

static struct mlx5e_tc_flow *mlx5e_flow_get(struct mlx5e_tc_flow *flow)
{
	if (!flow ||
	    !(atomic_read_acquire(&flow->flags) & MLX5E_TC_FLOW_INIT_DONE) ||
	    !refcount_inc_not_zero(&flow->refcnt))
		return ERR_PTR(-EINVAL);
	return flow;
}

static void mlx5e_flow_put(struct mlx5e_priv *priv,
			   struct mlx5e_tc_flow *flow)
{
	if (refcount_dec_and_test(&flow->refcnt)) {
		mlx5e_tc_del_flow(priv, flow);
		kfree_rcu(flow, rcu_head);
	}
}

static bool mlx5e_is_eswitch_flow(struct mlx5e_tc_flow *flow)
{
	return !!(atomic_read(&flow->flags) & MLX5E_TC_FLOW_ESWITCH);
}

static bool mlx5e_is_offloaded_flow(struct mlx5e_tc_flow *flow)
{
	return !!(atomic_read_acquire(&flow->flags) & MLX5E_TC_FLOW_OFFLOADED);
}

static void mlx5e_set_flow_flag_mb_before(struct mlx5e_tc_flow *flow, int flag)
{
	/* Complete all memory stores before setting bit. */
	smp_mb__before_atomic();
	atomic_or(flag, &flow->flags);
}

static inline u32 hash_mod_hdr_info(struct mod_hdr_key *key)
{
	return jhash(key->actions,
		     key->num_actions * MLX5_MH_ACT_SZ, 0);
}

static inline int cmp_mod_hdr_info(struct mod_hdr_key *a,
				   struct mod_hdr_key *b)
{
	if (a->num_actions != b->num_actions)
		return 1;

	return memcmp(a->actions, b->actions, a->num_actions * MLX5_MH_ACT_SZ);
}

static struct mlx5e_mod_hdr_entry *
mlx5e_mod_hdr_get(struct mlx5e_priv *priv, int namespace,
		  struct mod_hdr_key *key, u32 hash_key)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_mod_hdr_entry *mh;
	bool found = false;

	rcu_read_lock();
	if (namespace == MLX5_FLOW_NAMESPACE_FDB) {
		hash_for_each_possible_rcu(esw->offloads.mod_hdr_tbl, mh,
					   mod_hdr_hlist, hash_key) {
			if (!cmp_mod_hdr_info(&mh->key, key) &&
			    refcount_inc_not_zero(&mh->refcnt)) {
				found = true;
				break;
			}
		}
	} else {
		hash_for_each_possible_rcu(priv->fs.tc.mod_hdr_tbl, mh,
					   mod_hdr_hlist, hash_key) {
			if (!cmp_mod_hdr_info(&mh->key, key) &&
			    refcount_inc_not_zero(&mh->refcnt)) {
				found = true;
				break;
			}
		}
	}
	rcu_read_unlock();

	if (found)
		return mh;
	return NULL;
}

static struct mlx5e_mod_hdr_entry *
mlx5e_mod_hdr_get_create(struct mlx5e_priv *priv, int namespace,
			 struct mod_hdr_key *key, int num_actions,
			 int actions_size)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_mod_hdr_entry *mh, *mh_dup = NULL;
	u32 hash_key;
	int err;

	hash_key = hash_mod_hdr_info(key);

	mh = mlx5e_mod_hdr_get(priv, namespace, key, hash_key);
	if (mh)
		return mh;

	mh = kzalloc(sizeof(*mh) + actions_size, GFP_KERNEL);
	if (!mh)
		return ERR_PTR(-ENOMEM);

	mh->key.actions = (void *)mh + sizeof(*mh);
	memcpy(mh->key.actions, key->actions, actions_size);
	mh->key.num_actions = num_actions;
	spin_lock_init(&mh->flows_lock);
	INIT_LIST_HEAD(&mh->flows);
	refcount_set(&mh->refcnt, 1);

	err = mlx5_modify_header_alloc(priv->mdev, namespace,
				       mh->key.num_actions,
				       mh->key.actions,
				       &mh->mod_hdr_id);
	if (err)
		goto out_err;

	if (namespace == MLX5_FLOW_NAMESPACE_FDB) {
		spin_lock(&esw->offloads.mod_hdr_tbl_lock);
		/* check for concurrent insertion of mod header entry with same
		 * params
		 */
		mh_dup = mlx5e_mod_hdr_get(priv, namespace, key, hash_key);
		if (mh_dup) {
			spin_unlock(&esw->offloads.mod_hdr_tbl_lock);
			goto out_err;
		}

		hash_add_rcu(esw->offloads.mod_hdr_tbl, &mh->mod_hdr_hlist,
			     hash_key);
		spin_unlock(&esw->offloads.mod_hdr_tbl_lock);
	} else {
		spin_lock(&priv->fs.tc.mod_hdr_tbl_lock);
		/* check for concurrent insertion of mod header entry with same
		 * params
		 */
		mh_dup = mlx5e_mod_hdr_get(priv, namespace, key, hash_key);
		if (mh_dup) {
			spin_unlock(&priv->fs.tc.mod_hdr_tbl_lock);
			goto out_err;
		}

		hash_add_rcu(priv->fs.tc.mod_hdr_tbl, &mh->mod_hdr_hlist,
			     hash_key);
		spin_unlock(&priv->fs.tc.mod_hdr_tbl_lock);
	}

	return mh;

out_err:
	if (mh->mod_hdr_id)
		mlx5_modify_header_dealloc(priv->mdev, mh->mod_hdr_id);
	kfree(mh);
	if (mh_dup)
		return mh_dup;
	return ERR_PTR(err);
}

static void mlx5e_mod_hdr_put(struct mlx5e_priv *priv,
			      struct mlx5e_mod_hdr_entry *mh,
			      spinlock_t *tbl_lock)
{
	if (refcount_dec_and_test(&mh->refcnt)) {
		WARN_ON(!list_empty(&mh->flows));
		mlx5_modify_header_dealloc(priv->mdev, mh->mod_hdr_id);
		spin_lock(tbl_lock);
		hash_del_rcu(&mh->mod_hdr_hlist);
		spin_unlock(tbl_lock);
		kfree_rcu(mh, rcu);
	}
}

static int mlx5e_attach_mod_hdr(struct mlx5e_priv *priv,
				struct mlx5e_tc_flow *flow,
				struct mlx5e_tc_flow_parse_attr *parse_attr)
{
	int num_actions, actions_size, namespace;
	struct mlx5e_mod_hdr_entry *mh;
	struct mod_hdr_key key;
	bool is_eswitch_flow = mlx5e_is_eswitch_flow(flow);

	num_actions  = parse_attr->num_mod_hdr_actions;
	actions_size = MLX5_MH_ACT_SZ * num_actions;

	key.actions = parse_attr->mod_hdr_actions;
	key.num_actions = num_actions;

	namespace = is_eswitch_flow ?
		MLX5_FLOW_NAMESPACE_FDB : MLX5_FLOW_NAMESPACE_KERNEL;
	mh = mlx5e_mod_hdr_get_create(priv, namespace, &key, num_actions,
				      actions_size);
	if (IS_ERR(mh))
		return PTR_ERR(mh);

	flow->mh = mh;
	spin_lock(&mh->flows_lock);
	list_add(&flow->mod_hdr, &mh->flows);
	spin_unlock(&mh->flows_lock);
	if (is_eswitch_flow)
		flow->esw_attr->mod_hdr_id = mh->mod_hdr_id;
	else
		flow->nic_attr->mod_hdr_id = mh->mod_hdr_id;

	return 0;
}

static void mlx5e_detach_mod_hdr(struct mlx5e_priv *priv,
				 struct mlx5e_tc_flow *flow)
{
	spinlock_t *tbl_lock = mlx5e_is_eswitch_flow(flow) ?
		&priv->mdev->priv.eswitch->offloads.mod_hdr_tbl_lock :
		&priv->fs.tc.mod_hdr_tbl_lock;

	/* flow wasn't fully initialized */
	if (!flow->mh)
		return;

	spin_lock(&flow->mh->flows_lock);
	list_del(&flow->mod_hdr);
	spin_unlock(&flow->mh->flows_lock);

	mlx5e_mod_hdr_put(priv, flow->mh, tbl_lock);
	flow->mh = NULL;
}

static
struct mlx5_core_dev *mlx5e_hairpin_get_mdev(struct net *net, int ifindex)
{
	struct net_device *netdev;
	struct mlx5e_priv *priv;

	netdev = __dev_get_by_index(net, ifindex);
	priv = netdev_priv(netdev);
	return priv->mdev;
}

static int mlx5e_hairpin_create_transport(struct mlx5e_hairpin *hp)
{
	u32 out[MLX5_ST_SZ_DW(create_tir_out)] = {0};
	u32 in[MLX5_ST_SZ_DW(create_tir_in)] = {0};
	void *tirc;
	int err;

	err = mlx5_core_alloc_transport_domain(hp->func_mdev, &hp->tdn);
	if (err)
		goto alloc_tdn_err;

	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);

	MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_DIRECT);
	MLX5_SET(tirc, tirc, inline_rqn, hp->pair->rqn[0]);
	MLX5_SET(tirc, tirc, transport_domain, hp->tdn);

	err = mlx5_core_create_tir(hp->func_mdev, in, MLX5_ST_SZ_BYTES(create_tir_in),
				   out, MLX5_ST_SZ_BYTES(create_tir_out));
	if (err)
		goto create_tir_err;

	hp->tirn = MLX5_GET(create_tir_out, out, tirn);

	return 0;

create_tir_err:
	mlx5_core_dealloc_transport_domain(hp->func_mdev, hp->tdn);
alloc_tdn_err:
	return err;
}

static void mlx5e_hairpin_destroy_transport(struct mlx5e_hairpin *hp)
{
	mlx5_core_destroy_tir(hp->func_mdev, hp->tirn);
	mlx5_core_dealloc_transport_domain(hp->func_mdev, hp->tdn);
}

static void mlx5e_hairpin_fill_rqt_rqns(struct mlx5e_hairpin *hp, void *rqtc)
{
	u32 indirection_rqt[MLX5E_INDIR_RQT_SIZE], rqn;
	struct mlx5e_priv *priv = hp->func_priv;
	int i, ix, sz = MLX5E_INDIR_RQT_SIZE;

	mlx5e_build_default_indir_rqt(indirection_rqt, sz,
				      hp->num_channels);

	for (i = 0; i < sz; i++) {
		ix = i;
		if (priv->channels.params.rss_hfunc == ETH_RSS_HASH_XOR)
			ix = mlx5e_bits_invert(i, ilog2(sz));
		ix = indirection_rqt[ix];
		rqn = hp->pair->rqn[ix];
		MLX5_SET(rqtc, rqtc, rq_num[i], rqn);
	}
}

static int mlx5e_hairpin_create_indirect_rqt(struct mlx5e_hairpin *hp)
{
	int inlen, err, sz = MLX5E_INDIR_RQT_SIZE;
	struct mlx5e_priv *priv = hp->func_priv;
	struct mlx5_core_dev *mdev = priv->mdev;
	void *rqtc;
	u32 *in;

	inlen = MLX5_ST_SZ_BYTES(create_rqt_in) + sizeof(u32) * sz;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	rqtc = MLX5_ADDR_OF(create_rqt_in, in, rqt_context);

	MLX5_SET(rqtc, rqtc, rqt_actual_size, sz);
	MLX5_SET(rqtc, rqtc, rqt_max_size, sz);

	mlx5e_hairpin_fill_rqt_rqns(hp, rqtc);

	err = mlx5_core_create_rqt(mdev, in, inlen, &hp->indir_rqt.rqtn);
	if (!err)
		hp->indir_rqt.enabled = true;

	kvfree(in);
	return err;
}

static int mlx5e_hairpin_create_indirect_tirs(struct mlx5e_hairpin *hp)
{
	struct mlx5e_priv *priv = hp->func_priv;
	u32 out[MLX5_ST_SZ_DW(create_tir_out)];
	u32 in[MLX5_ST_SZ_DW(create_tir_in)];
	int tt, i, err;
	void *tirc;

	for (tt = 0; tt < MLX5E_NUM_INDIR_TIRS; tt++) {
		memset(in, 0, MLX5_ST_SZ_BYTES(create_tir_in));
		memset(out, 0, MLX5_ST_SZ_BYTES(create_tir_out));
		tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);

		MLX5_SET(tirc, tirc, transport_domain, hp->tdn);
		MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_INDIRECT);
		MLX5_SET(tirc, tirc, indirect_table, hp->indir_rqt.rqtn);
		mlx5e_build_indir_tir_ctx_hash(&priv->channels.params, tt, tirc, false);

		err = mlx5_core_create_tir(hp->func_mdev, in,
					   MLX5_ST_SZ_BYTES(create_tir_in),
					   out, MLX5_ST_SZ_BYTES(create_tir_out));
		if (err) {
			mlx5_core_warn(hp->func_mdev, "create indirect tirs failed, %d\n", err);
			goto err_destroy_tirs;
		}

		hp->indir_tirn[tt] = MLX5_GET(create_tir_out, out, tirn);
	}
	return 0;

err_destroy_tirs:
	for (i = 0; i < tt; i++)
		mlx5_core_destroy_tir(hp->func_mdev, hp->indir_tirn[i]);
	return err;
}

static void mlx5e_hairpin_destroy_indirect_tirs(struct mlx5e_hairpin *hp)
{
	int tt;

	for (tt = 0; tt < MLX5E_NUM_INDIR_TIRS; tt++)
		mlx5_core_destroy_tir(hp->func_mdev, hp->indir_tirn[tt]);
}

static void mlx5e_hairpin_set_ttc_params(struct mlx5e_hairpin *hp,
					 struct ttc_params *ttc_params)
{
	struct mlx5_flow_table_attr *ft_attr = &ttc_params->ft_attr;
	int tt;

	memset(ttc_params, 0, sizeof(*ttc_params));

	ttc_params->any_tt_tirn = hp->tirn;

	for (tt = 0; tt < MLX5E_NUM_INDIR_TIRS; tt++)
		ttc_params->indir_tirn[tt] = hp->indir_tirn[tt];

	ft_attr->max_fte = MLX5E_NUM_TT;
	ft_attr->level = MLX5E_TC_TTC_FT_LEVEL;
	ft_attr->prio = MLX5E_TC_PRIO;
}

static int mlx5e_hairpin_rss_init(struct mlx5e_hairpin *hp)
{
	struct mlx5e_priv *priv = hp->func_priv;
	struct ttc_params ttc_params;
	int err;

	err = mlx5e_hairpin_create_indirect_rqt(hp);
	if (err)
		return err;

	err = mlx5e_hairpin_create_indirect_tirs(hp);
	if (err)
		goto err_create_indirect_tirs;

	mlx5e_hairpin_set_ttc_params(hp, &ttc_params);
	err = mlx5e_create_ttc_table(priv, &ttc_params, &hp->ttc);
	if (err)
		goto err_create_ttc_table;

	netdev_dbg(priv->netdev, "add hairpin: using %d channels rss ttc table id %x\n",
		   hp->num_channels, hp->ttc.ft.t->id);

	return 0;

err_create_ttc_table:
	mlx5e_hairpin_destroy_indirect_tirs(hp);
err_create_indirect_tirs:
	mlx5e_destroy_rqt(priv, &hp->indir_rqt);

	return err;
}

static void mlx5e_hairpin_rss_cleanup(struct mlx5e_hairpin *hp)
{
	struct mlx5e_priv *priv = hp->func_priv;

	mlx5e_destroy_ttc_table(priv, &hp->ttc);
	mlx5e_hairpin_destroy_indirect_tirs(hp);
	mlx5e_destroy_rqt(priv, &hp->indir_rqt);
}

static struct mlx5e_hairpin *
mlx5e_hairpin_create(struct mlx5e_priv *priv, struct mlx5_hairpin_params *params,
		     int peer_ifindex)
{
	struct mlx5_core_dev *func_mdev, *peer_mdev;
	struct mlx5e_hairpin *hp;
	struct mlx5_hairpin *pair;
	int err;

	hp = kzalloc(sizeof(*hp), GFP_KERNEL);
	if (!hp)
		return ERR_PTR(-ENOMEM);

	func_mdev = priv->mdev;
	peer_mdev = mlx5e_hairpin_get_mdev(dev_net(priv->netdev), peer_ifindex);

	pair = mlx5_core_hairpin_create(func_mdev, peer_mdev, params);
	if (IS_ERR(pair)) {
		err = PTR_ERR(pair);
		goto create_pair_err;
	}
	hp->pair = pair;
	hp->func_mdev = func_mdev;
	hp->func_priv = priv;
	hp->num_channels = params->num_channels;

	err = mlx5e_hairpin_create_transport(hp);
	if (err)
		goto create_transport_err;

	if (hp->num_channels > 1) {
		err = mlx5e_hairpin_rss_init(hp);
		if (err)
			goto rss_init_err;
	}

	return hp;

rss_init_err:
	mlx5e_hairpin_destroy_transport(hp);
create_transport_err:
	mlx5_core_hairpin_destroy(hp->pair);
create_pair_err:
	kfree(hp);
	return ERR_PTR(err);
}

static void mlx5e_hairpin_destroy(struct mlx5e_hairpin *hp)
{
	if (hp->num_channels > 1)
		mlx5e_hairpin_rss_cleanup(hp);
	mlx5e_hairpin_destroy_transport(hp);
	mlx5_core_hairpin_destroy(hp->pair);
	kvfree(hp);
}

static inline u32 hash_hairpin_info(u16 peer_vhca_id, u8 prio)
{
	return (peer_vhca_id << 16 | prio);
}

static struct mlx5e_hairpin_entry *mlx5e_hairpin_get(struct mlx5e_priv *priv,
						     u16 peer_vhca_id, u8 prio)
{
	struct mlx5e_hairpin_entry *hpe;
	u32 hash_key = hash_hairpin_info(peer_vhca_id, prio);

	rcu_read_lock();
	hash_for_each_possible_rcu(priv->fs.tc.hairpin_tbl, hpe,
				   hairpin_hlist, hash_key) {
		if (hpe->peer_vhca_id == peer_vhca_id && hpe->prio == prio &&
		    refcount_inc_not_zero(&hpe->refcnt)) {
			rcu_read_unlock();
			return hpe;
		}
	}
	rcu_read_unlock();

	return NULL;
}

static struct mlx5e_hairpin_entry *
mlx5e_hairpin_get_create(struct mlx5e_priv *priv, int peer_ifindex, u16 peer_id,
			 u8 match_prio)
{
	struct mlx5e_hairpin_entry *hpe, *hpe_dup = NULL;
	struct mlx5_hairpin_params params;
	struct mlx5e_hairpin *hp;
	u64 link_speed64;
	u32 link_speed;
	int err;

	hpe = mlx5e_hairpin_get(priv, peer_id, match_prio);
	if (hpe)
		return hpe;

	hpe = kzalloc(sizeof(*hpe), GFP_KERNEL);
	if (!hpe)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&hpe->flows_lock);
	INIT_LIST_HEAD(&hpe->flows);
	hpe->peer_vhca_id = peer_id;
	hpe->prio = match_prio;
	refcount_set(&hpe->refcnt, 1);

	params.log_data_size = 15;
	params.log_data_size = min_t(u8, params.log_data_size,
				     MLX5_CAP_GEN(priv->mdev,
						  log_max_hairpin_wq_data_sz));
	params.log_data_size = max_t(u8, params.log_data_size,
				     MLX5_CAP_GEN(priv->mdev,
						  log_min_hairpin_wq_data_sz));

	params.log_num_packets = params.log_data_size -
				 MLX5_MPWRQ_MIN_LOG_STRIDE_SZ(priv->mdev);
	params.log_num_packets = min_t(u8, params.log_num_packets,
				       MLX5_CAP_GEN(priv->mdev,
						    log_max_hairpin_num_packets));

	params.q_counter = priv->q_counter;
	/* set hairpin pair per each 50Gbs share of the link */
	mlx5e_port_max_linkspeed(priv->mdev, &link_speed);
	link_speed = max_t(u32, link_speed, 50000);
	link_speed64 = link_speed;
	do_div(link_speed64, 50000);
	params.num_channels = link_speed64;

	hp = mlx5e_hairpin_create(priv, &params, peer_ifindex);
	if (IS_ERR(hp)) {
		err = PTR_ERR(hp);
		goto create_hairpin_err;
	}

	netdev_dbg(priv->netdev, "add hairpin: tirn %x rqn %x peer %s sqn %x prio %d (log) data %d packets %d\n",
		   hp->tirn, hp->pair->rqn[0], hp->pair->peer_mdev->priv.name,
		   hp->pair->sqn[0], match_prio, params.log_data_size,
		   params.log_num_packets);

	hpe->hp = hp;

	spin_lock(&priv->fs.tc.hairpin_tbl_lock);
	/* check for concurrent insertion of hairpin entry with same params */
	hpe_dup = mlx5e_hairpin_get(priv, peer_id, match_prio);
	if (hpe_dup)
		goto create_hairpin_err_locked;

	hash_add_rcu(priv->fs.tc.hairpin_tbl, &hpe->hairpin_hlist,
		     hash_hairpin_info(peer_id, match_prio));
	spin_unlock(&priv->fs.tc.hairpin_tbl_lock);

	return hpe;

create_hairpin_err_locked:
	spin_unlock(&priv->fs.tc.hairpin_tbl_lock);
	mlx5e_hairpin_destroy(hpe->hp);
create_hairpin_err:
	kfree(hpe);
	if (hpe_dup)
		return hpe_dup;
	return ERR_PTR(err);
}

static void mlx5e_hairpin_put(struct mlx5e_priv *priv,
			      struct mlx5e_hairpin_entry *hpe)
{
	/* no more hairpin flows for us, release the hairpin pair */
	if (refcount_dec_and_test(&hpe->refcnt)) {
		netdev_dbg(priv->netdev, "del hairpin: peer %s\n",
			   hpe->hp->pair->peer_mdev->priv.name);

		WARN_ON(!list_empty(&hpe->flows));
		mlx5e_hairpin_destroy(hpe->hp);
		spin_lock(&priv->fs.tc.hairpin_tbl_lock);
		hash_del_rcu(&hpe->hairpin_hlist);
		spin_unlock(&priv->fs.tc.hairpin_tbl_lock);
		kfree_rcu(hpe, rcu);
	}
}

#define UNKNOWN_MATCH_PRIO 8

static int mlx5e_hairpin_get_prio(struct mlx5e_priv *priv,
				  struct mlx5_flow_spec *spec, u8 *match_prio,
				  struct netlink_ext_ack *extack)
{
	void *headers_c, *headers_v;
	u8 prio_val, prio_mask = 0;
	bool vlan_present;

#ifdef CONFIG_MLX5_CORE_EN_DCB
	if (priv->dcbx_dp.trust_state != MLX5_QPTS_TRUST_PCP) {
		NL_SET_ERR_MSG_MOD(extack,
				   "only PCP trust state supported for hairpin");
		return -EOPNOTSUPP;
	}
#endif
	headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, outer_headers);
	headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value, outer_headers);

	vlan_present = MLX5_GET(fte_match_set_lyr_2_4, headers_v, cvlan_tag);
	if (vlan_present) {
		prio_mask = MLX5_GET(fte_match_set_lyr_2_4, headers_c, first_prio);
		prio_val = MLX5_GET(fte_match_set_lyr_2_4, headers_v, first_prio);
	}

	if (!vlan_present || !prio_mask) {
		prio_val = UNKNOWN_MATCH_PRIO;
	} else if (prio_mask != 0x7) {
		NL_SET_ERR_MSG_MOD(extack,
				   "masked priority match not supported for hairpin");
		return -EOPNOTSUPP;
	}

	*match_prio = prio_val;
	return 0;
}

static int mlx5e_hairpin_flow_add(struct mlx5e_priv *priv,
				  struct mlx5e_tc_flow *flow,
				  struct mlx5e_tc_flow_parse_attr *parse_attr,
				  struct netlink_ext_ack *extack)
{
	int peer_ifindex = parse_attr->mirred_ifindex;
	struct mlx5_core_dev *peer_mdev;
	struct mlx5e_hairpin_entry *hpe;
	u8 match_prio;
	u16 peer_id;
	int err;

	peer_mdev = mlx5e_hairpin_get_mdev(dev_net(priv->netdev), peer_ifindex);
	if (!MLX5_CAP_GEN(priv->mdev, hairpin) || !MLX5_CAP_GEN(peer_mdev, hairpin)) {
		NL_SET_ERR_MSG_MOD(extack, "hairpin is not supported");
		return -EOPNOTSUPP;
	}

	peer_id = MLX5_CAP_GEN(peer_mdev, vhca_id);
	err = mlx5e_hairpin_get_prio(priv, &parse_attr->spec, &match_prio,
				     extack);
	if (err)
		return err;
	hpe = mlx5e_hairpin_get_create(priv, peer_ifindex, peer_id, match_prio);
	if (IS_ERR(hpe))
		return PTR_ERR(hpe);

	if (hpe->hp->num_channels > 1) {
		atomic_or(MLX5E_TC_FLOW_HAIRPIN_RSS, &flow->flags);
		flow->nic_attr->hairpin_ft = hpe->hp->ttc.ft.t;
	} else {
		flow->nic_attr->hairpin_tirn = hpe->hp->tirn;
	}
	flow->hpe = hpe;
	spin_lock(&hpe->flows_lock);
	list_add(&flow->hairpin, &hpe->flows);
	spin_unlock(&hpe->flows_lock);

	return 0;
}

static void mlx5e_hairpin_flow_del(struct mlx5e_priv *priv,
				   struct mlx5e_tc_flow *flow)
{
	/* flow wasn't fully initialized */
	if (!flow->hpe)
		return;

	spin_lock(&flow->hpe->flows_lock);
	list_del(&flow->hairpin);
	spin_unlock(&flow->hpe->flows_lock);

	mlx5e_hairpin_put(priv, flow->hpe);
	flow->hpe = NULL;
}

static int
mlx5e_tc_add_nic_flow(struct mlx5e_priv *priv,
		      struct mlx5e_tc_flow_parse_attr *parse_attr,
		      struct mlx5e_tc_flow *flow,
		      struct netlink_ext_ack *extack)
{
	struct mlx5_nic_flow_attr *attr = flow->nic_attr;
	struct mlx5_core_dev *dev = priv->mdev;
	struct mlx5_flow_destination dest[2] = {};
	struct mlx5_flow_act flow_act = {
		.action = attr->action,
		.flow_tag = attr->flow_tag,
		.reformat_id = 0,
		.flags    = FLOW_ACT_HAS_TAG | FLOW_ACT_NO_APPEND,
	};
	struct mlx5_fc *counter = NULL;
	int err, dest_ix = 0;

	if (atomic_read(&flow->flags) & MLX5E_TC_FLOW_HAIRPIN) {
		err = mlx5e_hairpin_flow_add(priv, flow, parse_attr, extack);
		if (err)
			return err;

		if (atomic_read(&flow->flags) & MLX5E_TC_FLOW_HAIRPIN_RSS) {
			dest[dest_ix].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
			dest[dest_ix].ft = attr->hairpin_ft;
		} else {
			dest[dest_ix].type = MLX5_FLOW_DESTINATION_TYPE_TIR;
			dest[dest_ix].tir_num = attr->hairpin_tirn;
		}
		dest_ix++;
	} else if (attr->action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) {
		dest[dest_ix].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
		dest[dest_ix].ft = priv->fs.vlan.ft.t;
		dest_ix++;
	}

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_COUNT) {
		counter = mlx5_fc_create(dev, true);
		if (IS_ERR(counter))
			return PTR_ERR(counter);

		dest[dest_ix].type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
		dest[dest_ix].counter_id = mlx5_fc_id(counter);
		dest_ix++;
		attr->counter = counter;
	}

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR) {
		err = mlx5e_attach_mod_hdr(priv, flow, parse_attr);
		flow_act.modify_id = attr->mod_hdr_id;
		if (err)
			return err;
	}

	mutex_lock(&priv->fs.tc.t_lock);
	if (IS_ERR_OR_NULL(priv->fs.tc.t)) {
		int tc_grp_size, tc_tbl_size;
		u32 max_flow_counter;

		max_flow_counter = (MLX5_CAP_GEN(dev, max_flow_counter_31_16) << 16) |
				    MLX5_CAP_GEN(dev, max_flow_counter_15_0);

		tc_grp_size = min_t(int, max_flow_counter, MLX5E_TC_TABLE_MAX_GROUP_SIZE);

		tc_tbl_size = min_t(int, tc_grp_size * MLX5E_TC_TABLE_NUM_GROUPS,
				    BIT(MLX5_CAP_FLOWTABLE_NIC_RX(dev, log_max_ft_size)));

		priv->fs.tc.t =
			mlx5_create_auto_grouped_flow_table(priv->fs.ns,
							    MLX5E_TC_PRIO,
							    tc_tbl_size,
							    MLX5E_TC_TABLE_NUM_GROUPS,
							    MLX5E_TC_FT_LEVEL, 0);
		if (IS_ERR(priv->fs.tc.t)) {
			mutex_unlock(&priv->fs.tc.t_lock);
			NL_SET_ERR_MSG_MOD(extack,
					   "Failed to create tc offload table\n");
			netdev_err(priv->netdev,
				   "Failed to create tc offload table\n");
			return PTR_ERR(priv->fs.tc.t);
		}
	}

	if (attr->match_level != MLX5_MATCH_NONE)
		parse_attr->spec.match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;

	flow->rule[0] = mlx5_add_flow_rules(priv->fs.tc.t, &parse_attr->spec,
					    &flow_act, dest, dest_ix);
	mutex_unlock(&priv->fs.tc.t_lock);

	if (IS_ERR(flow->rule[0]))
		return PTR_ERR(flow->rule[0]);

	return 0;
}

static void mlx5e_tc_del_nic_flow(struct mlx5e_priv *priv,
				  struct mlx5e_tc_flow *flow)
{
	struct mlx5_nic_flow_attr *attr = flow->nic_attr;
	struct mlx5_fc *counter = NULL;

	counter = attr->counter;
	if (!IS_ERR_OR_NULL(flow->rule[0]))
		mlx5_del_flow_rules(flow->rule[0]);
	mlx5_fc_destroy(priv->mdev, counter);

	mutex_lock(&priv->fs.tc.t_lock);
	if (!mlx5e_tc_num_filters(priv, MLX5E_TC_NIC_OFFLOAD)  && priv->fs.tc.t) {
		mlx5_destroy_flow_table(priv->fs.tc.t);
		priv->fs.tc.t = NULL;
	}
	mutex_unlock(&priv->fs.tc.t_lock);

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)
		mlx5e_detach_mod_hdr(priv, flow);

	if (atomic_read(&flow->flags) & MLX5E_TC_FLOW_HAIRPIN)
		mlx5e_hairpin_flow_del(priv, flow);
}

static void mlx5e_detach_encap(struct mlx5e_priv *priv,
			       struct mlx5e_tc_flow *flow);

static int mlx5e_attach_encap(struct mlx5e_priv *priv,
			      struct ip_tunnel_info *tun_info,
			      struct net_device *mirred_dev,
			      struct net_device **encap_dev,
			      struct mlx5e_tc_flow *flow,
			      struct netlink_ext_ack *extack);

static struct mlx5_flow_handle *
mlx5e_tc_offload_fdb_rules(struct mlx5_eswitch *esw,
			   struct mlx5e_tc_flow *flow,
			   struct mlx5_flow_spec *spec,
			   struct mlx5_esw_flow_attr *attr)
{
	struct mlx5_flow_handle *rule;

	rule = mlx5_eswitch_add_offloaded_rule(esw, spec, attr);
	if (IS_ERR(rule))
		return rule;

	if (attr->mirror_count) {
		flow->rule[1] = mlx5_eswitch_add_fwd_rule(esw, spec, attr);
		if (IS_ERR(flow->rule[1])) {
			mlx5_eswitch_del_offloaded_rule(esw, rule, attr);
			return flow->rule[1];
		}
	}

	return rule;
}

static void
mlx5e_tc_unoffload_fdb_rules(struct mlx5_eswitch *esw,
			     struct mlx5e_tc_flow *flow,
			   struct mlx5_esw_flow_attr *attr)
{
	atomic_and(~MLX5E_TC_FLOW_OFFLOADED, &flow->flags);

	if (attr->mirror_count)
		mlx5_eswitch_del_fwd_rule(esw, flow->rule[1], attr);

	mlx5_eswitch_del_offloaded_rule(esw, flow->rule[0], attr);
}

static struct mlx5_flow_handle *
mlx5e_tc_offload_to_slow_path(struct mlx5_eswitch *esw,
			      struct mlx5e_tc_flow *flow,
			      struct mlx5_flow_spec *spec,
			      struct mlx5_esw_flow_attr *slow_attr)
{
	struct mlx5_flow_handle *rule;

	memcpy(slow_attr, flow->esw_attr, sizeof(*slow_attr));
	slow_attr->action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	slow_attr->mirror_count = 0;
	slow_attr->dest_chain = FDB_SLOW_PATH_CHAIN;

	rule = mlx5e_tc_offload_fdb_rules(esw, flow, spec, slow_attr);
	if (!IS_ERR(rule))
		atomic_or(MLX5E_TC_FLOW_SLOW, &flow->flags);

	return rule;
}

static void
mlx5e_tc_unoffload_from_slow_path(struct mlx5_eswitch *esw,
				  struct mlx5e_tc_flow *flow,
				  struct mlx5_esw_flow_attr *slow_attr)
{
	memcpy(slow_attr, flow->esw_attr, sizeof(*slow_attr));
	slow_attr->action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	slow_attr->mirror_count = 0;
	slow_attr->dest_chain = FDB_SLOW_PATH_CHAIN;
	mlx5e_tc_unoffload_fdb_rules(esw, flow, slow_attr);
	atomic_and(~MLX5E_TC_FLOW_SLOW, &flow->flags);
}

static void add_unready_flow(struct mlx5e_tc_flow *flow)
{
	struct mlx5e_rep_priv *rpriv;
	struct mlx5_eswitch *esw;

	esw = flow->priv->mdev->priv.eswitch;
	rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);

	atomic_or(MLX5E_TC_FLOW_NOT_READY, &flow->flags);
	list_add_tail(&flow->unready, &rpriv->unready_flows);
}

static void remove_unready_flow(struct mlx5e_tc_flow *flow)
{
	list_del(&flow->unready);
	atomic_and(~MLX5E_TC_FLOW_NOT_READY, &flow->flags);
}

static int
mlx5e_tc_add_fdb_flow(struct mlx5e_priv *priv,
		      struct mlx5e_tc_flow_parse_attr *parse_attr,
		      struct mlx5e_tc_flow *flow,
		      struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	u32 max_chain = mlx5_eswitch_get_chain_range(esw);
	struct mlx5_esw_flow_attr *attr = flow->esw_attr;
	u16 max_prio = mlx5_eswitch_get_prio_range(esw);
	struct net_device *out_dev, *encap_dev = NULL;
	struct mlx5_fc *counter = NULL;
	struct mlx5e_rep_priv *rpriv;
	struct mlx5e_priv *out_priv;
	int err = 0, encap_err = 0;

	if (!mlx5_eswitch_prios_supported(esw) && attr->prio != 1) {
		NL_SET_ERR_MSG(extack, "E-switch priorities unsupported, upgrade FW");
		return -EOPNOTSUPP;
	}

	if (attr->chain > max_chain) {
		NL_SET_ERR_MSG(extack, "Requested chain is out of supported range");
		return -EOPNOTSUPP;
	}

	if (attr->prio > max_prio) {
		NL_SET_ERR_MSG(extack, "Requested priority is out of supported range");
		return -EOPNOTSUPP;
	}

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT) {
		out_dev = __dev_get_by_index(dev_net(priv->netdev),
					     attr->parse_attr->mirred_ifindex);
		encap_err = mlx5e_attach_encap(priv, &parse_attr->tun_info,
					       out_dev, &encap_dev, flow,
					       extack);
		if (encap_err && encap_err != -EAGAIN)
			return encap_err;

		out_priv = netdev_priv(encap_dev);
		rpriv = out_priv->ppriv;
		attr->out_rep[attr->out_count] = rpriv->rep;
		attr->out_mdev[attr->out_count++] = out_priv->mdev;
	}

	err = mlx5_eswitch_add_vlan_action(esw, attr);
	if (err)
		return err;

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR) {
		err = mlx5e_attach_mod_hdr(priv, flow, parse_attr);
		kfree(parse_attr->mod_hdr_actions);
		parse_attr->mod_hdr_actions = NULL;
		if (err)
			return err;
	}

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_COUNT) {
		counter = mlx5_fc_create(esw->dev, true);
		if (IS_ERR(counter))
			return PTR_ERR(counter);

		attr->counter = counter;
	}

	/* we get here if (1) there's no error or when
	 * (2) there's an encap action and we're on -EAGAIN (no valid neigh)
	 */
	if (encap_err == -EAGAIN) {
		/* continue with goto slow path rule instead */
		struct mlx5_esw_flow_attr slow_attr;

		flow->rule[0] = mlx5e_tc_offload_to_slow_path(esw, flow, &parse_attr->spec, &slow_attr);
	} else {
		flow->rule[0] = mlx5e_tc_offload_fdb_rules(esw, flow, &parse_attr->spec, attr);
	}

	if (IS_ERR(flow->rule[0]))
		return PTR_ERR(flow->rule[0]);
	else
		mlx5e_set_flow_flag_mb_before(flow, MLX5E_TC_FLOW_OFFLOADED);

	return 0;
}

static void mlx5e_tc_del_fdb_flow(struct mlx5e_priv *priv,
				  struct mlx5e_tc_flow *flow)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_esw_flow_attr *attr = flow->esw_attr;
	struct mlx5_esw_flow_attr slow_attr;

	if (atomic_read(&flow->flags) & MLX5E_TC_FLOW_NOT_READY) {
		remove_unready_flow(flow);
#ifdef HAVE_TCF_TUNNEL_INFO
		if (attr->action & MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT)
			kvfree(attr->parse_attr);
#endif
		return;
	}

	if (mlx5e_is_offloaded_flow(flow)) {
		if (atomic_read(&flow->flags) & MLX5E_TC_FLOW_SLOW)
			mlx5e_tc_unoffload_from_slow_path(esw, flow, &slow_attr);
		else
			mlx5e_tc_unoffload_fdb_rules(esw, flow, attr);
	}

	mlx5_eswitch_del_vlan_action(esw, attr);

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT)
		mlx5e_detach_encap(priv, flow);

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)
		mlx5e_detach_mod_hdr(priv, flow);

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_COUNT)
		mlx5_fc_destroy(esw->dev, attr->counter);

	if (attr->parse_attr) {
		kfree(attr->parse_attr->mod_hdr_actions);
		kvfree(attr->parse_attr);
	}
}

static void mlx5e_put_flow_list(struct mlx5e_priv *priv,
				struct list_head *flow_list)
{
	struct mlx5e_tc_flow *flow, *tmp;

	list_for_each_entry_safe(flow, tmp, flow_list, tmp_list) {
		list_del(&flow->tmp_list);
		mlx5e_flow_put(priv, flow);
	}
}

void mlx5e_tc_encap_flows_add(struct mlx5e_priv *priv,
			      struct mlx5e_encap_entry *e,
			      unsigned long n_updated)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_esw_flow_attr slow_attr, *esw_attr;
	struct mlx5e_tc_flow *flow, *tmp;
	struct mlx5_flow_handle *rule;
	struct mlx5_flow_spec *spec;
	LIST_HEAD(added_flows);
	u32 encap_id;
	int err;

	err = mlx5_packet_reformat_alloc(priv->mdev, e->tunnel_type,
					 e->encap_size, e->encap_header,
					 MLX5_FLOW_NAMESPACE_FDB,
					 &encap_id);
	if (err) {
		mlx5_core_warn(priv->mdev, "Failed to offload cached encapsulation header, %d\n",
			       err);
		return;
	}

	mlx5e_rep_queue_neigh_stats_work(priv);
	mutex_lock(&e->encap_entry_lock);
	e->encap_id = encap_id;
	e->flags |= MLX5_ENCAP_ENTRY_VALID;
	e->updated = n_updated;

	list_for_each_entry_safe(flow, tmp, &e->flows, encap) {
		if (IS_ERR(mlx5e_flow_get(flow)))
			continue;

		list_add(&flow->tmp_list, &added_flows);
		esw_attr = flow->esw_attr;
		esw_attr->encap_id = e->encap_id;
		spec = &esw_attr->parse_attr->spec;

		/* update from slow path rule to encap rule */
		rule = mlx5e_tc_offload_fdb_rules(esw, flow, spec, esw_attr);
		if (IS_ERR(rule)) {
			err = PTR_ERR(rule);
			mlx5_core_warn(priv->mdev, "Failed to update cached encapsulation flow, %d\n",
				       err);
			continue;
		}

		mlx5e_tc_unoffload_from_slow_path(esw, flow, &slow_attr);
		flow->rule[0] = rule;
		/* was unset when slow path rule removed */
		mlx5e_set_flow_flag_mb_before(flow, MLX5E_TC_FLOW_OFFLOADED);
	}

	mutex_unlock(&e->encap_entry_lock);
	mlx5e_put_flow_list(priv, &added_flows);
}

void mlx5e_tc_encap_flows_del(struct mlx5e_priv *priv,
			      struct mlx5e_encap_entry *e,
			      unsigned long n_updated)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_esw_flow_attr slow_attr;
	struct mlx5e_tc_flow *flow, *tmp;
	struct mlx5_flow_handle *rule;
	struct mlx5_flow_spec *spec;
	LIST_HEAD(deleted_flows);
	int err;

	mutex_lock(&e->encap_entry_lock);
	list_for_each_entry_safe(flow, tmp, &e->flows, encap) {
		if (IS_ERR(mlx5e_flow_get(flow)))
			continue;

		list_add(&flow->tmp_list, &deleted_flows);
		spec = &flow->esw_attr->parse_attr->spec;

		/* update from encap rule to slow path rule */
		rule = mlx5e_tc_offload_to_slow_path(esw, flow, spec, &slow_attr);

		if (IS_ERR(rule)) {
			err = PTR_ERR(rule);
			mlx5_core_warn(priv->mdev, "Failed to update slow path (encap) flow, %d\n",
				       err);
			continue;
		}

		mlx5e_tc_unoffload_fdb_rules(esw, flow, flow->esw_attr);
		flow->rule[0] = rule;
		/* was unset when fast path rule removed */
		mlx5e_set_flow_flag_mb_before(flow, MLX5E_TC_FLOW_OFFLOADED);
	}

	e->updated = n_updated;
	/* we know that the encap is valid */
	e->flags &= ~MLX5_ENCAP_ENTRY_VALID;
	mlx5_packet_reformat_dealloc(priv->mdev, e->encap_id);
	mutex_unlock(&e->encap_entry_lock);

	mlx5e_put_flow_list(priv, &deleted_flows);
}

static struct mlx5_fc *mlx5e_tc_get_counter(struct mlx5e_tc_flow *flow)
{
	if (mlx5e_is_eswitch_flow(flow))
		return flow->esw_attr->counter;
	else
		return flow->nic_attr->counter;
}

static struct mlx5e_tc_flow *
mlx5e_get_next_encap_flow(struct mlx5e_encap_entry *e,
			  struct mlx5e_tc_flow *flow)
{
	struct mlx5e_tc_flow *next = NULL;
	bool found = false;

	mutex_lock(&e->encap_entry_lock);

	if (flow) {
		next = flow;
		list_for_each_entry_continue(next, &e->flows, encap)
			if (!IS_ERR(mlx5e_flow_get(next))) {
				found = true;
				break;
			}
	} else {
		list_for_each_entry(next, &e->flows, encap)
			if (!IS_ERR(mlx5e_flow_get(next))) {
				found = true;
				break;
			}
	}

	mutex_unlock(&e->encap_entry_lock);

	if (flow)
		mlx5e_flow_put(netdev_priv(e->out_dev), flow);

	return found ? next : NULL;
}

#ifndef list_next_or_null_rcu
/**
 * list_next_or_null_rcu - get the first element from a list
 * @head:       the head for the list.
 * @ptr:        the list head to take the next element from.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_head within the struct.
 *
 * Note that if the ptr is at the end of the list, NULL is returned.
 *
 * This primitive may safely run concurrently with the _rcu list-mutation
 * primitives such as list_add_rcu() as long as it's guarded by rcu_read_lock().
 */
#define list_next_or_null_rcu(head, ptr, type, member) \
({ \
	struct list_head *__head = (head); \
	struct list_head *__ptr = (ptr); \
	struct list_head *__next = READ_ONCE(__ptr->next); \
	likely(__next != __head) ? list_entry_rcu(__next, type, \
						  member) : NULL; \
})
#endif

static struct mlx5e_encap_entry *
mlx5e_get_next_valid_encap(struct mlx5e_neigh_hash_entry *nhe,
			   struct mlx5e_encap_entry *e)
{
	struct mlx5e_encap_entry *next = NULL;

	rcu_read_lock();

	for (next = e ?
		     list_next_or_null_rcu(&nhe->encap_list,
					   &e->encap_list,
					   struct mlx5e_encap_entry,
					   encap_list) :
		     list_first_or_null_rcu(&nhe->encap_list,
					    struct mlx5e_encap_entry,
					    encap_list);
	     next;
	     next = list_next_or_null_rcu(&nhe->encap_list,
					  &next->encap_list,
					  struct mlx5e_encap_entry,
					  encap_list))
		if ((next->flags & MLX5_ENCAP_ENTRY_VALID) &&
		    mlx5e_encap_take(next))
			break;

	rcu_read_unlock();

	if (e)
		mlx5e_encap_put(netdev_priv(e->out_dev), e);

	return next;
}

void mlx5e_tc_update_neigh_used_value(struct mlx5e_neigh_hash_entry *nhe)
{
	struct mlx5e_neigh *m_neigh = &nhe->m_neigh;
	struct mlx5e_encap_entry *e = NULL;
	struct mlx5e_tc_flow *flow = NULL;
	u64 bytes, packets, lastuse = 0;
	struct mlx5_fc *counter;
	struct neigh_table *tbl;
	bool neigh_used = false;
	struct neighbour *n;

	if (m_neigh->family == AF_INET)
		tbl = &arp_tbl;
#if IS_ENABLED(CONFIG_IPV6)
	else if (m_neigh->family == AF_INET6)
		tbl = &nd_tbl;
#endif
	else
		return;

	while ((e = mlx5e_get_next_valid_encap(nhe, e)) != NULL) {
		while ((flow = mlx5e_get_next_encap_flow(e, flow)) != NULL) {
			if (mlx5e_is_offloaded_flow(flow)) {
				counter = mlx5e_tc_get_counter(flow);
				mlx5_fc_query_cached(counter, &bytes, &packets, &lastuse);
				if (time_after((unsigned long)lastuse, nhe->reported_lastuse)) {
					mlx5e_flow_put(netdev_priv(e->out_dev),
						       flow);
					neigh_used = true;
					break;
				}
			}
		}
		if (neigh_used) {
			mlx5e_encap_put(netdev_priv(e->out_dev), e);
			break;
		}
	}

	if (neigh_used) {
		nhe->reported_lastuse = jiffies;

		/* find the relevant neigh according to the cached device and
		 * dst ip pair
		 */
		n = neigh_lookup(tbl, &m_neigh->dst_ip, m_neigh->dev);
		if (!n)
			return;

		neigh_event_send(n, NULL);
		neigh_release(n);
	}
}

void mlx5e_encap_put(struct mlx5e_priv *priv, struct mlx5e_encap_entry *e)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;

	if (refcount_dec_and_test(&e->refcnt)) {
		WARN_ON(!list_empty(&e->flows));
		/* encap can be deleted before attachment to dev if error
		 * happens during encap initialization
		 */
		if (e->out_dev)
			mlx5e_rep_encap_entry_detach(netdev_priv(e->out_dev),
						     e);

		if (e->flags & MLX5_ENCAP_ENTRY_VALID)
			mlx5_packet_reformat_dealloc(priv->mdev, e->encap_id);

		mutex_destroy(&e->encap_entry_lock);
		spin_lock(&esw->offloads.encap_tbl_lock);
		hash_del_rcu(&e->encap_hlist);
		spin_unlock(&esw->offloads.encap_tbl_lock);
		kfree(e->encap_header);
		kfree_rcu(e, rcu);
	}
}

static void mlx5e_detach_encap(struct mlx5e_priv *priv,
			       struct mlx5e_tc_flow *flow)
{
	struct mlx5e_encap_entry *e = flow->e;

	/* flow wasn't fully initialized */
	if (!e)
		return;

	mutex_lock(&e->encap_entry_lock);
	list_del(&flow->encap);
	mutex_unlock(&e->encap_entry_lock);

	mlx5e_encap_put(priv, e);
	flow->e = NULL;
}

static int mlx5e_reoffload_uninit_flow(struct mlx5e_priv *priv,
				       struct mlx5e_tc_flow *flow,
				       struct mlx5e_encap_entry *e)
{
	struct mlx5_esw_flow_attr *esw_attr = flow->esw_attr;
	struct mlx5_flow_spec *spec = &esw_attr->parse_attr->spec;
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_esw_flow_attr slow_attr;
	struct mlx5_flow_handle *rule;
	int err = 0;

	if (atomic_read(&flow->flags) & MLX5E_TC_FLOW_SLOW)
		mlx5e_tc_unoffload_from_slow_path(esw, flow, &slow_attr);
	else
		mlx5e_tc_unoffload_fdb_rules(esw, flow, flow->esw_attr);

	rule = e->flags & MLX5_ENCAP_ENTRY_VALID ?
		mlx5e_tc_offload_fdb_rules(esw, flow, spec, esw_attr) :
		mlx5e_tc_offload_to_slow_path(esw, flow, spec, &slow_attr);

	if (IS_ERR(rule))
		err = PTR_ERR(rule);
	else
		flow->rule[0] = rule;

	return err;
}

static int mlx5e_tc_update_and_init_done_fdb_flow(struct mlx5e_priv *priv,
						  struct mlx5e_tc_flow *flow)
{
	int err = 0;

	if ((flow->esw_attr->action &
	     MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT) &&
	    flow->e) {
		struct mlx5e_encap_entry *e = flow->e;

		mutex_lock(&e->encap_entry_lock);

		/* Encap neighbor was concurrently updated during flow init. */
		if (flow->encap_init_jiffies != e->updated)
			err = mlx5e_reoffload_uninit_flow(priv, flow, e);

		if (!err)
			mlx5e_set_flow_flag_mb_before(flow,
						      MLX5E_TC_FLOW_INIT_DONE);
		mutex_unlock(&e->encap_entry_lock);
	} else {
		mlx5e_set_flow_flag_mb_before(flow, MLX5E_TC_FLOW_INIT_DONE);
	}

	return err;
}

static void __mlx5e_tc_del_fdb_peer_flow(struct mlx5e_tc_flow *flow)
{
	struct mlx5_eswitch *esw = flow->priv->mdev->priv.eswitch;

	if (!(atomic_read(&flow->flags) & MLX5E_TC_FLOW_ESWITCH) ||
	    !(atomic_read(&flow->flags) & MLX5E_TC_FLOW_DUP))
		return;

	mutex_lock(&esw->offloads.peer_mutex);
	list_del(&flow->peer);
	mutex_unlock(&esw->offloads.peer_mutex);

	atomic_and(~MLX5E_TC_FLOW_DUP, &flow->flags);

	mlx5e_tc_del_fdb_flow(flow->peer_flow->priv, flow->peer_flow);
	kvfree(flow->peer_flow);
	flow->peer_flow = NULL;
}

static void mlx5e_tc_del_fdb_peer_flow(struct mlx5e_tc_flow *flow)
{
	struct mlx5_core_dev *dev = flow->priv->mdev;
	struct mlx5_devcom *devcom = dev->priv.devcom;
	struct mlx5_eswitch *peer_esw;

	peer_esw = mlx5_devcom_get_peer_data(devcom, MLX5_DEVCOM_ESW_OFFLOADS);
	if (!peer_esw)
		return;

	__mlx5e_tc_del_fdb_peer_flow(flow);
	mlx5_devcom_release_peer_data(devcom, MLX5_DEVCOM_ESW_OFFLOADS);
}

static void mlx5e_tc_del_flow(struct mlx5e_priv *priv,
			      struct mlx5e_tc_flow *flow)
{
	if (mlx5e_is_eswitch_flow(flow)) {
		mlx5e_tc_del_fdb_peer_flow(flow);
		mlx5e_tc_del_fdb_flow(priv, flow);
	} else {
		mlx5e_tc_del_nic_flow(priv, flow);
	}
}

static void parse_vxlan_attr(struct mlx5_flow_spec *spec,
			     struct tc_cls_flower_offload *f)
{
	void *headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				       outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				       outer_headers);
	void *misc_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				    misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				    misc_parameters);

	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_protocol);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol, IPPROTO_UDP);

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ENC_KEYID)) {
		struct flow_dissector_key_keyid *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_KEYID,
						  f->key);
		struct flow_dissector_key_keyid *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_KEYID,
						  f->mask);
		MLX5_SET(fte_match_set_misc, misc_c, vxlan_vni,
			 be32_to_cpu(mask->keyid));
		MLX5_SET(fte_match_set_misc, misc_v, vxlan_vni,
			 be32_to_cpu(key->keyid));
	}
}

static int parse_tunnel_attr(struct mlx5e_priv *priv,
			     struct mlx5_flow_spec *spec,
			     struct tc_cls_flower_offload *f,
			     u8 *match_level)
{
	struct netlink_ext_ack *extack = f->common.extack;
	void *headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				       outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				       outer_headers);

	struct flow_dissector_key_control *enc_control =
		skb_flow_dissector_target(f->dissector,
					  FLOW_DISSECTOR_KEY_ENC_CONTROL,
					  f->key);

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ENC_PORTS)) {
		struct flow_dissector_key_ports *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_PORTS,
						  f->key);
		struct flow_dissector_key_ports *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_PORTS,
						  f->mask);

		/* Full udp dst port must be given */
		if (memchr_inv(&mask->dst, 0xff, sizeof(mask->dst)))
			goto vxlan_match_offload_err;

		if (mlx5_vxlan_lookup_port(priv->mdev->vxlan, be16_to_cpu(key->dst)) &&
		    MLX5_CAP_ESW(priv->mdev, vxlan_encap_decap))
			parse_vxlan_attr(spec, f);
		else {
			NL_SET_ERR_MSG_MOD(extack,
					   "port isn't an offloaded vxlan udp dport");
			netdev_warn(priv->netdev,
				    "%d isn't an offloaded vxlan udp dport\n", be16_to_cpu(key->dst));
			return -EOPNOTSUPP;
		}

		*match_level = MLX5_MATCH_L4;
		MLX5_SET(fte_match_set_lyr_2_4, headers_c,
			 udp_dport, ntohs(mask->dst));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v,
			 udp_dport, ntohs(key->dst));

		MLX5_SET(fte_match_set_lyr_2_4, headers_c,
			 udp_sport, ntohs(mask->src));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v,
			 udp_sport, ntohs(key->src));
	} else { /* udp dst port must be given */
vxlan_match_offload_err:
		NL_SET_ERR_MSG_MOD(extack,
				   "IP tunnel decap offload supported only for vxlan, must set UDP dport");
		netdev_warn(priv->netdev,
			    "IP tunnel decap offload supported only for vxlan, must set UDP dport\n");
		return -EOPNOTSUPP;
	}

	if (enc_control->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_dissector_key_ipv4_addrs *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS,
						  f->key);
		struct flow_dissector_key_ipv4_addrs *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS,
						  f->mask);
		MLX5_SET(fte_match_set_lyr_2_4, headers_c,
			 src_ipv4_src_ipv6.ipv4_layout.ipv4,
			 ntohl(mask->src));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v,
			 src_ipv4_src_ipv6.ipv4_layout.ipv4,
			 ntohl(key->src));

		MLX5_SET(fte_match_set_lyr_2_4, headers_c,
			 dst_ipv4_dst_ipv6.ipv4_layout.ipv4,
			 ntohl(mask->dst));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v,
			 dst_ipv4_dst_ipv6.ipv4_layout.ipv4,
			 ntohl(key->dst));

		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ethertype);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype, ETH_P_IP);
	} else if (enc_control->addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_dissector_key_ipv6_addrs *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS,
						  f->key);
		struct flow_dissector_key_ipv6_addrs *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS,
						  f->mask);

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &mask->src, MLX5_FLD_SZ_BYTES(ipv6_layout, ipv6));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &key->src, MLX5_FLD_SZ_BYTES(ipv6_layout, ipv6));

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &mask->dst, MLX5_FLD_SZ_BYTES(ipv6_layout, ipv6));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &key->dst, MLX5_FLD_SZ_BYTES(ipv6_layout, ipv6));

		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ethertype);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype, ETH_P_IPV6);
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ENC_IP)) {
		struct flow_dissector_key_ip *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_IP,
						  f->key);
		struct flow_dissector_key_ip *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_IP,
						  f->mask);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_ecn, mask->tos & 0x3);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_ecn, key->tos & 0x3);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_dscp, mask->tos >> 2);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_dscp, key->tos  >> 2);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ttl_hoplimit, mask->ttl);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ttl_hoplimit, key->ttl);

		if (mask->ttl &&
		    !MLX5_CAP_ESW_FLOWTABLE_FDB
			(priv->mdev,
			 ft_field_support.outer_ipv4_ttl)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Matching on TTL is not supported");
			return -EOPNOTSUPP;
		}

	}

	/* Enforce DMAC when offloading incoming tunneled flows.
	 * Flow counters require a match on the DMAC.
	 */
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, dmac_47_16);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, dmac_15_0);
	ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				     dmac_47_16), priv->netdev->dev_addr);

	/* let software handle IP fragments */
	MLX5_SET(fte_match_set_lyr_2_4, headers_c, frag, 1);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, frag, 0);

	return 0;
}

static int __parse_cls_flower(struct mlx5e_priv *priv,
			      struct mlx5_flow_spec *spec,
			      struct tc_cls_flower_offload *f,
			      u8 *match_level, u8 *tunnel_match_level)
{
	struct netlink_ext_ack *extack = f->common.extack;
	void *headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				       outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				       outer_headers);
	void *misc_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				    misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				    misc_parameters);
	u16 addr_type = 0;
	u8 ip_proto = 0;

	*match_level = MLX5_MATCH_NONE;

	if (f->dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_VLAN) |
	      BIT(FLOW_DISSECTOR_KEY_CVLAN) |
	      BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_PORTS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_KEYID) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_PORTS)	|
	      BIT(FLOW_DISSECTOR_KEY_ENC_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_TCP) |
	      BIT(FLOW_DISSECTOR_KEY_IP)  |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IP))) {
		NL_SET_ERR_MSG_MOD(extack, "Unsupported key");
		netdev_warn(priv->netdev, "Unsupported key used: 0x%x\n",
			    f->dissector->used_keys);
		return -EOPNOTSUPP;
	}

	if ((dissector_uses_key(f->dissector,
				FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) ||
	     dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ENC_KEYID) ||
	     dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ENC_PORTS)) &&
	    dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ENC_CONTROL)) {
		struct flow_dissector_key_control *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_CONTROL,
						  f->key);
		switch (key->addr_type) {
		case FLOW_DISSECTOR_KEY_IPV4_ADDRS:
		case FLOW_DISSECTOR_KEY_IPV6_ADDRS:
			if (parse_tunnel_attr(priv, spec, f, tunnel_match_level))
				return -EOPNOTSUPP;
			break;
		default:
			return -EOPNOTSUPP;
		}

		/* In decap flow, header pointers should point to the inner
		 * headers, outer header were already set by parse_tunnel_attr
		 */
		headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
					 inner_headers);
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_dissector_key_basic *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_BASIC,
						  f->key);
		struct flow_dissector_key_basic *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_BASIC,
						  f->mask);
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ethertype,
			 ntohs(mask->n_proto));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype,
			 ntohs(key->n_proto));

		if (mask->n_proto)
			*match_level = MLX5_MATCH_L2;
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_dissector_key_vlan *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_VLAN,
						  f->key);
		struct flow_dissector_key_vlan *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_VLAN,
						  f->mask);
		if (mask->vlan_id || mask->vlan_priority || mask->vlan_tpid) {
			if (key->vlan_tpid == htons(ETH_P_8021AD)) {
				MLX5_SET(fte_match_set_lyr_2_4, headers_c,
					 svlan_tag, 1);
				MLX5_SET(fte_match_set_lyr_2_4, headers_v,
					 svlan_tag, 1);
			} else {
				MLX5_SET(fte_match_set_lyr_2_4, headers_c,
					 cvlan_tag, 1);
				MLX5_SET(fte_match_set_lyr_2_4, headers_v,
					 cvlan_tag, 1);
			}

			MLX5_SET(fte_match_set_lyr_2_4, headers_c, first_vid, mask->vlan_id);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v, first_vid, key->vlan_id);

			MLX5_SET(fte_match_set_lyr_2_4, headers_c, first_prio, mask->vlan_priority);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v, first_prio, key->vlan_priority);

			*match_level = MLX5_MATCH_L2;
		}
	} else if (*match_level != MLX5_MATCH_NONE) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, svlan_tag, 1);
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, cvlan_tag, 1);
		*match_level = MLX5_MATCH_L2;
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_CVLAN)) {
		struct flow_dissector_key_vlan *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_CVLAN,
						  f->key);
		struct flow_dissector_key_vlan *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_CVLAN,
						  f->mask);
		if (mask->vlan_id || mask->vlan_priority || mask->vlan_tpid) {
			if (key->vlan_tpid == htons(ETH_P_8021AD)) {
				MLX5_SET(fte_match_set_misc, misc_c,
					 outer_second_svlan_tag, 1);
				MLX5_SET(fte_match_set_misc, misc_v,
					 outer_second_svlan_tag, 1);
			} else {
				MLX5_SET(fte_match_set_misc, misc_c,
					 outer_second_cvlan_tag, 1);
				MLX5_SET(fte_match_set_misc, misc_v,
					 outer_second_cvlan_tag, 1);
			}

			MLX5_SET(fte_match_set_misc, misc_c, outer_second_vid,
				 mask->vlan_id);
			MLX5_SET(fte_match_set_misc, misc_v, outer_second_vid,
				 key->vlan_id);
			MLX5_SET(fte_match_set_misc, misc_c, outer_second_prio,
				 mask->vlan_priority);
			MLX5_SET(fte_match_set_misc, misc_v, outer_second_prio,
				 key->vlan_priority);

			*match_level = MLX5_MATCH_L2;
		}
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_dissector_key_eth_addrs *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ETH_ADDRS,
						  f->key);
		struct flow_dissector_key_eth_addrs *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ETH_ADDRS,
						  f->mask);

		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
					     dmac_47_16),
				mask->dst);
		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
					     dmac_47_16),
				key->dst);

		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
					     smac_47_16),
				mask->src);
		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
					     smac_47_16),
				key->src);

		if (!is_zero_ether_addr(mask->src) || !is_zero_ether_addr(mask->dst))
			*match_level = MLX5_MATCH_L2;
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_dissector_key_control *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_CONTROL,
						  f->key);

		struct flow_dissector_key_control *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_CONTROL,
						  f->mask);
		addr_type = key->addr_type;

		/* the HW doesn't support frag first/later */
		if (mask->flags & FLOW_DIS_FIRST_FRAG)
			return -EOPNOTSUPP;

		if (mask->flags & FLOW_DIS_IS_FRAGMENT) {
			MLX5_SET(fte_match_set_lyr_2_4, headers_c, frag, 1);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v, frag,
				 key->flags & FLOW_DIS_IS_FRAGMENT);

			/* the HW doesn't need L3 inline to match on frag=no */
			if (!(key->flags & FLOW_DIS_IS_FRAGMENT))
				*match_level = MLX5_MATCH_L2;
	/* ***  L2 attributes parsing up to here *** */
			else
				*match_level = MLX5_MATCH_L3;
		}
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_dissector_key_basic *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_BASIC,
						  f->key);
		struct flow_dissector_key_basic *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_BASIC,
						  f->mask);
		ip_proto = key->ip_proto;

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_protocol,
			 mask->ip_proto);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol,
			 key->ip_proto);

		if (mask->ip_proto)
			*match_level = MLX5_MATCH_L3;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_dissector_key_ipv4_addrs *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IPV4_ADDRS,
						  f->key);
		struct flow_dissector_key_ipv4_addrs *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IPV4_ADDRS,
						  f->mask);

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       &mask->src, sizeof(mask->src));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       &key->src, sizeof(key->src));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       &mask->dst, sizeof(mask->dst));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       &key->dst, sizeof(key->dst));

		if (mask->src || mask->dst)
			*match_level = MLX5_MATCH_L3;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_dissector_key_ipv6_addrs *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IPV6_ADDRS,
						  f->key);
		struct flow_dissector_key_ipv6_addrs *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IPV6_ADDRS,
						  f->mask);

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &mask->src, sizeof(mask->src));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &key->src, sizeof(key->src));

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &mask->dst, sizeof(mask->dst));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &key->dst, sizeof(key->dst));

		if (ipv6_addr_type(&mask->src) != IPV6_ADDR_ANY ||
		    ipv6_addr_type(&mask->dst) != IPV6_ADDR_ANY)
			*match_level = MLX5_MATCH_L3;
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_IP)) {
		struct flow_dissector_key_ip *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IP,
						  f->key);
		struct flow_dissector_key_ip *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IP,
						  f->mask);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_ecn, mask->tos & 0x3);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_ecn, key->tos & 0x3);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_dscp, mask->tos >> 2);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_dscp, key->tos  >> 2);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ttl_hoplimit, mask->ttl);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ttl_hoplimit, key->ttl);

		if (mask->ttl &&
		    !MLX5_CAP_ESW_FLOWTABLE_FDB(priv->mdev,
						ft_field_support.outer_ipv4_ttl)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Matching on TTL is not supported");
			return -EOPNOTSUPP;
		}

		if (mask->tos || mask->ttl)
			*match_level = MLX5_MATCH_L3;
	}

	/* ***  L3 attributes parsing up to here *** */

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_dissector_key_ports *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_PORTS,
						  f->key);
		struct flow_dissector_key_ports *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_PORTS,
						  f->mask);
		switch (ip_proto) {
		case IPPROTO_TCP:
			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 tcp_sport, ntohs(mask->src));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 tcp_sport, ntohs(key->src));

			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 tcp_dport, ntohs(mask->dst));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 tcp_dport, ntohs(key->dst));
			break;

		case IPPROTO_UDP:
			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 udp_sport, ntohs(mask->src));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 udp_sport, ntohs(key->src));

			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 udp_dport, ntohs(mask->dst));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 udp_dport, ntohs(key->dst));
			break;
		default:
			NL_SET_ERR_MSG_MOD(extack,
					   "Only UDP and TCP transports are supported for L4 matching");
			netdev_err(priv->netdev,
				   "Only UDP and TCP transport are supported\n");
			return -EINVAL;
		}

		if (mask->src || mask->dst)
			*match_level = MLX5_MATCH_L4;
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_TCP)) {
		struct flow_dissector_key_tcp *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_TCP,
						  f->key);
		struct flow_dissector_key_tcp *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_TCP,
						  f->mask);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, tcp_flags,
			 ntohs(mask->flags));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_flags,
			 ntohs(key->flags));

		if (mask->flags)
			*match_level = MLX5_MATCH_L4;
	}

	return 0;
}

static int parse_cls_flower(struct mlx5e_priv *priv,
			    struct mlx5e_tc_flow *flow,
			    struct mlx5_flow_spec *spec,
			    struct tc_cls_flower_offload *f)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct mlx5_core_dev *dev = priv->mdev;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5_eswitch_rep *rep;
	bool is_eswitch_flow;
	u8 match_level, tunnel_match_level = MLX5_MATCH_NONE;
	int err;

	err = __parse_cls_flower(priv, spec, f, &match_level, &tunnel_match_level);

	is_eswitch_flow = mlx5e_is_eswitch_flow(flow);
	if (!err && is_eswitch_flow) {
		rep = rpriv->rep;
		if (rep->vport != MLX5_VPORT_UPLINK &&
		    (esw->offloads.inline_mode != MLX5_INLINE_MODE_NONE &&
		    esw->offloads.inline_mode < match_level)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Flow is not offloaded due to min inline setting");
			netdev_warn(priv->netdev,
				    "Flow is not offloaded due to min inline setting, required %d actual %d\n",
				    match_level, esw->offloads.inline_mode);
			return -EOPNOTSUPP;
		}
	}

	if (is_eswitch_flow)
		flow->esw_attr->match_level = match_level;
		flow->esw_attr->tunnel_match_level = tunnel_match_level;
	} else {
		flow->nic_attr->match_level = match_level;
	}

	return err;
}

struct pedit_headers {
	struct ethhdr  eth;
	struct vlan_hdr vlan;
	struct iphdr   ip4;
	struct ipv6hdr ip6;
	struct tcphdr  tcp;
	struct udphdr  udp;
};

static int pedit_header_offsets[] = {
	[TCA_PEDIT_KEY_EX_HDR_TYPE_ETH] = offsetof(struct pedit_headers, eth),
	[TCA_PEDIT_KEY_EX_HDR_TYPE_IP4] = offsetof(struct pedit_headers, ip4),
	[TCA_PEDIT_KEY_EX_HDR_TYPE_IP6] = offsetof(struct pedit_headers, ip6),
	[TCA_PEDIT_KEY_EX_HDR_TYPE_TCP] = offsetof(struct pedit_headers, tcp),
	[TCA_PEDIT_KEY_EX_HDR_TYPE_UDP] = offsetof(struct pedit_headers, udp),
};

#define pedit_header(_ph, _htype) ((void *)(_ph) + pedit_header_offsets[_htype])

static int set_pedit_val(u8 hdr_type, u32 mask, u32 val, u32 offset,
			 struct pedit_headers *masks,
			 struct pedit_headers *vals)
{
	u32 *curr_pmask, *curr_pval;

	if (hdr_type >= __PEDIT_HDR_TYPE_MAX)
		goto out_err;

	curr_pmask = (u32 *)(pedit_header(masks, hdr_type) + offset);
	curr_pval  = (u32 *)(pedit_header(vals, hdr_type) + offset);

	if (*curr_pmask & mask)  /* disallow acting twice on the same location */
		goto out_err;

	*curr_pmask |= mask;
	*curr_pval  |= (val & mask);

	return 0;

out_err:
	return -EOPNOTSUPP;
}

struct mlx5_fields {
	u8  field;
	u8  size;
	u32 offset;
};

#define OFFLOAD(fw_field, size, field, off) \
		{MLX5_ACTION_IN_FIELD_OUT_ ## fw_field, size, offsetof(struct pedit_headers, field) + (off)}

static struct mlx5_fields fields[] = {
	OFFLOAD(DMAC_47_16, 4, eth.h_dest[0], 0),
	OFFLOAD(DMAC_15_0,  2, eth.h_dest[4], 0),
	OFFLOAD(SMAC_47_16, 4, eth.h_source[0], 0),
	OFFLOAD(SMAC_15_0,  2, eth.h_source[4], 0),
	OFFLOAD(ETHERTYPE,  2, eth.h_proto, 0),
	OFFLOAD(FIRST_VID,  2, vlan.h_vlan_TCI, 0),

	OFFLOAD(IP_TTL, 1, ip4.ttl,   0),
	OFFLOAD(SIPV4,  4, ip4.saddr, 0),
	OFFLOAD(DIPV4,  4, ip4.daddr, 0),

	OFFLOAD(SIPV6_127_96, 4, ip6.saddr.s6_addr32[0], 0),
	OFFLOAD(SIPV6_95_64,  4, ip6.saddr.s6_addr32[1], 0),
	OFFLOAD(SIPV6_63_32,  4, ip6.saddr.s6_addr32[2], 0),
	OFFLOAD(SIPV6_31_0,   4, ip6.saddr.s6_addr32[3], 0),
	OFFLOAD(DIPV6_127_96, 4, ip6.daddr.s6_addr32[0], 0),
	OFFLOAD(DIPV6_95_64,  4, ip6.daddr.s6_addr32[1], 0),
	OFFLOAD(DIPV6_63_32,  4, ip6.daddr.s6_addr32[2], 0),
	OFFLOAD(DIPV6_31_0,   4, ip6.daddr.s6_addr32[3], 0),
	OFFLOAD(IPV6_HOPLIMIT, 1, ip6.hop_limit, 0),

	OFFLOAD(TCP_SPORT, 2, tcp.source,  0),
	OFFLOAD(TCP_DPORT, 2, tcp.dest,    0),
	OFFLOAD(TCP_FLAGS, 1, tcp.ack_seq, 5),

	OFFLOAD(UDP_SPORT, 2, udp.source, 0),
	OFFLOAD(UDP_DPORT, 2, udp.dest,   0),
};

/* On input attr->max_mod_hdr_actions tells how many HW actions can be parsed at
 * max from the SW pedit action. On success, attr->num_mod_hdr_actions
 * says how many HW actions were actually parsed.
 */
static int offload_pedit_fields(struct pedit_headers *masks,
				struct pedit_headers *vals,
				struct mlx5e_tc_flow_parse_attr *parse_attr,
				struct netlink_ext_ack *extack)
{
	struct pedit_headers *set_masks, *add_masks, *set_vals, *add_vals;
	int i, action_size, nactions, max_actions, first, last, next_z;
	void *s_masks_p, *a_masks_p, *vals_p;
	struct mlx5_fields *f;
	u8 cmd, field_bsize;
	u32 s_mask, a_mask;
	unsigned long mask;
	__be32 mask_be32;
	__be16 mask_be16;
	void *action;

	set_masks = &masks[TCA_PEDIT_KEY_EX_CMD_SET];
	add_masks = &masks[TCA_PEDIT_KEY_EX_CMD_ADD];
	set_vals = &vals[TCA_PEDIT_KEY_EX_CMD_SET];
	add_vals = &vals[TCA_PEDIT_KEY_EX_CMD_ADD];

	action_size = MLX5_UN_SZ_BYTES(set_action_in_add_action_in_auto);
	action = parse_attr->mod_hdr_actions +
		 parse_attr->num_mod_hdr_actions * action_size;

	max_actions = parse_attr->max_mod_hdr_actions;
	nactions = parse_attr->num_mod_hdr_actions;

	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		f = &fields[i];
		/* avoid seeing bits set from previous iterations */
		s_mask = 0;
		a_mask = 0;

		s_masks_p = (void *)set_masks + f->offset;
		a_masks_p = (void *)add_masks + f->offset;

		memcpy(&s_mask, s_masks_p, f->size);
		memcpy(&a_mask, a_masks_p, f->size);

		if (!s_mask && !a_mask) /* nothing to offload here */
			continue;

		if (s_mask && a_mask) {
			NL_SET_ERR_MSG_MOD(extack,
					   "can't set and add to the same HW field");
			printk(KERN_WARNING "mlx5: can't set and add to the same HW field (%x)\n", f->field);
			return -EOPNOTSUPP;
		}

		if (nactions == max_actions) {
			NL_SET_ERR_MSG_MOD(extack,
					   "too many pedit actions, can't offload");
			printk(KERN_WARNING "mlx5: parsed %d pedit actions, can't do more\n", nactions);
			return -EOPNOTSUPP;
		}

		if (s_mask) {
			cmd  = MLX5_ACTION_TYPE_SET;
			mask = s_mask;
			vals_p = (void *)set_vals + f->offset;
			/* clear to denote we consumed this field */
			memset(s_masks_p, 0, f->size);
		} else {
			cmd  = MLX5_ACTION_TYPE_ADD;
			mask = a_mask;
			vals_p = (void *)add_vals + f->offset;
			/* clear to denote we consumed this field */
			memset(a_masks_p, 0, f->size);
		}

		field_bsize = f->size * BITS_PER_BYTE;

		if (field_bsize == 32) {
			mask_be32 = *(__be32 *)&mask;
			mask = (__force unsigned long)cpu_to_le32(be32_to_cpu(mask_be32));
		} else if (field_bsize == 16) {
			mask_be16 = *(__be16 *)&mask;
			mask = (__force unsigned long)cpu_to_le16(be16_to_cpu(mask_be16));
		}

		first = find_first_bit(&mask, field_bsize);
		next_z = find_next_zero_bit(&mask, field_bsize, first);
		last  = find_last_bit(&mask, field_bsize);
		if (first < next_z && next_z < last) {
			NL_SET_ERR_MSG_MOD(extack,
					   "rewrite of few sub-fields isn't supported");
			printk(KERN_WARNING "mlx5: rewrite of few sub-fields (mask %lx) isn't offloaded\n",
			       mask);
			return -EOPNOTSUPP;
		}

		MLX5_SET(set_action_in, action, action_type, cmd);
		MLX5_SET(set_action_in, action, field, f->field);

		if (cmd == MLX5_ACTION_TYPE_SET) {
			MLX5_SET(set_action_in, action, offset, first);
			/* length is num of bits to be written, zero means length of 32 */
			MLX5_SET(set_action_in, action, length, (last - first + 1));
		}

		if (field_bsize == 32)
			MLX5_SET(set_action_in, action, data, ntohl(*(__be32 *)vals_p) >> first);
		else if (field_bsize == 16)
			MLX5_SET(set_action_in, action, data, ntohs(*(__be16 *)vals_p) >> first);
		else if (field_bsize == 8)
			MLX5_SET(set_action_in, action, data, *(u8 *)vals_p >> first);

		action += action_size;
		nactions++;
	}

	parse_attr->num_mod_hdr_actions = nactions;
	return 0;
}

static int alloc_mod_hdr_actions(struct mlx5e_priv *priv,
				 const struct tc_action *a, int namespace,
				 struct mlx5e_tc_flow_parse_attr *parse_attr)
{
	int nkeys, action_size, max_actions;

	nkeys = tcf_pedit_nkeys(a);
	action_size = MLX5_UN_SZ_BYTES(set_action_in_add_action_in_auto);

	if (namespace == MLX5_FLOW_NAMESPACE_FDB) /* FDB offloading */
		max_actions = MLX5_CAP_ESW_FLOWTABLE_FDB(priv->mdev, max_modify_header_actions);
	else /* namespace is MLX5_FLOW_NAMESPACE_KERNEL - NIC offloading */
		max_actions = MLX5_CAP_FLOWTABLE_NIC_RX(priv->mdev, max_modify_header_actions);

	/* can get up to crazingly 16 HW actions in 32 bits pedit SW key */
	max_actions = min(max_actions, nkeys * 16);

	parse_attr->mod_hdr_actions = kcalloc(max_actions, action_size, GFP_KERNEL);
	if (!parse_attr->mod_hdr_actions)
		return -ENOMEM;

	parse_attr->max_mod_hdr_actions = max_actions;
	return 0;
}

static const struct pedit_headers zero_masks = {};

static int parse_tc_pedit_action(struct mlx5e_priv *priv,
				 const struct tc_action *a, int namespace,
				 struct mlx5e_tc_flow_parse_attr *parse_attr,
				 struct netlink_ext_ack *extack)
{
	struct pedit_headers masks[__PEDIT_CMD_MAX], vals[__PEDIT_CMD_MAX], *cmd_masks;
	int nkeys, i, err = -EOPNOTSUPP;
	u32 mask, val, offset;
	u8 cmd, htype;

	nkeys = tcf_pedit_nkeys(a);

	memset(masks, 0, sizeof(struct pedit_headers) * __PEDIT_CMD_MAX);
	memset(vals,  0, sizeof(struct pedit_headers) * __PEDIT_CMD_MAX);

	for (i = 0; i < nkeys; i++) {
		htype = tcf_pedit_htype(a, i);
		cmd = tcf_pedit_cmd(a, i);
		err = -EOPNOTSUPP; /* can't be all optimistic */

		if (htype == TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK) {
			NL_SET_ERR_MSG_MOD(extack,
					   "legacy pedit isn't offloaded");
			goto out_err;
		}

		if (cmd != TCA_PEDIT_KEY_EX_CMD_SET && cmd != TCA_PEDIT_KEY_EX_CMD_ADD) {
			NL_SET_ERR_MSG_MOD(extack, "pedit cmd isn't offloaded");
			goto out_err;
		}

		mask = tcf_pedit_mask(a, i);
		val = tcf_pedit_val(a, i);
		offset = tcf_pedit_offset(a, i);

		err = set_pedit_val(htype, ~mask, val, offset, &masks[cmd], &vals[cmd]);
		if (err)
			goto out_err;
	}

	if (!parse_attr->mod_hdr_actions) {
		err = alloc_mod_hdr_actions(priv, a, namespace, parse_attr);
		if (err)
			goto out_err;
	}

	err = offload_pedit_fields(masks, vals, parse_attr, extack);
	if (err < 0)
		goto out_dealloc_parsed_actions;

	for (cmd = 0; cmd < __PEDIT_CMD_MAX; cmd++) {
		cmd_masks = &masks[cmd];
		if (memcmp(cmd_masks, &zero_masks, sizeof(zero_masks))) {
			NL_SET_ERR_MSG_MOD(extack,
					   "attempt to offload an unsupported field");
			netdev_warn(priv->netdev, "attempt to offload an unsupported field (cmd %d)\n", cmd);
			print_hex_dump(KERN_WARNING, "mask: ", DUMP_PREFIX_ADDRESS,
				       16, 1, cmd_masks, sizeof(zero_masks), true);
			err = -EOPNOTSUPP;
			goto out_dealloc_parsed_actions;
		}
	}

	return 0;

out_dealloc_parsed_actions:
	kfree(parse_attr->mod_hdr_actions);
	parse_attr->mod_hdr_actions = NULL;
out_err:
	return err;
}

static bool csum_offload_supported(struct mlx5e_priv *priv,
				   u32 action,
				   u32 update_flags,
				   struct netlink_ext_ack *extack)
{
	u32 prot_flags = TCA_CSUM_UPDATE_FLAG_IPV4HDR | TCA_CSUM_UPDATE_FLAG_TCP |
			 TCA_CSUM_UPDATE_FLAG_UDP;

	/*  The HW recalcs checksums only if re-writing headers */
	if (!(action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "TC csum action is only offloaded with pedit");
		netdev_warn(priv->netdev,
			    "TC csum action is only offloaded with pedit\n");
		return false;
	}

	if (update_flags & ~prot_flags) {
		NL_SET_ERR_MSG_MOD(extack,
				   "can't offload TC csum action for some header/s");
		netdev_warn(priv->netdev,
			    "can't offload TC csum action for some header/s - flags %#x\n",
			    update_flags);
		return false;
	}

	return true;
}

struct ip_ttl_word {
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
};

struct ipv6_hoplimit_word {
	__be16	payload_len;
	__u8	nexthdr;
	__u8	hop_limit;
};

static bool is_action_keys_supported(const struct tc_action *a, int nkeys)
{
	u32 mask, offset;
	u8 htype;
	int k;

	for (k = 0; k < nkeys; k++) {
		mask = ~tcf_pedit_mask(a, k);
		offset = tcf_pedit_offset(a, k);
		htype = tcf_pedit_htype(a, k);
		/* For IPv4 & IPv6 header check 4 byte word,
		 * to determine that modified fields
		 * are NOT ttl & hop_limit only.
		 */
		if (htype == TCA_PEDIT_KEY_EX_HDR_TYPE_IP4) {
			struct ip_ttl_word *ttl_word =
				(struct ip_ttl_word *)&mask;

			if (offset != offsetof(struct iphdr, ttl) ||
			    ttl_word->protocol ||
			    ttl_word->check) {
				return true;
			}
		} else if (htype == TCA_PEDIT_KEY_EX_HDR_TYPE_IP6) {
			struct ipv6_hoplimit_word *hoplimit_word =
				(struct ipv6_hoplimit_word *)&mask;

			if (offset != offsetof(struct ipv6hdr, payload_len) ||
			    hoplimit_word->payload_len ||
			    hoplimit_word->nexthdr) {
				return true;
			}
		}
	}
	return false;
}

static bool modify_header_match_supported(struct mlx5_flow_spec *spec,
					  struct tcf_exts *exts,
					  u32 match_actions,
					  struct netlink_ext_ack *extack)
{
	const struct tc_action *a;
	bool modify_ip_header;
	LIST_HEAD(actions);
	void *headers_v;
	u16 ethertype;
	u8 ip_proto;
	int i;

	if (match_actions & MLX5_FLOW_CONTEXT_ACTION_DECAP)
		headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value, inner_headers);
	else
		headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value, outer_headers);

	ethertype = MLX5_GET(fte_match_set_lyr_2_4, headers_v, ethertype);

	/* for non-IP we only re-write MACs, so we're okay */
	if (ethertype != ETH_P_IP && ethertype != ETH_P_IPV6)
		goto out_ok;

	modify_ip_header = false;
	tcf_exts_for_each_action(i, a, exts) {
		if (!is_tcf_pedit(a))
			continue;

		modify_ip_header = is_action_keys_supported(a, tcf_pedit_nkeys(a));
	}

	ip_proto = MLX5_GET(fte_match_set_lyr_2_4, headers_v, ip_protocol);
	if (modify_ip_header && ip_proto != IPPROTO_TCP &&
	    ip_proto != IPPROTO_UDP && ip_proto != IPPROTO_ICMP) {
		NL_SET_ERR_MSG_MOD(extack,
				   "can't offload re-write of non TCP/UDP");
		pr_info("can't offload re-write of ip proto %d\n", ip_proto);
		return false;
	}

out_ok:
	return true;
}

static bool actions_match_supported(struct mlx5e_priv *priv,
				    struct tcf_exts *exts,
				    struct mlx5e_tc_flow_parse_attr *parse_attr,
				    struct mlx5e_tc_flow *flow,
				    struct netlink_ext_ack *extack)
{
	u32 actions;

	if (mlx5e_is_eswitch_flow(flow))
		actions = flow->esw_attr->action;
	else
		actions = flow->nic_attr->action;

/* disabled due to hindering VF lag. */
#if 0
	if (atomic_read(&flow->flags) & MLX5E_TC_FLOW_EGRESS &&
	    !(actions & MLX5_FLOW_CONTEXT_ACTION_DECAP))
		return false;
#endif

	if (actions & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)
		return modify_header_match_supported(&parse_attr->spec, exts,
						     actions, extack);

	return true;
}

static bool same_hw_devs(struct mlx5e_priv *priv, struct mlx5e_priv *peer_priv)
{
	struct mlx5_core_dev *fmdev, *pmdev;
	u64 fsystem_guid, psystem_guid;

	fmdev = priv->mdev;
	pmdev = peer_priv->mdev;

	fsystem_guid = mlx5_query_nic_system_image_guid(fmdev);
	psystem_guid = mlx5_query_nic_system_image_guid(pmdev);

	return (fsystem_guid == psystem_guid);
}

static int parse_tc_nic_actions(struct mlx5e_priv *priv, struct tcf_exts *exts,
				struct mlx5e_tc_flow_parse_attr *parse_attr,
				struct mlx5e_tc_flow *flow,
				struct netlink_ext_ack *extack)
{
	struct mlx5_nic_flow_attr *attr = flow->nic_attr;
	const struct tc_action *a;
	LIST_HEAD(actions);
	u32 action = 0;
	int err, i;

	if (!tcf_exts_has_actions(exts))
		return -EINVAL;

	attr->flow_tag = MLX5_FS_DEFAULT_FLOW_TAG;

	tcf_exts_for_each_action(i, a, exts) {
		if (is_tcf_gact_shot(a)) {
			action |= MLX5_FLOW_CONTEXT_ACTION_DROP;
			if (MLX5_CAP_FLOWTABLE(priv->mdev,
					       flow_table_properties_nic_receive.flow_counter))
				action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;
			continue;
		}

		if (is_tcf_pedit(a)) {
			err = parse_tc_pedit_action(priv, a, MLX5_FLOW_NAMESPACE_KERNEL,
						    parse_attr, extack);
			if (err)
				return err;

			action |= MLX5_FLOW_CONTEXT_ACTION_MOD_HDR |
				  MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
			continue;
		}

		if (is_tcf_csum(a)) {
			if (csum_offload_supported(priv, action,
						   tcf_csum_update_flags(a),
						   extack))
				continue;

			return -EOPNOTSUPP;
		}

		if (is_tcf_mirred_egress_redirect(a)) {
			struct net_device *peer_dev = tcf_mirred_dev(a);

			if (priv->netdev->netdev_ops == peer_dev->netdev_ops &&
			    same_hw_devs(priv, netdev_priv(peer_dev))) {
				parse_attr->mirred_ifindex = peer_dev->ifindex;
				atomic_or(MLX5E_TC_FLOW_HAIRPIN, &flow->flags);
				action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
					  MLX5_FLOW_CONTEXT_ACTION_COUNT;
			} else {
				NL_SET_ERR_MSG_MOD(extack,
						   "device is not on same HW, can't offload");
				netdev_warn(priv->netdev, "device %s not on same HW, can't offload\n",
					    peer_dev->name);
				return -EINVAL;
			}
			continue;
		}

		if (is_tcf_skbedit_mark(a)) {
			u32 mark = tcf_skbedit_mark(a);

			if (mark & ~MLX5E_TC_FLOW_ID_MASK) {
				NL_SET_ERR_MSG_MOD(extack,
						   "Bad flow mark - only 16 bit is supported");
				return -EINVAL;
			}

			attr->flow_tag = mark;
			action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
			continue;
		}

		return -EINVAL;
	}

	attr->action = action;
	if (!actions_match_supported(priv, exts, parse_attr, flow, extack))
		return -EOPNOTSUPP;

	return 0;
}

static struct net_device *mlx5_upper_lag_dev_get(struct net_device *uplink_dev)
{
        struct net_device *upper = netdev_master_upper_dev_get(uplink_dev);

        if (upper && netif_is_lag_master(upper))
                return upper;
        else
                return NULL;
}

static inline int cmp_encap_info(struct ip_tunnel_key *a,
				 struct ip_tunnel_key *b)
{
	return memcmp(a, b, sizeof(*a));
}

static inline int hash_encap_info(struct ip_tunnel_key *key)
{
	return jhash(key, sizeof(*key), 0);
}

static int get_route_and_out_devs(struct mlx5e_priv *priv,
				  struct net_device *dev,
				  struct net_device **route_dev,
				  struct net_device **out_dev)
{
	struct net_device *uplink_dev, *uplink_upper_lag_dev;
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_rep_priv *uplink_rpriv;
	bool dst_is_lag_dev;

	uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
	uplink_dev = uplink_rpriv->netdev;
	uplink_upper_lag_dev = mlx5_upper_lag_dev_get(uplink_dev);
	dst_is_lag_dev = (dev == uplink_upper_lag_dev &&
			  mlx5_lag_is_active(priv->mdev));

	/* if the egress device isn't on the same HW e-switch or
	 * it's a LAG device, use the uplink
	 */
	if (!switchdev_port_same_parent_id(priv->netdev, dev) ||
	    dst_is_lag_dev) {
		*route_dev = uplink_dev;
		*out_dev = *route_dev;
	} else {
		*route_dev = dev;
		if (is_vlan_dev(*route_dev))
			*out_dev = uplink_dev;
		else if (mlx5e_eswitch_rep(dev))
			*out_dev = *route_dev;
		else
			return -EOPNOTSUPP;
	}

	return 0;
}

static int mlx5e_route_lookup_ipv4(struct mlx5e_priv *priv,
				   struct net_device *mirred_dev,
				   struct net_device **out_dev,
				   struct net_device **route_dev,
				   struct flowi4 *fl4,
				   struct neighbour **out_n,
				   u8 *out_ttl)
{
 	struct neighbour *n = NULL;
	struct rtable *rt;

#if IS_ENABLED(CONFIG_INET)
	struct mlx5_core_dev *mdev = priv->mdev;
	struct net_device *uplink_dev;
	int ret;

	if (mlx5_lag_is_multipath(mdev)) {
		struct mlx5_eswitch *esw = mdev->priv.eswitch;

		uplink_dev = mlx5_eswitch_uplink_get_proto_dev(esw, REP_ETH);
		fl4->flowi4_oif = uplink_dev->ifindex;
	}

	rt = ip_route_output_key(dev_net(mirred_dev), fl4);
	ret = PTR_ERR_OR_ZERO(rt);
	if (ret)
		return ret;

	if (mlx5_lag_is_multipath(mdev) && !rt->rt_gateway)
		return -ENETUNREACH;
#else
	return -EOPNOTSUPP;
#endif

	ret = get_route_and_out_devs(priv, rt->dst.dev, route_dev, out_dev);
	if (ret < 0)
		return ret;

	if (!(*out_ttl))
		*out_ttl = ip4_dst_hoplimit(&rt->dst);
	n = dst_neigh_lookup(&rt->dst, &fl4->daddr);
	ip_rt_put(rt);
	if (!n)
		return -ENOMEM;

	*out_n = n;
	return 0;
}

static bool is_merged_eswitch_dev(struct mlx5e_priv *priv,
				  struct net_device *peer_netdev)
{
	struct mlx5e_priv *peer_priv;

	peer_priv = netdev_priv(peer_netdev);

	return (MLX5_CAP_ESW(priv->mdev, merged_eswitch) &&
		mlx5e_eswitch_rep(priv->netdev) &&
		mlx5e_eswitch_rep(peer_netdev) &&
		same_hw_devs(priv, peer_priv));
}

static int mlx5e_route_lookup_ipv6(struct mlx5e_priv *priv,
				   struct net_device *mirred_dev,
				   struct net_device **out_dev,
				   struct net_device **route_dev,
				   struct flowi6 *fl6,
				   struct neighbour **out_n,
				   u8 *out_ttl)
{
	struct neighbour *n = NULL;
	struct dst_entry *dst;

#if IS_ENABLED(CONFIG_INET) && IS_ENABLED(CONFIG_IPV6)
	int ret;

	ret = ipv6_stub->ipv6_dst_lookup(dev_net(mirred_dev), NULL, &dst,
					 fl6);
	if (ret < 0)
		return ret;

	if (!(*out_ttl))
		*out_ttl = ip6_dst_hoplimit(dst);

#else
	return -EOPNOTSUPP;
#endif

	ret = get_route_and_out_devs(priv, rt->dst.dev, route_dev, out_dev);
	if (ret < 0)
		return ret;

	n = dst_neigh_lookup(dst, &fl6->daddr);
	dst_release(dst);
	if (!n)
		return -ENOMEM;

	*out_n = n;
	return 0;
}

static char *gen_eth_tnl_hdr(char *buf, struct net_device *dev,
			     unsigned char h_dest[ETH_ALEN],
			     u16 proto)
{
	struct ethhdr *eth = (struct ethhdr *)buf;
	char *ip;

	ether_addr_copy(eth->h_dest, h_dest);
	ether_addr_copy(eth->h_source, dev->dev_addr);
	if (is_vlan_dev(dev)) {
		struct vlan_hdr *vlan = (struct vlan_hdr *)
					((char *)eth + ETH_HLEN);
		ip = (char *)vlan + VLAN_HLEN;
		eth->h_proto = vlan_dev_vlan_proto(dev);
		vlan->h_vlan_TCI = htons(vlan_dev_vlan_id(dev));
		vlan->h_vlan_encapsulated_proto = htons(proto);
	} else {
		eth->h_proto = htons(proto);
		ip = (char *)eth + ETH_HLEN;
	}

	return ip;
}

static void gen_vxlan_header_ipv4(struct net_device *out_dev,
				  char buf[], int encap_size,
				  unsigned char h_dest[ETH_ALEN],
				  u8 tos, u8 ttl,
				  __be32 daddr,
				  __be32 saddr,
				  __be16 udp_dst_port,
				  __be32 vx_vni)
{
	struct iphdr  *ip;
	struct udphdr *udp;
	struct vxlanhdr *vxh;

	memset(buf, 0, encap_size);

	ip = (struct iphdr *)gen_eth_tnl_hdr(buf, out_dev, h_dest,
					     ETH_P_IP);
	ip->daddr = daddr;
	ip->saddr = saddr;

	ip->tos = tos;
	ip->ttl = ttl;
	ip->protocol = IPPROTO_UDP;
	ip->version = 0x4;
	ip->ihl = 0x5;

	udp = (struct udphdr *)((char *)ip + sizeof(struct iphdr));
	udp->dest = udp_dst_port;

	vxh = (struct vxlanhdr *)((char *)udp + sizeof(struct udphdr));
	vxh->vx_flags = VXLAN_HF_VNI;
	vxh->vx_vni = vxlan_vni_field(vx_vni);
}

static void gen_vxlan_header_ipv6(struct net_device *out_dev,
				  char buf[], int encap_size,
				  unsigned char h_dest[ETH_ALEN],
				  u8 tos, u8 ttl,
				  struct in6_addr *daddr,
				  struct in6_addr *saddr,
				  __be16 udp_dst_port,
				  __be32 vx_vni)
{
	struct ipv6hdr *ip6h;
	struct udphdr *udp;
	struct vxlanhdr *vxh;

	memset(buf, 0, encap_size);

	ip6h = (struct ipv6hdr *)gen_eth_tnl_hdr(buf, out_dev, h_dest,
						 ETH_P_IPV6);
	ip6_flow_hdr(ip6h, tos, 0);
	/* the HW fills up ipv6 payload len */
	ip6h->nexthdr     = IPPROTO_UDP;
	ip6h->hop_limit   = ttl;
	ip6h->daddr	  = *daddr;
	ip6h->saddr	  = *saddr;

	udp = (struct udphdr *)((char *)ip6h + sizeof(struct ipv6hdr));
	udp->dest = udp_dst_port;

	vxh = (struct vxlanhdr *)((char *)udp + sizeof(struct udphdr));
	vxh->vx_flags = VXLAN_HF_VNI;
	vxh->vx_vni = vxlan_vni_field(vx_vni);
}

static int mlx5e_encap_entry_attach_update(struct mlx5e_priv *priv,
					   struct net_device *out_dev,
					   struct mlx5e_encap_entry *e,
					   struct neighbour *n,
					   unsigned long n_updated)
{
	unsigned long n_updated_new;
	int err;

	err = mlx5e_rep_encap_entry_attach(netdev_priv(out_dev), e);
	if (err)
		return err;

	read_lock_bh(&n->lock);
	n_updated_new = n->updated;
	read_unlock_bh(&n->lock);

	/* Neigh state changed before encap was attached to nhe.
	 * Schedule update work.
	 */
	if (n_updated != n_updated_new) {
		mlx5e_rep_neigh_entry_hold(e->nhe);
		mlx5e_rep_queue_neigh_update_work(priv, e->nhe, n);
	}

	e->updated = n_updated_new;

	return 0;
}

static int mlx5e_create_encap_header_ipv4(struct mlx5e_priv *priv,
					  struct net_device *mirred_dev,
					  struct mlx5e_encap_entry *e)
{
	int max_encap_size = MLX5_CAP_ESW(priv->mdev, max_encap_header_size);
	struct ip_tunnel_key *tun_key = &e->tun_info.key;
	struct net_device *out_dev, *route_dev;
	struct neighbour *n = NULL;
	unsigned long n_updated;
	struct flowi4 fl4 = {};
	u8 nud_state, tos, ttl;
	int ipv4_encap_size;
	char *encap_header;
	int err;

	switch (e->tunnel_type) {
	case MLX5_REFORMAT_TYPE_L2_TO_VXLAN:
		fl4.flowi4_proto = IPPROTO_UDP;
		fl4.fl4_dport = tun_key->tp_dst;
		break;
	default:
		err = -EOPNOTSUPP;
		goto out;
	}

	tos = tun_key->tos;
	ttl = tun_key->ttl;

	fl4.flowi4_tos = tun_key->tos;
	fl4.daddr = tun_key->u.ipv4.dst;
	fl4.saddr = tun_key->u.ipv4.src;

	err = mlx5e_route_lookup_ipv4(priv, mirred_dev, &out_dev, &route_dev,
				      &fl4, &n, &ttl);
	if (err)
		return err;

	ipv4_encap_size =
		(is_vlan_dev(route_dev) ? VLAN_ETH_HLEN : ETH_HLEN) +
		sizeof(struct iphdr) +
		VXLAN_HLEN;

	if (max_encap_size < ipv4_encap_size) {
		mlx5_core_warn(priv->mdev, "encap size %d too big, max supported is %d\n",
			       ipv4_encap_size, max_encap_size);
		return -EOPNOTSUPP;
	}

	encap_header = kzalloc(ipv4_encap_size, GFP_KERNEL);
	if (!encap_header)
		return -ENOMEM;

	/* used by mlx5e_detach_encap to lookup a neigh hash table
	 * entry in the neigh hash table when a user deletes a rule
	 */
	e->m_neigh.dev = n->dev;
	e->m_neigh.family = n->ops->family;
	memcpy(&e->m_neigh.dst_ip, n->primary_key, n->tbl->key_len);
	e->out_dev = out_dev;

	read_lock_bh(&n->lock);
	nud_state = n->nud_state;
	ether_addr_copy(e->h_dest, n->ha);
	n_updated = n->updated;
	read_unlock_bh(&n->lock);

	switch (e->tunnel_type) {
	case MLX5_REFORMAT_TYPE_L2_TO_VXLAN:
		gen_vxlan_header_ipv4(route_dev, encap_header,
				      ipv4_encap_size, e->h_dest, tos, ttl,
				      fl4.daddr,
				      fl4.saddr, tun_key->tp_dst,
				      tunnel_id_to_key32(tun_key->tun_id));
		break;
	default:
		err = -EOPNOTSUPP;
		goto free_encap;
	}
	e->encap_size = ipv4_encap_size;
	e->encap_header = encap_header;

	if (!(nud_state & NUD_VALID)) {
		err = mlx5e_encap_entry_attach_update(priv, out_dev, e, n,
						      n_updated);
		if (err)
			goto free_encap;
		neigh_event_send(n, NULL);
		err = -EAGAIN;
		goto out;
	}

	err = mlx5_packet_reformat_alloc(priv->mdev, e->tunnel_type,
					 ipv4_encap_size, encap_header,
					 MLX5_FLOW_NAMESPACE_FDB,
					 &e->encap_id);
	if (err)
		goto free_encap;

	e->flags |= MLX5_ENCAP_ENTRY_VALID;

	err = mlx5e_encap_entry_attach_update(priv, out_dev, e, n, n_updated);
	if (err)
		goto dealloc_encap;
	mlx5e_rep_queue_neigh_stats_work(netdev_priv(out_dev));
	neigh_release(n);
	return err;

dealloc_encap:
	mlx5_packet_reformat_dealloc(priv->mdev, e->encap_id);
	e->flags &= ~MLX5_ENCAP_ENTRY_VALID;
free_encap:
	kfree(encap_header);
	e->encap_size = 0;
	e->encap_header = NULL;
out:
	if (n)
		neigh_release(n);
	return err;
}

static int mlx5e_create_encap_header_ipv6(struct mlx5e_priv *priv,
					  struct net_device *mirred_dev,
					  struct mlx5e_encap_entry *e)
{
	int max_encap_size = MLX5_CAP_ESW(priv->mdev, max_encap_header_size);
	struct ip_tunnel_key *tun_key = &e->tun_info.key;
	struct net_device *out_dev, *route_dev;
	struct neighbour *n = NULL;
	unsigned long n_updated;
	struct flowi6 fl6 = {};
	u8 nud_state, tos, ttl;
	int ipv6_encap_size;
	char *encap_header;
	int err;

	switch (e->tunnel_type) {
	case MLX5_REFORMAT_TYPE_L2_TO_VXLAN:
		fl6.flowi6_proto = IPPROTO_UDP;
		fl6.fl6_dport = tun_key->tp_dst;
		break;
	default:
		err = -EOPNOTSUPP;
		goto out;
	}

	tos = tun_key->tos;
	ttl = tun_key->ttl;

	fl6.flowlabel = ip6_make_flowinfo(RT_TOS(tun_key->tos), tun_key->label);
	fl6.daddr = tun_key->u.ipv6.dst;
	fl6.saddr = tun_key->u.ipv6.src;

	err = mlx5e_route_lookup_ipv6(priv, mirred_dev, &out_dev, &route_dev,
				      &fl6, &n, &ttl);
	if (err)
		return err;

	ipv6_encap_size = (is_vlan_dev(route_dev) ? VLAN_ETH_HLEN : ETH_HLEN) +
		+ sizeof(struct ipv6hdr) +
		VXLAN_HLEN;

	if (max_encap_size < ipv6_encap_size) {
		mlx5_core_warn(priv->mdev, "encap size %d too big, max supported is %d\n",
			       ipv6_encap_size, max_encap_size);
		return -EOPNOTSUPP;
	}

	encap_header = kzalloc(ipv6_encap_size, GFP_KERNEL);
	if (!encap_header)
		return -ENOMEM;

	/* used by mlx5e_detach_encap to lookup a neigh hash table
	 * entry in the neigh hash table when a user deletes a rule
	 */
	e->m_neigh.dev = n->dev;
	e->m_neigh.family = n->ops->family;
	memcpy(&e->m_neigh.dst_ip, n->primary_key, n->tbl->key_len);
	e->out_dev = out_dev;

	read_lock_bh(&n->lock);
	nud_state = n->nud_state;
	ether_addr_copy(e->h_dest, n->ha);
	n_updated = n->updated;
	read_unlock_bh(&n->lock);

	switch (e->tunnel_type) {
	case MLX5_REFORMAT_TYPE_L2_TO_VXLAN:
		gen_vxlan_header_ipv6(route_dev, encap_header,
				      ipv6_encap_size, e->h_dest, tos, ttl,
				      &fl6.daddr,
				      &fl6.saddr, tun_key->tp_dst,
				      tunnel_id_to_key32(tun_key->tun_id));
		break;
	default:
		err = -EOPNOTSUPP;
		goto free_encap;
	}

	e->encap_size = ipv6_encap_size;
	e->encap_header = encap_header;

	if (!(nud_state & NUD_VALID)) {
		err = mlx5e_encap_entry_attach_update(priv, out_dev, e, n,
						      n_updated);
		if (err)
			goto free_encap;

		neigh_event_send(n, NULL);
		err = -EAGAIN;
		goto out;
	}

	err = mlx5_packet_reformat_alloc(priv->mdev, e->tunnel_type,
					 ipv6_encap_size, encap_header,
					 MLX5_FLOW_NAMESPACE_FDB,
					 &e->encap_id);
	if (err)
		goto free_encap;

	e->flags |= MLX5_ENCAP_ENTRY_VALID;

	err = mlx5e_encap_entry_attach_update(priv, out_dev, e, n,
					      n_updated);
	if (err)
		goto dealloc_encap;
	mlx5e_rep_queue_neigh_stats_work(netdev_priv(out_dev));
	neigh_release(n);
	return err;

dealloc_encap:
	mlx5_packet_reformat_dealloc(priv->mdev, e->encap_id);
	e->flags &= ~MLX5_ENCAP_ENTRY_VALID;
free_encap:
	kfree(encap_header);
	e->encap_size = 0;
	e->encap_header = NULL;
out:
	if (n)
		neigh_release(n);
	return err;
}

bool mlx5e_encap_take(struct mlx5e_encap_entry *e)
{
	return refcount_inc_not_zero(&e->refcnt);
}

static struct mlx5e_encap_entry *
mlx5e_encap_get(struct mlx5e_priv *priv, struct ip_tunnel_key *key,
		uintptr_t hash_key)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_encap_entry *e;
	bool found = false;

	rcu_read_lock();
	hash_for_each_possible_rcu(esw->offloads.encap_tbl, e,
				   encap_hlist, hash_key) {
		if (!cmp_encap_info(&e->tun_info.key, key) &&
		    mlx5e_encap_take(e)) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	if (found)
		return e;
	return NULL;
}

static struct mlx5e_encap_entry *
mlx5e_encap_get_create(struct mlx5e_priv *priv, struct ip_tunnel_info *tun_info,
		       struct net_device *mirred_dev, int tunnel_type)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	unsigned short family = ip_tunnel_info_af(tun_info);
	struct ip_tunnel_key *key = &tun_info->key;
	struct mlx5e_encap_entry *e, *e_dup = NULL;
	int err = 0;
	uintptr_t hash_key = hash_encap_info(key);

	e = mlx5e_encap_get(priv, key, hash_key);

	/* must verify if encap is valid or not */
	if (e)
		return e;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return ERR_PTR(-ENOMEM);

	mutex_init(&e->encap_entry_lock);
	e->tun_info = *tun_info;
	e->tunnel_type = tunnel_type;
	INIT_LIST_HEAD(&e->flows);
	INIT_LIST_HEAD(&e->neigh_update_list);
	refcount_set(&e->refcnt, 1);

	if (family == AF_INET)
		err = mlx5e_create_encap_header_ipv4(priv, mirred_dev, e);
	else if (family == AF_INET6)
		err = mlx5e_create_encap_header_ipv6(priv, mirred_dev, e);

	if (err && err != -EAGAIN) {
		kfree(e);
		return ERR_PTR(err);
	}

	spin_lock(&esw->offloads.encap_tbl_lock);
	/* check for concurrent insertion of encap entry with same params */
	e_dup = mlx5e_encap_get(priv, key, hash_key);
	if (e_dup)
		goto err_out;
	hash_add_rcu(esw->offloads.encap_tbl, &e->encap_hlist, hash_key);
	spin_unlock(&esw->offloads.encap_tbl_lock);

	return e;
err_out:
	spin_unlock(&esw->offloads.encap_tbl_lock);
	mlx5e_encap_put(priv, e);
	if (e_dup)
		return e_dup;
	return ERR_PTR(err);
}

static int mlx5e_attach_encap(struct mlx5e_priv *priv,
			      struct ip_tunnel_info *tun_info,
			      struct net_device *mirred_dev,
			      struct net_device **encap_dev,
			      struct mlx5e_tc_flow *flow,
			      struct netlink_ext_ack *extack)
{
	struct mlx5_esw_flow_attr *attr = flow->esw_attr;
	struct ip_tunnel_key *key = &tun_info->key;
	struct mlx5e_encap_entry *e;
	int tunnel_type, err = 0;

	/* udp dst port must be set */
	if (!memchr_inv(&key->tp_dst, 0, sizeof(key->tp_dst)))
		goto vxlan_encap_offload_err;

	/* setting udp src port isn't supported */
	if (memchr_inv(&key->tp_src, 0, sizeof(key->tp_src))) {
vxlan_encap_offload_err:
		NL_SET_ERR_MSG_MOD(extack,
				   "must set udp dst port and not set udp src port");
		netdev_warn(priv->netdev,
			    "must set udp dst port and not set udp src port\n");
		return -EOPNOTSUPP;
	}

	if (mlx5_vxlan_lookup_port(priv->mdev->vxlan, be16_to_cpu(key->tp_dst)) &&
	    MLX5_CAP_ESW(priv->mdev, vxlan_encap_decap)) {
		tunnel_type = MLX5_REFORMAT_TYPE_L2_TO_VXLAN;
	} else {
		NL_SET_ERR_MSG_MOD(extack,
				   "port isn't an offloaded vxlan udp dport");
		netdev_warn(priv->netdev,
			    "%d isn't an offloaded vxlan udp dport\n", be16_to_cpu(key->tp_dst));
		return -EOPNOTSUPP;
	}

	e = mlx5e_encap_get_create(priv, tun_info, mirred_dev, tunnel_type);

	/* must verify if encap is valid or not */
	if (IS_ERR(e))
		return PTR_ERR(e);

	flow->e = e;
	mutex_lock(&e->encap_entry_lock);
	list_add(&flow->encap, &e->flows);
	*encap_dev = e->out_dev;
	if (e->flags & MLX5_ENCAP_ENTRY_VALID)
		attr->encap_id = e->encap_id;
	else
		err = -EAGAIN;
	flow->encap_init_jiffies = e->updated;
	mutex_unlock(&e->encap_entry_lock);

	return err;
}

static int add_vlan_rewrite_action(struct mlx5e_priv *priv,
				   const struct tc_action *a,
				   struct mlx5_esw_flow_attr *attr,
				   struct mlx5e_tc_flow_parse_attr *parse_attr,
				   u32 *action, struct netlink_ext_ack *extack)
{
	int err;
	struct tcf_pedit_key_ex pedit_key_ex = {
		.htype = TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
		.cmd = TCA_PEDIT_KEY_EX_CMD_SET,
	};
	u16 mask16 = VLAN_VID_MASK;
	u16 val16 = tcf_vlan_push_vid(a) & VLAN_VID_MASK;
	struct tc_pedit_key pedit_key = {
		.mask = ~(u32)be16_to_cpu(*(__be16 *)&mask16),
		.val = (u32)be16_to_cpu(*(__be16 *)&val16),
		.off = offsetof(struct vlan_ethhdr, h_vlan_TCI),
	};
	const struct tcf_pedit pedit_act = {
		.tcfp_nkeys = 1,
		.tcfp_keys = &pedit_key,
		.tcfp_keys_ex = &pedit_key_ex,
	};

	if (tcf_vlan_push_prio(a)) {
		NL_SET_ERR_MSG_MOD(extack, "Setting VLAN prio is not supported");
		return -EOPNOTSUPP;
	}

	err = parse_tc_pedit_action(priv, (const struct tc_action *)&pedit_act,
				    MLX5_FLOW_NAMESPACE_FDB, parse_attr, NULL);
	*action |= MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
	attr->mirror_count = attr->out_count;
	return err;
}

static int parse_tc_vlan_action(struct mlx5e_priv *priv,
				const struct tc_action *a,
				struct mlx5_esw_flow_attr *attr,
				u32 *action,
				struct mlx5e_tc_flow_parse_attr *parse_attr,
				struct netlink_ext_ack *extack)
{
	u8 vlan_idx = attr->total_vlan;

	if (vlan_idx >= MLX5_FS_VLAN_DEPTH)
		return -EOPNOTSUPP;

	if (tcf_vlan_action(a) == TCA_VLAN_ACT_POP) {
		if (vlan_idx) {
			if (!mlx5_eswitch_vlan_actions_supported(priv->mdev,
								 MLX5_FS_VLAN_DEPTH))
				return -EOPNOTSUPP;

			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_POP_2;
		} else {
			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_POP;
		}
	} else if (tcf_vlan_action(a) == TCA_VLAN_ACT_PUSH) {
		if ((*action) & MLX5_FLOW_CONTEXT_ACTION_VLAN_POP) {
			/* Replace vlan pop+push with vlan modify */
			*action &= ~MLX5_FLOW_CONTEXT_ACTION_VLAN_POP;
			return add_vlan_rewrite_action(priv, a, attr, parse_attr,
					       action, extack);
		}
		attr->vlan_vid[vlan_idx] = tcf_vlan_push_vid(a);
		attr->vlan_prio[vlan_idx] = tcf_vlan_push_prio(a);
		attr->vlan_proto[vlan_idx] = tcf_vlan_push_proto(a);
		if (!attr->vlan_proto[vlan_idx])
			attr->vlan_proto[vlan_idx] = htons(ETH_P_8021Q);

		if (vlan_idx) {
			if (!mlx5_eswitch_vlan_actions_supported(priv->mdev,
								 MLX5_FS_VLAN_DEPTH))
				return -EOPNOTSUPP;

			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH_2;
		} else {
			if (!mlx5_eswitch_vlan_actions_supported(priv->mdev, 1) &&
			    (tcf_vlan_push_proto(a) != htons(ETH_P_8021Q) ||
			     tcf_vlan_push_prio(a)))
				return -EOPNOTSUPP;

			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH;
		}
	} else { /* action is TCA_VLAN_ACT_MODIFY */
		return add_vlan_rewrite_action(priv, a, attr, parse_attr,
					       action, extack);
	}

	attr->total_vlan = vlan_idx + 1;

	return 0;
}

static int parse_tc_fdb_actions(struct mlx5e_priv *priv, struct tcf_exts *exts,
				struct mlx5e_tc_flow_parse_attr *parse_attr,
				struct mlx5e_tc_flow *flow,
				struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_esw_flow_attr *attr = flow->esw_attr;
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct ip_tunnel_info *info = NULL;
	const struct tc_action *a;
	LIST_HEAD(actions);
	bool encap = false;
	u32 action = 0;
	int err, i;

	attr->parse_attr = parse_attr;

	if (!tcf_exts_has_actions(exts))
		return -EINVAL;

	attr->in_rep = rpriv->rep;
	attr->in_mdev = priv->mdev;

	tcf_exts_for_each_action(i, a, exts) {
		if (is_tcf_gact_shot(a)) {
			action |= MLX5_FLOW_CONTEXT_ACTION_DROP |
				  MLX5_FLOW_CONTEXT_ACTION_COUNT;
			continue;
		}

		if (is_tcf_pedit(a)) {
			err = parse_tc_pedit_action(priv, a, MLX5_FLOW_NAMESPACE_FDB,
						    parse_attr, extack);
			if (err)
				return err;

			action |= MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
			attr->mirror_count = attr->out_count;
			continue;
		}

		if (is_tcf_csum(a)) {
			if (csum_offload_supported(priv, action,
						   tcf_csum_update_flags(a),
						   extack))
				continue;

			return -EOPNOTSUPP;
		}

		if (is_tcf_mirred_egress_redirect(a) || is_tcf_mirred_egress_mirror(a)) {
			struct mlx5e_priv *out_priv;
			struct net_device *out_dev;

			out_dev = tcf_mirred_dev(a);

			if (attr->out_count >= MLX5_MAX_FLOW_FWD_VPORTS) {
				NL_SET_ERR_MSG_MOD(extack,
						   "can't support more output ports, can't offload forwarding");
				pr_err("can't support more than %d output ports, can't offload forwarding\n",
				       attr->out_count);
				return -EOPNOTSUPP;
			}

			if (switchdev_port_same_parent_id(priv->netdev,
							  out_dev) ||
			    is_merged_eswitch_dev(priv, out_dev)) {
				struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
				struct mlx5e_rep_priv *uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
				struct net_device *uplink_dev = uplink_rpriv->netdev;
				struct net_device *upper_lag = mlx5_upper_lag_dev_get(uplink_dev);

				if (upper_lag == out_dev)
					out_dev = uplink_dev;
				action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
					  MLX5_FLOW_CONTEXT_ACTION_COUNT;

				if (!mlx5e_eswitch_rep(out_dev))
					return -EOPNOTSUPP;

				out_priv = netdev_priv(out_dev);
				rpriv = out_priv->ppriv;
				attr->out_rep[attr->out_count] = rpriv->rep;
				attr->out_mdev[attr->out_count++] = out_priv->mdev;
			} else if (encap) {
				parse_attr->mirred_ifindex = out_dev->ifindex;
				parse_attr->tun_info = *info;
				action |= MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT |
					  MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
					  MLX5_FLOW_CONTEXT_ACTION_COUNT;
				/* attr->out_rep is resolved when we handle encap */
			} else {
				NL_SET_ERR_MSG_MOD(extack,
						   "devices are not on same switch HW, can't offload forwarding");
				pr_err("devices %s %s not on same switch HW, can't offload forwarding\n",
				       priv->netdev->name, out_dev->name);
				return -EINVAL;
			}
			continue;
		}

		if (is_tcf_tunnel_set(a)) {
			info = tcf_tunnel_info(a);
			if (info)
				encap = true;
			else
				return -EOPNOTSUPP;
			attr->mirror_count = attr->out_count;
			continue;
		}

		if (is_tcf_vlan(a)) {
			err = parse_tc_vlan_action(priv, a, attr, &action,
						   parse_attr, extack);

			if (err)
				return err;

			attr->mirror_count = attr->out_count;
			continue;
		}

		if (is_tcf_tunnel_release(a)) {
			action |= MLX5_FLOW_CONTEXT_ACTION_DECAP;
			continue;
		}

		if (is_tcf_gact_goto_chain(a)) {
			u32 dest_chain = tcf_gact_goto_chain_index(a);
			u32 max_chain = mlx5_eswitch_get_chain_range(esw);

			if (dest_chain <= attr->chain) {
				NL_SET_ERR_MSG(extack, "Goto earlier chain isn't supported");
				return -EOPNOTSUPP;
			}
			if (dest_chain > max_chain) {
				NL_SET_ERR_MSG(extack, "Requested destination chain is out of supported range");
				return -EOPNOTSUPP;
			}
			action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;
			attr->dest_chain = dest_chain;

			continue;
		}

		return -EINVAL;
	}

	attr->action = action;
	if (!actions_match_supported(priv, exts, parse_attr, flow, extack))
		return -EOPNOTSUPP;

	if (attr->dest_chain) {
		if (attr->action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) {
			NL_SET_ERR_MSG(extack, "Mirroring goto chain rules isn't supported");
			return -EOPNOTSUPP;
		}
		attr->action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	}

	if (attr->mirror_count > 0 && !mlx5_esw_has_fwd_fdb(priv->mdev)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "current firmware doesn't support split rule for port mirroring");
		netdev_warn_once(priv->netdev, "current firmware doesn't support split rule for port mirroring\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static bool is_peer_flow_needed(struct mlx5e_tc_flow *flow)
{
	struct mlx5_esw_flow_attr *attr = flow->esw_attr;
	bool is_rep_ingress = attr->in_rep->vport != MLX5_VPORT_UPLINK &&
				atomic_read(&flow->flags) & MLX5E_TC_FLOW_INGRESS;
	bool act_is_encap = !!(attr->action &
			       MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT);
	bool esw_paired = mlx5_devcom_is_paired(attr->in_mdev->priv.devcom,
						MLX5_DEVCOM_ESW_OFFLOADS);

	if (!esw_paired)
		return false;

	if ((mlx5_lag_is_sriov(attr->in_mdev) ||
	     mlx5_lag_is_multipath(attr->in_mdev)) &&
	    (is_rep_ingress || act_is_encap))
		return true;

	return false;
}

static void get_flags(int flags, int *flow_flags)
{
	int __flow_flags = 0;

	if (flags & MLX5E_TC_INGRESS)
		__flow_flags |= MLX5E_TC_FLOW_INGRESS;
	if (flags & MLX5E_TC_EGRESS)
		__flow_flags |= MLX5E_TC_FLOW_EGRESS;

	if (flags & MLX5E_TC_ESW_OFFLOAD)
		__flow_flags |= MLX5E_TC_FLOW_ESWITCH;
	if (flags & MLX5E_TC_NIC_OFFLOAD)
		__flow_flags |= MLX5E_TC_FLOW_NIC;

	*flow_flags = __flow_flags;
}

static const struct rhashtable_params tc_ht_params = {
	.head_offset = offsetof(struct mlx5e_tc_flow, node),
	.key_offset = offsetof(struct mlx5e_tc_flow, cookie),
	.key_len = sizeof(((struct mlx5e_tc_flow *)0)->cookie),
	.automatic_shrinking = true,
};

static struct rhashtable *get_tc_ht(struct mlx5e_priv *priv, int flags)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_rep_priv *uplink_rpriv;

	if (flags & MLX5E_TC_ESW_OFFLOAD) {
		uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
		return &uplink_rpriv->tc_ht;
	} else /* NIC offload */
		return &priv->fs.tc.ht;
}

static void mlx5e_lock_tc_ht(struct mlx5e_priv *priv, int flags)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_rep_priv *uplink_rpriv;

	if (flags & MLX5E_TC_ESW_OFFLOAD) {
		uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
		spin_lock(&uplink_rpriv->tc_ht_lock);
	} else {
		spin_lock(&priv->fs.tc.ht_lock);
	}
}

static void mlx5e_unlock_tc_ht(struct mlx5e_priv *priv, int flags)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_rep_priv *uplink_rpriv;

	if (flags & MLX5E_TC_ESW_OFFLOAD) {
		uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
		spin_unlock(&uplink_rpriv->tc_ht_lock);
	} else {
		spin_unlock(&priv->fs.tc.ht_lock);
	}
}

static int
mlx5e_alloc_flow(struct mlx5e_priv *priv, int attr_size,
		 struct tc_cls_flower_offload *f, int flow_flags,
		 struct mlx5e_tc_flow_parse_attr **__parse_attr,
		 struct mlx5e_tc_flow **__flow)
{
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct mlx5e_tc_flow *flow;
	int err;

	flow = kzalloc(sizeof(*flow) + attr_size, GFP_KERNEL);
	parse_attr = kvzalloc(sizeof(*parse_attr), GFP_KERNEL);
	if (!parse_attr || !flow) {
		err = -ENOMEM;
		goto err_free;
	}

	flow->cookie = f->cookie;
	atomic_set(&flow->flags, flow_flags);
	flow->priv = priv;
	INIT_LIST_HEAD(&flow->encap);
	INIT_LIST_HEAD(&flow->mod_hdr);
	INIT_LIST_HEAD(&flow->hairpin);
	INIT_LIST_HEAD(&flow->tmp_list);
	refcount_set(&flow->refcnt, 1);

	err = parse_cls_flower(priv, flow, &parse_attr->spec, f);
	if (err)
		goto err_free;

	*__flow = flow;
	*__parse_attr = parse_attr;

	return 0;

err_free:
	kfree(flow);
	kvfree(parse_attr);
	return err;
}

static int
__mlx5e_add_fdb_flow(struct mlx5e_priv *priv,
		     struct tc_cls_flower_offload *f,
		     u8 flow_flags,
		     struct mlx5_eswitch_rep *in_rep,
		     struct mlx5_core_dev *in_mdev,
		     struct mlx5e_tc_flow **__flow)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct netlink_ext_ack *extack = f->common.extack;
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct mlx5e_tc_flow *flow;
	int attr_size, err;

	flow_flags |= MLX5E_TC_FLOW_ESWITCH;
	attr_size  = sizeof(struct mlx5_esw_flow_attr);
	err = mlx5e_alloc_flow(priv, attr_size, f, flow_flags,
			       &parse_attr, &flow);
	if (err)
		goto out;

	flow->esw_attr->chain = f->common.chain_index;
	flow->esw_attr->prio = TC_H_MAJ(f->common.prio) >> 16;
	err = parse_tc_fdb_actions(priv, f->exts, parse_attr, flow, extack);
	if (err)
		goto err_free;

	flow->esw_attr->in_rep = in_rep;
	flow->esw_attr->in_mdev = in_mdev;

	if (MLX5_CAP_ESW(esw->dev, counter_eswitch_affinity) ==
	    MLX5_COUNTER_SOURCE_ESWITCH)
		flow->esw_attr->counter_dev = in_mdev;
	else
		flow->esw_attr->counter_dev = priv->mdev;

	err = mlx5e_tc_add_fdb_flow(priv, parse_attr, flow, extack);
	if (err) {
		if (!(err == -ENETUNREACH && mlx5_lag_is_multipath(in_mdev)))
			goto err_free;

		add_unready_flow(flow);
	}

	if (!(flow->esw_attr->action &
	      MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT)) {
		kvfree(parse_attr);
		flow->esw_attr->parse_attr = NULL;
	}

	err = mlx5e_tc_update_and_init_done_fdb_flow(priv, flow);
	if (err)
		goto err_free;

	*__flow = flow;

	return 0;

err_free:
	mlx5e_flow_put(priv, flow);
out:
	return err;
}

static int mlx5e_tc_add_fdb_peer_flow(struct tc_cls_flower_offload *f,
				      struct mlx5e_tc_flow *flow,
				      u16 flow_flags)
{
	struct mlx5e_priv *priv = flow->priv, *peer_priv;
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch, *peer_esw;
	struct mlx5_devcom *devcom = priv->mdev->priv.devcom;
	struct mlx5e_rep_priv *peer_urpriv;
	struct mlx5e_tc_flow *peer_flow;
	struct mlx5_core_dev *in_mdev;
	int err = 0;

	peer_esw = mlx5_devcom_get_peer_data(devcom, MLX5_DEVCOM_ESW_OFFLOADS);
	if (!peer_esw)
		return -ENODEV;

	peer_urpriv = mlx5_eswitch_get_uplink_priv(peer_esw, REP_ETH);
	peer_priv = netdev_priv(peer_urpriv->netdev);

	/* in_mdev is assigned of which the packet originated from.
	 * So packets redirected to uplink use the same mdev of the
	 * original flow and packets redirected from uplink use the
	 * peer mdev.
	 */
	if (flow->esw_attr->in_rep->vport == MLX5_VPORT_UPLINK)
		in_mdev = peer_priv->mdev;
	else
		in_mdev = priv->mdev;

	err = __mlx5e_add_fdb_flow(peer_priv, f, flow_flags,
				   flow->esw_attr->in_rep, in_mdev, &peer_flow);
	if (err)
		goto out;

	flow->peer_flow = peer_flow;
	atomic_or(MLX5E_TC_FLOW_DUP, &flow->flags);
	mutex_lock(&esw->offloads.peer_mutex);
	list_add_tail(&flow->peer, &esw->offloads.peer_flows);
	mutex_unlock(&esw->offloads.peer_mutex);

out:
	mlx5_devcom_release_peer_data(devcom, MLX5_DEVCOM_ESW_OFFLOADS);
	return err;
}

static int
mlx5e_add_fdb_flow(struct mlx5e_priv *priv,
		   struct tc_cls_flower_offload *f,
		   int flow_flags,
		   struct mlx5e_tc_flow **__flow)
{
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5_eswitch_rep *in_rep = rpriv->rep;
	struct mlx5_core_dev *in_mdev = priv->mdev;
	struct mlx5e_tc_flow *flow;
	int err;

	err = __mlx5e_add_fdb_flow(priv, f, flow_flags, in_rep,
				   in_mdev, &flow);
	if (err)
		goto out;

	if (is_peer_flow_needed(flow)) {
		err = mlx5e_tc_add_fdb_peer_flow(f, flow, flow_flags);
		if (err) {
			mlx5e_tc_del_fdb_flow(priv, flow);
			goto out;
		}
	}

	*__flow = flow;

	return 0;

out:
	return err;
}

static int
mlx5e_add_nic_flow(struct mlx5e_priv *priv,
		   struct tc_cls_flower_offload *f,
		   int flow_flags,
		   struct mlx5e_tc_flow **__flow)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct mlx5e_tc_flow *flow;
	int attr_size, err;

	/* multi-chain not supported for NIC rules */
	if (!tc_cls_can_offload_and_chain0(priv->netdev, &f->common))
		return -EOPNOTSUPP;

	flow_flags |= MLX5E_TC_FLOW_NIC;
	attr_size  = sizeof(struct mlx5_nic_flow_attr);
	err = mlx5e_alloc_flow(priv, attr_size, f, flow_flags,
			       &parse_attr, &flow);
	if (err)
		goto out;

	err = parse_tc_nic_actions(priv, f->exts, parse_attr, flow, extack);
	if (err)
		goto err_free;

	err = mlx5e_tc_add_nic_flow(priv, parse_attr, flow, extack);
	if (err)
		goto err_free;

	mlx5e_set_flow_flag_mb_before(flow, MLX5E_TC_FLOW_OFFLOADED |
				      MLX5E_TC_FLOW_INIT_DONE);
	kfree(parse_attr->mod_hdr_actions);
	kvfree(parse_attr);
	*__flow = flow;

	return 0;

err_free:
	mlx5e_flow_put(priv, flow);
	kfree(parse_attr->mod_hdr_actions);
	kvfree(parse_attr);
out:
	return err;
}

static int
mlx5e_tc_add_flow(struct mlx5e_priv *priv,
		  struct tc_cls_flower_offload *f,
		  int flags,
		  struct mlx5e_tc_flow **flow)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	int flow_flags;
	int err;

	get_flags(flags, &flow_flags);

	if (!tc_can_offload_extack(priv->netdev, f->common.extack))
		return -EOPNOTSUPP;

	if (esw && esw->mode == SRIOV_OFFLOADS)
		err = mlx5e_add_fdb_flow(priv, f, flow_flags, flow);
	else
		err = mlx5e_add_nic_flow(priv, f, flow_flags, flow);

	return err;
}

int mlx5e_configure_flower(struct mlx5e_priv *priv,
			   struct tc_cls_flower_offload *f, int flags)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct rhashtable *tc_ht = get_tc_ht(priv, flags);
	struct mlx5e_tc_flow *flow;
	int err = 0;

	rcu_read_lock();
	flow = rhashtable_lookup(tc_ht, &f->cookie, tc_ht_params);
	if (flow) {
		rcu_read_unlock();
		NL_SET_ERR_MSG_MOD(extack,
				   "flow cookie already exists, ignoring");
		netdev_warn_once(priv->netdev,
				 "flow cookie %lx already exists, ignoring\n",
				 f->cookie);
		goto out;
	}
	rcu_read_unlock();

	err = mlx5e_tc_add_flow(priv, f, flags, &flow);
	if (err)
		goto out;

	err = rhashtable_insert_fast(tc_ht, &flow->node, tc_ht_params);
	if (err)
		goto err_free;

	return 0;

err_free:
	mlx5e_flow_put(priv, flow);
out:
	return err;
}

#define DIRECTION_MASK (MLX5E_TC_INGRESS | MLX5E_TC_EGRESS)
#define FLOW_DIRECTION_MASK (MLX5E_TC_FLOW_INGRESS | MLX5E_TC_FLOW_EGRESS)

static bool same_flow_direction(struct mlx5e_tc_flow *flow, int flags)
{
	if ((atomic_read(&flow->flags) & FLOW_DIRECTION_MASK) ==
	    (flags & DIRECTION_MASK))
		return true;

	return false;
}

int mlx5e_delete_flower(struct mlx5e_priv *priv,
			struct tc_cls_flower_offload *f, int flags)
{
	struct rhashtable *tc_ht = get_tc_ht(priv, flags);
	struct mlx5e_tc_flow *flow;

	mlx5e_lock_tc_ht(priv, flags);

	flow = rhashtable_lookup_fast(tc_ht, &f->cookie, tc_ht_params);
	if (!flow || !same_flow_direction(flow, flags)) {
		mlx5e_unlock_tc_ht(priv, flags);
		return -EINVAL;
	}

	rhashtable_remove_fast(tc_ht, &flow->node, tc_ht_params);
	mlx5e_unlock_tc_ht(priv, flags);

	mlx5e_flow_put(priv, flow);

	return 0;
}

int mlx5e_stats_flower(struct mlx5e_priv *priv,
		       struct tc_cls_flower_offload *f, int flags)
{
	struct mlx5_devcom *devcom = priv->mdev->priv.devcom;
	struct rhashtable *tc_ht = get_tc_ht(priv, flags);
	struct mlx5_eswitch *peer_esw;
	struct mlx5e_tc_flow *flow;
	struct mlx5_fc *counter;
	int err = 0;
	u64 lastuse = 0;
	u64 packets = 0;
	u64 bytes = 0;

	rcu_read_lock();
	flow = mlx5e_flow_get(rhashtable_lookup(tc_ht, &f->cookie,
						tc_ht_params));
	rcu_read_unlock();
	if (IS_ERR(flow)) {
		return PTR_ERR(flow);
	} else if (!same_flow_direction(flow, flags)) {
		err = -EINVAL;
		goto errout;
	}

	if (mlx5e_is_offloaded_flow(flow)) {
		counter = mlx5e_tc_get_counter(flow);
		if (!counter)
			goto errout;

		mlx5_fc_query_cached(counter, &bytes, &packets, &lastuse);
	}

	peer_esw = mlx5_devcom_get_peer_data(devcom, MLX5_DEVCOM_ESW_OFFLOADS);
	if (!peer_esw)
		goto out;

	/* Under multipath it's possible for one rule to be currently
	 * un-offloaded while the other rule is offloaded.
	 */
	if ((atomic_read(&flow->flags) & MLX5E_TC_FLOW_DUP) &&
	    (atomic_read(&flow->peer_flow->flags) & MLX5E_TC_FLOW_OFFLOADED)) {
		u64 bytes2;
		u64 packets2;
		u64 lastuse2;

		counter =  mlx5e_tc_get_counter(flow->peer_flow);
		if (!counter)
			goto no_peer_counter;
		mlx5_fc_query_cached(counter, &bytes2, &packets2, &lastuse2);

		bytes += bytes2;
		packets += packets2;
		lastuse = max_t(u64, lastuse, lastuse2);
	}

no_peer_counter:
	mlx5_devcom_release_peer_data(devcom, MLX5_DEVCOM_ESW_OFFLOADS);
out:
	tcf_exts_stats_update(f->exts, bytes, packets, lastuse);
errout:
	mlx5e_flow_put(priv, flow);
	return err;
}

static void mlx5e_tc_hairpin_update_dead_peer(struct mlx5e_priv *priv,
					      struct mlx5e_priv *peer_priv)
{
	struct mlx5_core_dev *peer_mdev = peer_priv->mdev;
	struct mlx5e_hairpin_entry *hpe;
	u16 peer_vhca_id;
	int bkt;

	if (!same_hw_devs(priv, peer_priv))
		return;

	peer_vhca_id = MLX5_CAP_GEN(peer_mdev, vhca_id);

	hash_for_each(priv->fs.tc.hairpin_tbl, bkt, hpe, hairpin_hlist) {
		if (hpe->peer_vhca_id == peer_vhca_id)
			hpe->hp->pair->peer_gone = true;
	}
}

static int mlx5e_tc_netdev_event(struct notifier_block *this,
				 unsigned long event, void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	struct mlx5e_flow_steering *fs;
	struct mlx5e_priv *peer_priv;
	struct mlx5e_tc_table *tc;
	struct mlx5e_priv *priv;

	if (ndev->netdev_ops != &mlx5e_netdev_ops ||
	    event != NETDEV_UNREGISTER ||
	    ndev->reg_state == NETREG_REGISTERED)
		return NOTIFY_DONE;

	tc = container_of(this, struct mlx5e_tc_table, netdevice_nb);
	fs = container_of(tc, struct mlx5e_flow_steering, tc);
	priv = container_of(fs, struct mlx5e_priv, fs);
	peer_priv = netdev_priv(ndev);
	if (priv == peer_priv ||
	    !(priv->netdev->features & NETIF_F_HW_TC))
		return NOTIFY_DONE;

	mlx5e_tc_hairpin_update_dead_peer(priv, peer_priv);

	return NOTIFY_DONE;
}

int mlx5e_tc_nic_init(struct mlx5e_priv *priv)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	int err;

	mutex_init(&tc->t_lock);
	spin_lock_init(&tc->mod_hdr_tbl_lock);
	hash_init(tc->mod_hdr_tbl);
	spin_lock_init(&tc->hairpin_tbl_lock);
	hash_init(tc->hairpin_tbl);

	spin_lock_init(&tc->ht_lock);
	err = rhashtable_init(&tc->ht, &tc_ht_params);
	if (err)
		return err;

	tc->netdevice_nb.notifier_call = mlx5e_tc_netdev_event;
	if (register_netdevice_notifier(&tc->netdevice_nb)) {
		tc->netdevice_nb.notifier_call = NULL;
		mlx5_core_warn(priv->mdev, "Failed to register netdev notifier\n");
	}

	return err;
}

static void _mlx5e_tc_del_flow(void *ptr, void *arg)
{
	struct mlx5e_tc_flow *flow = ptr;
	struct mlx5e_priv *priv = flow->priv;

	mlx5e_tc_del_flow(priv, flow);
	kfree(flow);
}

void mlx5e_tc_nic_cleanup(struct mlx5e_priv *priv)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;

	if (tc->netdevice_nb.notifier_call)
		unregister_netdevice_notifier(&tc->netdevice_nb);

	rhashtable_destroy(&tc->ht);

	if (!IS_ERR_OR_NULL(tc->t)) {
		mlx5_destroy_flow_table(tc->t);
		tc->t = NULL;
	}
	mutex_destroy(&tc->t_lock);
}

int mlx5e_tc_esw_init(struct rhashtable *tc_ht)
{
	return rhashtable_init(tc_ht, &tc_ht_params);
}

void mlx5e_tc_esw_cleanup(struct rhashtable *tc_ht)
{
	rhashtable_free_and_destroy(tc_ht, _mlx5e_tc_del_flow, NULL);
}

int mlx5e_tc_num_filters(struct mlx5e_priv *priv, int flags)
{
	struct rhashtable *tc_ht = get_tc_ht(priv, flags);

	return atomic_read(&tc_ht->nelems);
}

void mlx5e_tc_clean_fdb_peer_flows(struct mlx5_eswitch *esw)
{
	struct mlx5e_tc_flow *flow, *tmp;

	list_for_each_entry_safe(flow, tmp, &esw->offloads.peer_flows, peer)
		__mlx5e_tc_del_fdb_peer_flow(flow);
}

void mlx5e_tc_reoffload_flows_work(struct mlx5_core_dev *mdev)
{
	struct mlx5_eswitch *esw = mdev->priv.eswitch;
	struct mlx5e_rep_priv *rpriv;
	struct mlx5e_tc_flow *flow, *tmp;

	ASSERT_RTNL();

	rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
	list_for_each_entry_safe(flow, tmp, &rpriv->unready_flows, unready) {
		if (!mlx5e_tc_add_fdb_flow(flow->priv,
					   flow->esw_attr->parse_attr,
					   flow, NULL))
			remove_unready_flow(flow);
	}
}
