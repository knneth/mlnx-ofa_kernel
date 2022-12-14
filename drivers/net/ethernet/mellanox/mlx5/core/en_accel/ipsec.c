/*
 * Copyright (c) 2017 Mellanox Technologies. All rights reserved.
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
 *
 */

#include <crypto/internal/geniv.h>
#include <crypto/aead.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/module.h>

#include "en.h"
#include "en_accel/ipsec.h"
#include "en_accel/ipsec_rxtx.h"
#include "en_accel/ipsec_fs.h"
#include "eswitch.h"
#include "en/ipsec_aso.h"
#include "../esw/ipsec.h"

#ifndef XFRM_OFFLOAD_FULL
#define XFRM_OFFLOAD_FULL 4
#endif

struct mlx5e_ipsec_async_work {
	struct delayed_work dwork;
	struct mlx5e_priv *priv;
	u32 obj_id;
};

static void _mlx5e_ipsec_async_event(struct work_struct *work);

static struct mlx5e_ipsec_sa_entry *to_ipsec_sa_entry(struct xfrm_state *x)
{
	struct mlx5e_ipsec_sa_entry *sa;

	if (!x)
		return NULL;

	sa = (struct mlx5e_ipsec_sa_entry *)x->xso.offload_handle;
	if (!sa)
		return NULL;

	WARN_ON(sa->x != x);
	return sa;
}

struct xfrm_state *mlx5e_ipsec_sadb_rx_lookup(struct mlx5e_ipsec *ipsec,
					      unsigned int handle)
{
	struct mlx5e_ipsec_sa_entry *sa_entry;
	struct xfrm_state *ret = NULL;

	rcu_read_lock();
	hash_for_each_possible_rcu(ipsec->sadb_rx, sa_entry, hlist, handle)
		if (sa_entry->handle == handle) {
			ret = sa_entry->x;
			xfrm_state_hold(ret);
			break;
		}
	rcu_read_unlock();

	return ret;
}

#define ipv6_equal(a, b) (memcmp(&(a), &(b), sizeof(a)) == 0)

static inline bool mlx5e_ipsec_sa_fs_equal(struct mlx5e_ipsec_sa_entry *sa_entry,
					   struct ethtool_rx_flow_spec *fs)
{
	if ((fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT)) == ESP_V4_FLOW)
		return ((sa_entry->x->props.family == AF_INET) &&
			(fs->h_u.esp_ip4_spec.ip4dst == sa_entry->x->id.daddr.a4) &&
			(fs->h_u.esp_ip4_spec.ip4src == sa_entry->x->props.saddr.a4) &&
			(fs->h_u.esp_ip4_spec.spi == sa_entry->x->id.spi));

	return ((sa_entry->x->props.family == AF_INET6) &&
		ipv6_equal(fs->h_u.esp_ip6_spec.ip6dst, sa_entry->x->id.daddr.a6) &&
		ipv6_equal(fs->h_u.esp_ip6_spec.ip6src, sa_entry->x->props.saddr.a6) &&
		(fs->h_u.esp_ip6_spec.spi == sa_entry->x->id.spi));
}

int mlx5e_ipsec_sadb_rx_lookup_rev(struct mlx5e_ipsec *ipsec,
				   struct ethtool_rx_flow_spec *fs, u32 *handle)
{
	struct mlx5e_ipsec_sa_entry *sa_entry;
	int ret = -ENOENT;
	unsigned int temp;

	if (((fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT)) != ESP_V4_FLOW) &&
	    ((fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT)) != ESP_V6_FLOW))
		return -ENOENT;

	rcu_read_lock();
	hash_for_each_rcu(ipsec->sadb_rx, temp, sa_entry, hlist)
		if (mlx5e_ipsec_sa_fs_equal(sa_entry, fs)) {
			*handle = sa_entry->handle;
			ret = 0;
			break;
		}
	rcu_read_unlock();

	return ret;
}


static int  mlx5e_ipsec_sadb_rx_add(struct mlx5e_ipsec_sa_entry *sa_entry,
				    unsigned int handle)
{
	struct mlx5e_ipsec *ipsec = sa_entry->ipsec;
	struct mlx5e_ipsec_sa_entry *_sa_entry;
	unsigned long flags;

	rcu_read_lock();
	hash_for_each_possible_rcu(ipsec->sadb_rx, _sa_entry, hlist, handle)
		if (_sa_entry->handle == handle) {
			rcu_read_unlock();
			return  -EEXIST;
		}
	rcu_read_unlock();

	spin_lock_irqsave(&ipsec->sadb_rx_lock, flags);
	sa_entry->handle = handle;
	hash_add_rcu(ipsec->sadb_rx, &sa_entry->hlist, sa_entry->handle);
	spin_unlock_irqrestore(&ipsec->sadb_rx_lock, flags);

	return 0;
}

static void mlx5e_ipsec_sadb_rx_del(struct mlx5e_ipsec_sa_entry *sa_entry)
{
	struct mlx5e_ipsec *ipsec = sa_entry->ipsec;
	unsigned long flags;

	spin_lock_irqsave(&ipsec->sadb_rx_lock, flags);
	hash_del_rcu(&sa_entry->hlist);
	spin_unlock_irqrestore(&ipsec->sadb_rx_lock, flags);
}

struct xfrm_state *mlx5e_ipsec_sadb_tx_lookup(struct mlx5e_ipsec *ipsec,
					      unsigned int handle)
{
	struct mlx5e_ipsec_sa_entry *sa_entry;
	struct xfrm_state *ret = NULL;

	rcu_read_lock();
	hash_for_each_possible_rcu(ipsec->sadb_tx, sa_entry, hlist, handle)
		if (sa_entry->handle == handle) {
			ret = sa_entry->x;
			xfrm_state_hold(ret);
			break;
		}
	rcu_read_unlock();

	return ret;
}

static int  mlx5e_ipsec_sadb_tx_add(struct mlx5e_ipsec_sa_entry *sa_entry,
				    unsigned int handle)
{
	struct mlx5e_ipsec *ipsec = sa_entry->ipsec;
	struct mlx5e_ipsec_sa_entry *_sa_entry;
	unsigned long flags;

	rcu_read_lock();
	hash_for_each_possible_rcu(ipsec->sadb_tx, _sa_entry, hlist, handle)
		if (_sa_entry->handle == handle) {
			rcu_read_unlock();
			return  -EEXIST;
		}
	rcu_read_unlock();

	spin_lock_irqsave(&ipsec->sadb_tx_lock, flags);
	sa_entry->handle = handle;
	hash_add_rcu(ipsec->sadb_tx, &sa_entry->hlist, sa_entry->handle);
	spin_unlock_irqrestore(&ipsec->sadb_tx_lock, flags);

	return 0;
}

static void mlx5e_ipsec_sadb_tx_del(struct mlx5e_ipsec_sa_entry *sa_entry)
{
	struct mlx5e_ipsec *ipsec = sa_entry->ipsec;
	unsigned long flags;

	spin_lock_irqsave(&ipsec->sadb_tx_lock, flags);
	hash_del_rcu(&sa_entry->hlist);
	spin_unlock_irqrestore(&ipsec->sadb_tx_lock, flags);
}

static bool mlx5e_ipsec_update_esn_state(struct mlx5e_ipsec_sa_entry *sa_entry)
{
	struct xfrm_replay_state_esn *replay_esn;
	u32 seq_bottom = 0;
	u8 overlap;
	u32 *esn;

	if (!(sa_entry->x->props.flags & XFRM_STATE_ESN)) {
		sa_entry->esn_state.trigger = 0;
		return false;
	}

	replay_esn = sa_entry->x->replay_esn;
	if (replay_esn->seq >= replay_esn->replay_window)
		seq_bottom = replay_esn->seq - replay_esn->replay_window + 1;

	overlap = sa_entry->esn_state.overlap;

	sa_entry->esn_state.esn = xfrm_replay_seqhi(sa_entry->x,
						    htonl(seq_bottom));
	esn = &sa_entry->esn_state.esn;

	sa_entry->esn_state.trigger = 1;
	if (unlikely(overlap && seq_bottom < MLX5E_IPSEC_ESN_SCOPE_MID)) {
		++(*esn);
		sa_entry->esn_state.overlap = 0;
		return true;
	} else if (unlikely(!overlap &&
			    (seq_bottom >= MLX5E_IPSEC_ESN_SCOPE_MID))) {
		sa_entry->esn_state.overlap = 1;
		return true;
	}

	return false;
}

static void
initialize_lifetime_limit(struct mlx5e_ipsec_sa_entry *sa_entry,
			  struct mlx5_accel_esp_xfrm_attrs *attrs)
{
	struct mlx5e_ipsec_state_lft *lft = &sa_entry->lft;
	struct xfrm_state *x = sa_entry->x;
	u64 soft_limit, hard_limit;
	struct net_device *netdev;
	struct mlx5e_priv *priv;

	netdev = x->xso.dev;
	priv = netdev_priv(netdev);

	if (MLX5_CAP_GEN(priv->mdev, fpga))
		return;

	hard_limit = x->lft.hard_packet_limit;
	soft_limit = (x->lft.soft_packet_limit == IPSEC_NO_LIMIT)
			? 0 : x->lft.soft_packet_limit;
	if (!(x->xso.flags & XFRM_OFFLOAD_FULL) ||
	    (hard_limit <= soft_limit) ||
	    (hard_limit == IPSEC_NO_LIMIT)) {
		attrs->soft_packet_limit = IPSEC_NO_LIMIT;
		attrs->hard_packet_limit = IPSEC_NO_LIMIT;

		if ((hard_limit <= soft_limit) && hard_limit)
			netdev_warn(priv->netdev,
				    "hard limit=%lld must be bigger than soft limit=%lld\n",
				    hard_limit, soft_limit);
		return;
	}

	/* We have three possible scenarios:
	 * 1: soft and hard less than 32 bit
	 * 2: soft less than 32 bit, hard greater than 32 bit
	 * 3: soft and hard greater than 32 bit
	 */
	if (hard_limit < IPSEC_HW_LIMIT) {
		/* Case 1: we have one round of hard and one round of soft */
		lft->round_hard = 1;
		lft->round_soft = soft_limit ? 1 : 0;
		lft->is_simulated = false;

		/* xfrm user set soft limit is 2 and hard limit is 9 meaning u raise soft event
		 * after 2 packet and hard event after 9 packets. It means for hard limit you
		 * set counter to 9. For soft limit you have to set the comparator to 7 so that
		 * you get the soft event after 2 packet
		 */
		attrs->soft_packet_limit = soft_limit ? hard_limit - soft_limit : 0;;
		attrs->hard_packet_limit = hard_limit;
		return;
	}

	/* Case 2 and 3:
	 * Each interrupt (round) counts 2^31 packets. How it works is:
	 *   Soft limit (comparator) is set 2^31. At soft event, counter is < 2^31
	 *   and counter's bit(31) is set for another round of counting.
	 * If round hard is not divisible by 2^31, the first round is for counting
	 * the round hard's modulo of 2^31.
	 */
	lft->is_simulated = true;

	/* To distinguish betwen no soft limit and soft limit,
	 * we notify soft when round_soft == 1. Therefore + 1 to the division result
	 */
	lft->round_soft = (soft_limit) ? (soft_limit >> IPSEC_SW_LIMIT_BIT) + 1 : 0;
	lft->round_hard = hard_limit >> IPSEC_SW_LIMIT_BIT;

	attrs->hard_packet_limit = IPSEC_SW_LIMIT + (hard_limit & IPSEC_SW_MASK);
	attrs->soft_packet_limit = IPSEC_SW_LIMIT;
}

static void
mlx5e_ipsec_build_accel_xfrm_attrs(struct mlx5e_ipsec_sa_entry *sa_entry,
				   struct mlx5_accel_esp_xfrm_attrs *attrs)
{
	struct aes_gcm_keymat *aes_gcm = &attrs->keymat.aes_gcm;
	unsigned int crypto_data_len, key_len;
	struct xfrm_state *x = sa_entry->x;
	struct aead_geniv_ctx *geniv_ctx;
	struct crypto_aead *aead;
	int ivsize;

	memset(attrs, 0, sizeof(*attrs));

	/* key */
	crypto_data_len = (x->aead->alg_key_len + 7) / 8;
	key_len = crypto_data_len - 4; /* 4 bytes salt at end */

	memcpy(aes_gcm->aes_key, x->aead->alg_key, key_len);
	aes_gcm->key_len = key_len * 8;

	/* salt and seq_iv */
	aead = x->data;
	geniv_ctx = crypto_aead_ctx(aead);
	ivsize = crypto_aead_ivsize(aead);
	memcpy(&aes_gcm->seq_iv, &geniv_ctx->salt, ivsize);
	memcpy(&aes_gcm->salt, x->aead->alg_key + key_len,
	       sizeof(aes_gcm->salt));

	/* iv len */
	aes_gcm->icv_len = x->aead->alg_icv_len;

	/* esn */
	if (sa_entry->esn_state.trigger) {
		attrs->flags |= MLX5_ACCEL_ESP_FLAGS_ESN_TRIGGERED;
		attrs->esn = sa_entry->esn_state.esn;
		if (sa_entry->esn_state.overlap)
			attrs->flags |= MLX5_ACCEL_ESP_FLAGS_ESN_STATE_OVERLAP;
		attrs->replay_window = x->replay_esn->replay_window;
	}

	/* rx handle */
	attrs->sa_handle = sa_entry->handle;

	/* algo type */
	attrs->keymat_type = MLX5_ACCEL_ESP_KEYMAT_AES_GCM;

	/* action */
	attrs->action = (!(x->xso.flags & XFRM_OFFLOAD_INBOUND)) ?
			MLX5_ACCEL_ESP_ACTION_ENCRYPT :
			MLX5_ACCEL_ESP_ACTION_DECRYPT;
	/* flags */
	attrs->flags |= (x->props.mode == XFRM_MODE_TRANSPORT) ?
			MLX5_ACCEL_ESP_FLAGS_TRANSPORT :
			MLX5_ACCEL_ESP_FLAGS_TUNNEL;

	if (x->xso.flags & XFRM_OFFLOAD_FULL)
		attrs->flags |= MLX5_ACCEL_ESP_FLAGS_FULL_OFFLOAD;

	/* spi */
	attrs->spi = x->id.spi;

	/* source , destination ips and udp dport */
	memcpy(&attrs->saddr, x->props.saddr.a6, sizeof(attrs->saddr));
	memcpy(&attrs->daddr, x->id.daddr.a6, sizeof(attrs->daddr));
	attrs->upspec.dport = ntohs(x->sel.dport);
	attrs->upspec.dport_mask = ntohs(x->sel.dport_mask);
	attrs->upspec.proto = x->sel.proto;
	attrs->is_ipv6 = (x->props.family != AF_INET);

	/* authentication tag length */
	attrs->aulen = crypto_aead_authsize(aead);

	/* lifetime limit for full offload */
	initialize_lifetime_limit(sa_entry, attrs);
}

static inline int mlx5e_xfrm_validate_state(struct xfrm_state *x)
{
	struct net_device *netdev = x->xso.real_dev;
	struct mlx5_core_dev *mdev;
	struct mlx5_eswitch *esw;
	struct mlx5e_priv *priv;

	priv = netdev_priv(netdev);
	mdev = priv->mdev;

	if (x->props.aalgo != SADB_AALG_NONE) {
		netdev_info(netdev, "Cannot offload authenticated xfrm states\n");
		return -EINVAL;
	}
	if (x->props.ealgo != SADB_X_EALG_AES_GCM_ICV16) {
		netdev_info(netdev, "Only AES-GCM-ICV16 xfrm state may be offloaded\n");
		return -EINVAL;
	}
	if (x->props.calgo != SADB_X_CALG_NONE) {
		netdev_info(netdev, "Cannot offload compressed xfrm states\n");
		return -EINVAL;
	}
	if (x->props.flags & XFRM_STATE_ESN &&
	    !(mlx5_accel_ipsec_device_caps(mdev) &
	    MLX5_ACCEL_IPSEC_CAP_ESN)) {
		netdev_info(netdev, "Cannot offload ESN xfrm states\n");
		return -EINVAL;
	}
	if (x->props.family != AF_INET &&
	    x->props.family != AF_INET6) {
		netdev_info(netdev, "Only IPv4/6 xfrm states may be offloaded\n");
		return -EINVAL;
	}
	if (x->props.mode != XFRM_MODE_TRANSPORT &&
	    x->props.mode != XFRM_MODE_TUNNEL) {
		dev_info(&netdev->dev, "Only transport and tunnel xfrm states may be offloaded\n");
		return -EINVAL;
	}
	if (x->id.proto != IPPROTO_ESP) {
		netdev_info(netdev, "Only ESP xfrm state may be offloaded\n");
		return -EINVAL;
	}
	if (x->encap) {
		netdev_info(netdev, "Encapsulated xfrm state may not be offloaded\n");
		return -EINVAL;
	}
	if (!x->aead) {
		netdev_info(netdev, "Cannot offload xfrm states without aead\n");
		return -EINVAL;
	}
	if (x->aead->alg_icv_len != 128) {
		netdev_info(netdev, "Cannot offload xfrm states with AEAD ICV length other than 128bit\n");
		return -EINVAL;
	}
	if ((x->aead->alg_key_len != 128 + 32) &&
	    (x->aead->alg_key_len != 256 + 32)) {
		netdev_info(netdev, "Cannot offload xfrm states with AEAD key length other than 128/256 bit\n");
		return -EINVAL;
	}
	if (x->tfcpad) {
		netdev_info(netdev, "Cannot offload xfrm states with tfc padding\n");
		return -EINVAL;
	}
	if (!x->geniv) {
		netdev_info(netdev, "Cannot offload xfrm states without geniv\n");
		return -EINVAL;
	}
	if (strcmp(x->geniv, "seqiv")) {
		netdev_info(netdev, "Cannot offload xfrm states with geniv other than seqiv\n");
		return -EINVAL;
	}
	if (x->props.family == AF_INET6 &&
	    !(mlx5_accel_ipsec_device_caps(mdev) &
	     MLX5_ACCEL_IPSEC_CAP_IPV6)) {
		netdev_info(netdev, "IPv6 xfrm state offload is not supported by this device\n");
		return -EINVAL;
	}
	if (x->xso.flags & XFRM_OFFLOAD_FULL) {
		if (!(mlx5_accel_ipsec_device_caps(mdev) & MLX5_ACCEL_IPSEC_CAP_FULL_OFFLOAD)) {
			netdev_info(netdev, "IPsec full offload is not supported by this device.\n");
			return -EINVAL;
		}
		esw = mdev->priv.eswitch;
		if (!esw || esw->mode != MLX5_ESWITCH_OFFLOADS) {
			netdev_info(netdev, "IPsec full offload allowed only in switchdev mode.\n");
			return -EINVAL;
		}
		if (esw->offloads.ipsec != DEVLINK_ESWITCH_IPSEC_MODE_FULL) {
			netdev_info(netdev,
				    "IPsec full offload allowed only in when devlink full ipsec mode is set.\n");
			return -EINVAL;
		}
	} else {
		esw = mdev->priv.eswitch;
		if (esw && esw->offloads.ipsec == DEVLINK_ESWITCH_IPSEC_MODE_FULL) {
			netdev_info(netdev,
				    "IPsec crypto only offload is not allowed when devlink ipsec mode is full.\n");
			return -EINVAL;
		}
	}

	if ((x->xso.flags & XFRM_OFFLOAD_FULL) &&
	    ((x->lft.hard_byte_limit != XFRM_INF) ||
	     (x->lft.soft_byte_limit != XFRM_INF))) {
		netdev_info(netdev, "full offload state does not support:\n\
				x->lft.hard_byte_limit=0x%llx,\n\
				x->lft.soft_byte_limit=0x%llx,\n",
				x->lft.hard_byte_limit,
				x->lft.soft_byte_limit);
		return -EINVAL;
	}

	return 0;
}

static int mlx5e_xfrm_fs_add_rule(struct mlx5e_priv *priv,
				  struct mlx5e_ipsec_sa_entry *sa_entry)
{
	if (!mlx5_is_ipsec_device(priv->mdev))
		return 0;

	return mlx5e_accel_ipsec_fs_add_rule(priv, &sa_entry->xfrm->attrs,
					     sa_entry->ipsec_obj_id,
					     &sa_entry->ipsec_rule);
}

static void mlx5e_xfrm_fs_del_rule(struct mlx5e_priv *priv,
				   struct mlx5e_ipsec_sa_entry *sa_entry)
{
	if (!mlx5_is_ipsec_device(priv->mdev))
		return;

	mlx5e_accel_ipsec_fs_del_rule(priv, &sa_entry->xfrm->attrs,
				      &sa_entry->ipsec_rule);
}

static int mlx5e_xfrm_add_state(struct xfrm_state *x)
{
	struct mlx5e_ipsec_sa_entry *sa_entry = NULL;
	struct net_device *netdev = x->xso.real_dev;
	struct mlx5_accel_esp_xfrm_attrs attrs;
	struct mlx5e_priv *priv;
	unsigned int sa_handle;
	u32 pdn;
	int err;

	priv = netdev_priv(netdev);

	err = mlx5e_xfrm_validate_state(x);
	if (err)
		return err;

	sa_entry = kzalloc(sizeof(*sa_entry), GFP_KERNEL);
	if (!sa_entry) {
		err = -ENOMEM;
		goto out;
	}

	sa_entry->x = x;
	sa_entry->ipsec = priv->ipsec;

	/* check esn */
	mlx5e_ipsec_update_esn_state(sa_entry);

	/* create xfrm */
	mlx5e_ipsec_build_accel_xfrm_attrs(sa_entry, &attrs);
	sa_entry->xfrm =
		mlx5_accel_esp_create_xfrm(priv->mdev, &attrs,
					   MLX5_ACCEL_XFRM_FLAG_REQUIRE_METADATA);
	if (IS_ERR(sa_entry->xfrm)) {
		err = PTR_ERR(sa_entry->xfrm);
		goto err_sa_entry;
	}

	/* create hw context */
	pdn = priv->ipsec->ipsec_aso ? priv->ipsec->ipsec_aso->aso->pdn : 0;
	sa_entry->hw_context =
			mlx5_accel_esp_create_hw_context(priv->mdev,
							 sa_entry->xfrm,
							 pdn,
							 &sa_handle);
	if (IS_ERR(sa_entry->hw_context)) {
		err = PTR_ERR(sa_entry->hw_context);
		goto err_xfrm;
	}

	sa_entry->ipsec_obj_id = sa_handle;
	err = mlx5e_xfrm_fs_add_rule(priv, sa_entry);
	if (err)
		goto err_hw_ctx;

	if (x->xso.flags & XFRM_OFFLOAD_INBOUND) {
		err = mlx5e_ipsec_sadb_rx_add(sa_entry, sa_handle);
		if (err)
			goto err_add_rule;
	} else {
		err = mlx5e_ipsec_sadb_tx_add(sa_entry, sa_handle);
		if (err)
			goto err_add_rule;
		sa_entry->set_iv_op = (x->props.flags & XFRM_STATE_ESN) ?
				mlx5e_ipsec_set_iv_esn : mlx5e_ipsec_set_iv;
	}

	x->xso.offload_handle = (unsigned long)sa_entry;
	goto out;

err_add_rule:
	mlx5e_xfrm_fs_del_rule(priv, sa_entry);
err_hw_ctx:
	mlx5_accel_esp_free_hw_context(priv->mdev, sa_entry->hw_context);
err_xfrm:
	mlx5_accel_esp_destroy_xfrm(sa_entry->xfrm);
err_sa_entry:
	kfree(sa_entry);

out:
	return err;
}

static void mlx5e_xfrm_del_state(struct xfrm_state *x)
{
	struct mlx5e_ipsec_sa_entry *sa_entry = to_ipsec_sa_entry(x);

	if (!sa_entry || sa_entry->is_removed)
		return;

	if (x->xso.flags & XFRM_OFFLOAD_INBOUND)
		mlx5e_ipsec_sadb_rx_del(sa_entry);
	else
		mlx5e_ipsec_sadb_tx_del(sa_entry);
}

static void clean_up_steering(struct mlx5e_ipsec_sa_entry *sa_entry, struct mlx5e_priv *priv)
{
	if (!sa_entry->hw_context)
		return;

	flush_workqueue(sa_entry->ipsec->wq);
	mlx5e_xfrm_fs_del_rule(priv, sa_entry);
	mlx5_accel_esp_free_hw_context(sa_entry->xfrm->mdev, sa_entry->hw_context);
	mlx5_accel_esp_destroy_xfrm(sa_entry->xfrm);
}

static void mlx5e_xfrm_free_state(struct xfrm_state *x)
{
	struct mlx5e_ipsec_sa_entry *sa_entry = to_ipsec_sa_entry(x);
	struct mlx5e_priv *priv = netdev_priv(x->xso.dev);

	if (!sa_entry)
		return;

	if (!sa_entry->is_removed)
		clean_up_steering(sa_entry, priv);

	kfree(sa_entry);
}

void mlx5e_ipsec_ul_cleanup(struct mlx5e_priv *priv)
{
	struct mlx5e_ipsec_sa_entry *sa_entry;
	struct mlx5e_ipsec *ipsec = priv->ipsec;
	unsigned int bucket;

	if (!ipsec)
		return;

	/* Take rtnl lock to block XFRM Netlink command.
	 * Cannot take rcu. Therefore, cannot handle race situation
	 * with internal net/xfrm call back.
	 */
	rtnl_lock();
	hash_for_each_rcu(ipsec->sadb_rx, bucket, sa_entry, hlist) {
		sa_entry->is_removed = true;
		mlx5e_ipsec_sadb_rx_del(sa_entry);
		clean_up_steering(sa_entry, priv);
	}

	hash_for_each_rcu(ipsec->sadb_tx, bucket, sa_entry, hlist) {
		sa_entry->is_removed = true;
		mlx5e_ipsec_sadb_tx_del(sa_entry);
		clean_up_steering(sa_entry, priv);
	}
	rtnl_unlock();
}

int mlx5e_ipsec_init(struct mlx5e_priv *priv)
{
	struct mlx5e_ipsec *ipsec = NULL;
	int err;

	if (!MLX5_IPSEC_DEV(priv->mdev)) {
		netdev_dbg(priv->netdev, "Not an IPSec offload device\n");
		return 0;
	}

	ipsec = kzalloc(sizeof(*ipsec), GFP_KERNEL);
	if (!ipsec)
		return -ENOMEM;

	hash_init(ipsec->sadb_rx);
	spin_lock_init(&ipsec->sadb_rx_lock);
	hash_init(ipsec->sadb_tx);
	spin_lock_init(&ipsec->sadb_tx_lock);
	ida_init(&ipsec->halloc);
	ipsec->en_priv = priv;
	ipsec->en_priv->ipsec = ipsec;
	ipsec->no_trailer = !!(mlx5_accel_ipsec_device_caps(priv->mdev) &
			       MLX5_ACCEL_IPSEC_CAP_RX_NO_TRAILER);
	ipsec->wq = alloc_ordered_workqueue("mlx5e_ipsec: %s", 0,
					    priv->netdev->name);
	if (!ipsec->wq) {
		err = -ENOMEM;
		goto out_wq;
	}

	err = mlx5e_accel_ipsec_fs_init(priv);
	if (err)
		goto out_fs;

	if (mlx5_is_ipsec_full_offload(priv))
		mlx5e_ipsec_aso_setup(priv);

	netdev_dbg(priv->netdev, "IPSec attached to netdevice\n");
	return 0;

out_fs:
	destroy_workqueue(ipsec->wq);
out_wq:
	ida_destroy(&ipsec->halloc);
	kfree(ipsec);
	return err;
}

void mlx5e_ipsec_cleanup(struct mlx5e_priv *priv)
{
	struct mlx5e_ipsec *ipsec = priv->ipsec;

	if (!ipsec)
		return;

	mlx5e_ipsec_aso_cleanup(priv);
	priv->ipsec->ipsec_aso = NULL;

	mlx5e_accel_ipsec_fs_cleanup(priv);
	destroy_workqueue(ipsec->wq);
	ida_destroy(&ipsec->halloc);
	kfree(ipsec);
	priv->ipsec = NULL;
}

static bool mlx5e_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *x)
{
	if (x->props.family == AF_INET) {
		/* Offload with IPv4 options is not supported yet */
		if (ip_hdr(skb)->ihl > 5)
			return false;
	} else {
		/* Offload with IPv6 extension headers is not support yet */
		if (ipv6_ext_hdr(ipv6_hdr(skb)->nexthdr))
			return false;
	}

	return true;
}

struct mlx5e_ipsec_modify_state_work {
	struct work_struct		work;
	struct mlx5_accel_esp_xfrm_attrs attrs;
	struct mlx5e_ipsec_sa_entry	*sa_entry;
};

static void _update_xfrm_state(struct work_struct *work)
{
	int ret;
	struct mlx5e_ipsec_modify_state_work *modify_work =
		container_of(work, struct mlx5e_ipsec_modify_state_work, work);
	struct mlx5e_ipsec_sa_entry *sa_entry = modify_work->sa_entry;

	ret = mlx5_accel_esp_modify_xfrm(sa_entry->xfrm,
					 &modify_work->attrs);
	if (ret)
		netdev_warn(sa_entry->ipsec->en_priv->netdev,
			    "Not an IPSec offload device\n");

	kfree(modify_work);
}

static void mlx5e_xfrm_advance_esn_state(struct xfrm_state *x)
{
	struct mlx5e_ipsec_sa_entry *sa_entry = to_ipsec_sa_entry(x);
	struct mlx5e_ipsec_modify_state_work *modify_work;
	bool need_update;

	if (!sa_entry)
		return;

	need_update = mlx5e_ipsec_update_esn_state(sa_entry);
	if (!need_update)
		return;

	modify_work = kzalloc(sizeof(*modify_work), GFP_ATOMIC);
	if (!modify_work)
		return;

	mlx5e_ipsec_build_accel_xfrm_attrs(sa_entry, &modify_work->attrs);
	modify_work->sa_entry = sa_entry;

	INIT_WORK(&modify_work->work, _update_xfrm_state);
	WARN_ON(!queue_work(sa_entry->ipsec->wq, &modify_work->work));
}

static const struct xfrmdev_ops mlx5e_ipsec_xfrmdev_ops = {
	.xdo_dev_state_add	= mlx5e_xfrm_add_state,
	.xdo_dev_state_delete	= mlx5e_xfrm_del_state,
	.xdo_dev_state_free	= mlx5e_xfrm_free_state,
	.xdo_dev_offload_ok	= mlx5e_ipsec_offload_ok,
	.xdo_dev_state_advance_esn = mlx5e_xfrm_advance_esn_state,
};

void mlx5e_ipsec_build_netdev(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	struct net_device *netdev = priv->netdev;

	if (!(mlx5_accel_ipsec_device_caps(mdev) & MLX5_ACCEL_IPSEC_CAP_ESP) ||
	    !MLX5_CAP_ETH(mdev, swp)) {
		mlx5_core_dbg(mdev, "mlx5e: ESP and SWP offload not supported\n");
		return;
	}

	mlx5_core_info(mdev, "mlx5e: IPSec ESP acceleration enabled\n");
	netdev->xfrmdev_ops = &mlx5e_ipsec_xfrmdev_ops;
	netdev->features |= NETIF_F_HW_ESP;
	netdev->hw_enc_features |= NETIF_F_HW_ESP;

	if (!MLX5_CAP_ETH(mdev, swp_csum)) {
		mlx5_core_dbg(mdev, "mlx5e: SWP checksum not supported\n");
		return;
	}

	netdev->features |= NETIF_F_HW_ESP_TX_CSUM;
	netdev->hw_enc_features |= NETIF_F_HW_ESP_TX_CSUM;

	if (!(mlx5_accel_ipsec_device_caps(mdev) & MLX5_ACCEL_IPSEC_CAP_LSO) ||
	    !MLX5_CAP_ETH(mdev, swp_lso)) {
		mlx5_core_dbg(mdev, "mlx5e: ESP LSO not supported\n");
		return;
	}

	if (mlx5_is_ipsec_device(mdev))
		netdev->gso_partial_features |= NETIF_F_GSO_ESP;

	mlx5_core_dbg(mdev, "mlx5e: ESP GSO capability turned on\n");
	netdev->features |= NETIF_F_GSO_ESP;
	netdev->hw_features |= NETIF_F_GSO_ESP;
	netdev->hw_enc_features |= NETIF_F_GSO_ESP;
}

static void update_esn_full_offload(struct mlx5e_priv *priv,
				    struct mlx5e_ipsec_sa_entry *sa_entry,
				    u32 obj_id, u32 mode_param)
{
	struct mlx5_accel_esp_xfrm_attrs attrs = {};

	if (mode_param < MLX5E_IPSEC_ESN_SCOPE_MID) {
		sa_entry->esn_state.esn++;
		sa_entry->esn_state.overlap = 0;
	} else {
		sa_entry->esn_state.overlap = 1;
	}

	mlx5e_ipsec_build_accel_xfrm_attrs(sa_entry, &attrs);
	mlx5_accel_esp_modify_xfrm(sa_entry->xfrm, &attrs);
	mlx5e_ipsec_aso_set(priv, obj_id, ARM_ESN_EVENT, 0, NULL, NULL, NULL, NULL);
}

static void _mlx5e_ipsec_async_event(struct work_struct *work)
{
	struct mlx5e_ipsec_async_work *async_work;
	struct mlx5e_ipsec_sa_entry *sa_entry;
	struct mlx5e_ipsec_state_lft *lft;
	u32 hard_cnt, soft_cnt, old_cnt;
	struct delayed_work *dwork;
	struct mlx5e_priv *priv;
	struct xfrm_state *xs;
	u32 mode_param;
	u8 event_arm;
	u32 obj_id;
	int err;

	/* Look up xfrm_state from obj_id */
	dwork = to_delayed_work(work);
	async_work = container_of(dwork, struct mlx5e_ipsec_async_work, dwork);
	priv = async_work->priv;
	obj_id = async_work->obj_id;

	xs = mlx5e_ipsec_sadb_tx_lookup(priv->ipsec, obj_id);
	if (!xs) {
		xs = mlx5e_ipsec_sadb_rx_lookup(priv->ipsec, obj_id);
		if (!xs)
			goto out_async_work;
	}

	sa_entry = to_ipsec_sa_entry(xs);
	if (!sa_entry)
		goto out_xs_state;

	lft = &sa_entry->lft;

	/* Query IPsec ASO context */
	if (mlx5e_ipsec_aso_query(priv, obj_id, &hard_cnt, &soft_cnt, &event_arm, &mode_param))
		goto out_xs_state;

	/* Check ESN event */
	if (sa_entry->esn_state.trigger && !(event_arm & MLX5_ASO_ESN_ARM))
		update_esn_full_offload(priv, sa_entry, obj_id, mode_param);

	/* Check life time event */
	if (hard_cnt > soft_cnt ||
	    (!hard_cnt && !(event_arm & MLX5_ASO_REMOVE_FLOW_ENABLE)))
		goto out_xs_state;

	/* Life time event */
	if (!hard_cnt) { /* Notify hard lifetime to xfrm stack */
		goto out_xs_state;
	}

	/* 0: no more soft
	 * 1: notify soft
	 */
	if (lft->round_soft) {
		lft->round_soft--;
	}

	if (!lft->is_simulated) /* hard_limit < IPSEC_HW_LIMIT */
		goto out_xs_state;

	/* Simulated case */
	if (hard_cnt < IPSEC_SW_LIMIT) {
		lft->round_hard--;
		if (!lft->round_hard) /* already in last round, no need to set bit(31) */
			goto out_xs_state;
	}

	/* Update ASO context */
	old_cnt = hard_cnt;

	if (soft_cnt != IPSEC_SW_LIMIT)
		err = mlx5e_ipsec_aso_set(priv, obj_id,
					  SET_SOFT | ARM_SOFT | SET_CNT_BIT31,
					  IPSEC_SW_LIMIT, &hard_cnt, &soft_cnt, NULL, NULL);
	else
		err = mlx5e_ipsec_aso_set(priv, obj_id,
					  ARM_SOFT | SET_CNT_BIT31,
					  0, &hard_cnt, &soft_cnt, NULL, NULL);

	/* when soft_cnt == IPSEC_SW_LIMIT, soft event can happen
	 *   case 1: hard_cnt goes down from IPSEC_SW_LIMIT to IPSEC_SW_LIMIT - 1. In this case,
	 *   we need one extra round of soft event.
	 *   case 2: hard_count goes down from (IPSEC_SW_LIMIT + a) to IPSEC_SW_LIMIT
	 */
	if (old_cnt == IPSEC_SW_LIMIT) {
		if (hard_cnt > old_cnt)
			lft->round_hard--;
		else if (lft->round_soft)
			lft->round_soft++;
	}

out_xs_state:
	xfrm_state_put(xs);

out_async_work:
	kfree(async_work);
}

int mlx5e_ipsec_async_event(struct mlx5e_priv *priv, u32 obj_id)
{
	struct mlx5e_ipsec_async_work *async_work;

	async_work = kzalloc(sizeof(*async_work), GFP_ATOMIC);
	if (!async_work)
		return NOTIFY_DONE;

	async_work->priv = priv;
	async_work->obj_id = obj_id;

	INIT_DELAYED_WORK(&async_work->dwork, _mlx5e_ipsec_async_event);

	WARN_ON(!queue_delayed_work(priv->ipsec->wq, &async_work->dwork, 0));

	return NOTIFY_OK;
}
