// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2019 Mellanox Technologies.

#include <net/inet6_hashtables.h>
#include "en_accel/en_accel.h"
#include "en_accel/tls.h"
#include "en_accel/ktls_txrx.h"
#include "en_accel/ktls_utils.h"
#include "en_accel/fs_tcp.h"

#define KTLS_STATS_INC(priv, rxq, fld) \
		((priv)->channels.c[rxq]->rq.stats->fld++)

struct accel_rule {
	struct work_struct work;
	struct mlx5e_priv *priv;
	struct mlx5_flow_handle *rule;
	struct sock *sk;
};

#define PROGRESS_PARAMS_WRITE_UNIT	64
#define PROGRESS_PARAMS_PADDED_SIZE	\
		(ALIGN(sizeof(struct mlx5_wqe_tls_progress_params_seg), \
		       PROGRESS_PARAMS_WRITE_UNIT))

struct mlx5e_ktls_rx_resync_ctx {
	struct work_struct work;
	struct mlx5e_priv *priv;
	dma_addr_t dma_addr;
	refcount_t refcnt;
	u32 hw_seq;
	u32 sw_seq;
	__be64 sw_rcd_sn_be;

	union {
		struct mlx5_wqe_tls_progress_params_seg progress;
		u8 pad[PROGRESS_PARAMS_PADDED_SIZE];
	} ____cacheline_aligned_in_smp;
};

enum {
	MLX5E_PRIV_RX_FLAG_DELETING,
	MLX5E_NUM_PRIV_RX_FLAGS,
};

struct mlx5e_ktls_offload_context_rx {
	struct tls12_crypto_info_aes_gcm_128 crypto_info;
	struct accel_rule rule;
	struct tls_offload_context_rx *rx_ctx;
	struct completion add_ctx;
	u32 tirn;
	u32 key_id;
	u32 rxq;
	DECLARE_BITMAP(flags, MLX5E_NUM_PRIV_RX_FLAGS);

	/* resync */
	struct mlx5e_ktls_rx_resync_ctx resync;
};

static int mlx5e_ktls_create_tir(struct mlx5_core_dev *mdev, u32 *tirn, u32 rqtn)
{
	int err, inlen;
	void *tirc;
	u32 *in;

	inlen = MLX5_ST_SZ_BYTES(create_tir_in);
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);

	MLX5_SET(tirc, tirc, transport_domain, mdev->mlx5e_res.td.tdn);
	MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_INDIRECT);
	MLX5_SET(tirc, tirc, rx_hash_fn, MLX5_RX_HASH_FN_INVERTED_XOR8);
	MLX5_SET(tirc, tirc, indirect_table, rqtn);
	MLX5_SET(tirc, tirc, tls_en, 1);
	MLX5_SET(tirc, tirc, self_lb_block,
		 MLX5_TIRC_SELF_LB_BLOCK_BLOCK_UNICAST |
		 MLX5_TIRC_SELF_LB_BLOCK_BLOCK_MULTICAST);

	err = mlx5_core_create_tir(mdev, in, tirn);

	kvfree(in);
	return err;
}

static void accel_rule_handle_work(struct work_struct *work)
{
	struct mlx5e_ktls_offload_context_rx *priv_rx;
	struct accel_rule *accel_rule;
	struct mlx5_flow_handle *rule;

	accel_rule = container_of(work, struct accel_rule, work);
	priv_rx = container_of(accel_rule, struct mlx5e_ktls_offload_context_rx, rule);
	if (unlikely(test_bit(MLX5E_PRIV_RX_FLAG_DELETING, priv_rx->flags)))
		goto out;

	rule = mlx5e_accel_fs_add_sk(accel_rule->priv, accel_rule->sk,
				     priv_rx->tirn, MLX5_FS_DEFAULT_FLOW_TAG);
	if (!IS_ERR_OR_NULL(rule))
		accel_rule->rule = rule;
out:
	complete(&priv_rx->add_ctx);
}

static void accel_rule_init(struct accel_rule *rule, struct mlx5e_priv *priv,
			    struct sock *sk)
{
	INIT_WORK(&rule->work, accel_rule_handle_work);
	rule->priv = priv;
	rule->sk = sk;
}

static void icosq_fill_wi(struct mlx5e_icosq *sq,
			  u16 pi, u8 wqe_type, u8 num_wqebbs,
			  struct mlx5e_ktls_offload_context_rx *priv_rx)
{
	struct mlx5e_icosq_wqe_info *wi = &sq->db.wqe_info[pi];

	*wi = (struct mlx5e_icosq_wqe_info) {
		.wqe_type      = wqe_type,
		.num_wqebbs    = num_wqebbs,
		.accel.priv_rx = priv_rx,
	};
}

static struct mlx5_wqe_ctrl_seg *
post_static_params(struct mlx5e_icosq *sq,
		   struct mlx5e_ktls_offload_context_rx *priv_rx)
{
	struct mlx5e_set_tls_static_params_wqe *wqe;
	u16 pi, num_wqebbs, room;

	num_wqebbs = MLX5E_TLS_SET_STATIC_PARAMS_WQEBBS;
	room = mlx5e_stop_room_for_wqe(num_wqebbs);
	if (unlikely(!mlx5e_wqc_has_room_for(&sq->wq, sq->cc, sq->pc, room)))
		return ERR_PTR(-ENOSPC);

	pi = mlx5e_icosq_get_next_pi(sq, num_wqebbs);
	wqe = MLX5E_TLS_FETCH_SET_STATIC_PARAMS_WQE(sq, pi);
	mlx5e_ktls_build_static_params(wqe, sq->pc, sq->sqn, &priv_rx->crypto_info,
				       priv_rx->tirn, priv_rx->key_id,
				       priv_rx->resync.hw_seq, false,
				       TLS_OFFLOAD_CTX_DIR_RX);
	icosq_fill_wi(sq, pi, MLX5E_ICOSQ_WQE_UMR_TLS, num_wqebbs, priv_rx);
	sq->pc += num_wqebbs;

	return &wqe->ctrl;
}

static struct mlx5_wqe_ctrl_seg *
post_progress_params(struct mlx5e_icosq *sq,
		     struct mlx5e_ktls_offload_context_rx *priv_rx,
		     u32 next_record_tcp_sn)
{
	struct mlx5e_set_tls_progress_params_wqe *wqe;
	u16 pi, num_wqebbs, room;

	num_wqebbs = MLX5E_TLS_SET_PROGRESS_PARAMS_WQEBBS;
	room = mlx5e_stop_room_for_wqe(num_wqebbs);
	if (unlikely(!mlx5e_wqc_has_room_for(&sq->wq, sq->cc, sq->pc, room)))
		return ERR_PTR(-ENOSPC);

	pi = mlx5e_icosq_get_next_pi(sq, num_wqebbs);
	wqe = MLX5E_TLS_FETCH_SET_PROGRESS_PARAMS_WQE(sq, pi);
	mlx5e_ktls_build_progress_params(wqe, sq->pc, sq->sqn, priv_rx->tirn, false,
					 next_record_tcp_sn,
					 TLS_OFFLOAD_CTX_DIR_RX);
	icosq_fill_wi(sq, pi, MLX5E_ICOSQ_WQE_SET_PSV_TLS, num_wqebbs, priv_rx);
	sq->pc += num_wqebbs;

	return &wqe->ctrl;
}

static int post_rx_param_wqes(struct mlx5e_channel *c,
			      struct mlx5e_ktls_offload_context_rx *priv_rx,
			      u32 next_record_tcp_sn)
{
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5e_icosq *sq;
	int err;

	err = 0;
	sq = &c->async_icosq;
	spin_lock(&c->async_icosq_lock);

	cseg = post_static_params(sq, priv_rx);
	if (IS_ERR(cseg)) {
		err = PTR_ERR(cseg);
		complete(&priv_rx->add_ctx);
		goto unlock;
	}
	cseg = post_progress_params(sq, priv_rx, next_record_tcp_sn);
	if (IS_ERR(cseg)) {
		err = PTR_ERR(cseg);
		complete(&priv_rx->add_ctx);
		goto unlock;
	}

	mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, cseg);
unlock:
	spin_unlock(&c->async_icosq_lock);

	return err;
}

static void
mlx5e_set_ktls_rx_priv_ctx(struct tls_context *tls_ctx,
			   struct mlx5e_ktls_offload_context_rx *priv_rx)
{
	struct mlx5e_ktls_offload_context_rx **ctx =
		__tls_driver_ctx(tls_ctx, TLS_OFFLOAD_CTX_DIR_RX);

	BUILD_BUG_ON(sizeof(struct mlx5e_ktls_offload_context_rx *) >
		     TLS_OFFLOAD_CONTEXT_SIZE_RX);

	*ctx = priv_rx;
}

static struct mlx5e_ktls_offload_context_rx *
mlx5e_get_ktls_rx_priv_ctx(struct tls_context *tls_ctx)
{
	struct mlx5e_ktls_offload_context_rx **ctx =
		__tls_driver_ctx(tls_ctx, TLS_OFFLOAD_CTX_DIR_RX);

	return *ctx;
}

/* Re-sync */
static struct mlx5_wqe_ctrl_seg *
resync_post_get_progress_params(struct mlx5e_icosq *sq,
				struct mlx5e_ktls_offload_context_rx *priv_rx)
{
	struct mlx5e_ktls_rx_resync_ctx *resync = &priv_rx->resync;
	struct mlx5e_get_tls_progress_params_wqe *wqe;
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5_seg_get_psv *psv;
	u16 pi;

	dma_sync_single_for_device(resync->priv->mdev->device,
				   resync->dma_addr,
				   PROGRESS_PARAMS_PADDED_SIZE,
				   DMA_FROM_DEVICE);
	BUILD_BUG_ON(MLX5E_KTLS_GET_PROGRESS_WQEBBS != 1);
	if (unlikely(!mlx5e_wqc_has_room_for(&sq->wq, sq->cc, sq->pc, 1)))
		return ERR_PTR(-ENOSPC);

	pi = mlx5e_icosq_get_next_pi(sq, 1);
	wqe = MLX5E_TLS_FETCH_GET_PROGRESS_PARAMS_WQE(sq, pi);

#define GET_PSV_DS_CNT (DIV_ROUND_UP(sizeof(*wqe), MLX5_SEND_WQE_DS))

	cseg = &wqe->ctrl;
	cseg->opmod_idx_opcode =
		cpu_to_be32((sq->pc << 8) | MLX5_OPCODE_GET_PSV |
			    (MLX5_OPC_MOD_TLS_TIR_PROGRESS_PARAMS << 24));
	cseg->qpn_ds =
		cpu_to_be32((sq->sqn << MLX5_WQE_CTRL_QPN_SHIFT) | GET_PSV_DS_CNT);

	psv = &wqe->psv;
	psv->num_psv      = 1 << 4;
	psv->l_key        = sq->channel->mkey_be;
	psv->psv_index[0] = cpu_to_be32(priv_rx->tirn);
	psv->va           = cpu_to_be64(priv_rx->resync.dma_addr);

	icosq_fill_wi(sq, pi, MLX5E_ICOSQ_WQE_GET_PSV_TLS, 1, priv_rx);
	sq->pc++;

	return cseg;
}

/* Function is called with elevated refcount.
 * It decreases it only if no WQE is posted.
 */
static void resync_handle_work(struct work_struct *work)
{
	struct mlx5e_ktls_offload_context_rx *priv_rx;
	struct mlx5e_ktls_rx_resync_ctx *resync;
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5e_channel *c;
	struct mlx5e_icosq *sq;
	struct mlx5_wq_cyc *wq;

	resync = container_of(work, struct mlx5e_ktls_rx_resync_ctx, work);
	priv_rx = container_of(resync, struct mlx5e_ktls_offload_context_rx, resync);

	if (unlikely(test_bit(MLX5E_PRIV_RX_FLAG_DELETING, priv_rx->flags))) {
		refcount_dec(&resync->refcnt);
		return;
	}

	c = resync->priv->channels.c[priv_rx->rxq];
	sq = &c->async_icosq;
	wq = &sq->wq;

	spin_lock(&c->async_icosq_lock);

	cseg = resync_post_get_progress_params(sq, priv_rx);
	if (IS_ERR(cseg)) {
		refcount_dec(&resync->refcnt);
		goto unlock;
	}
	mlx5e_notify_hw(wq, sq->pc, sq->uar_map, cseg);
unlock:
	spin_unlock(&c->async_icosq_lock);
}

static void resync_init(struct mlx5e_ktls_rx_resync_ctx *resync, struct mlx5e_priv *priv)
{
	INIT_WORK(&resync->work, resync_handle_work);
	resync->priv = priv;
	refcount_set(&resync->refcnt, 1);
}

/* Function can be called with the refcount being either elevated or not.
 * It does not affect the refcount.
 */
static int resync_handle_seq_match(struct mlx5e_ktls_offload_context_rx *priv_rx,
				   struct mlx5e_channel *c)
{
	struct tls12_crypto_info_aes_gcm_128 *info = &priv_rx->crypto_info;
	u8 tracker_state, auth_state, *ctx;
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5e_icosq *sq;
	int err;

	ctx = priv_rx->resync.progress.ctx;
	tracker_state = MLX5_GET(tls_progress_params, ctx, record_tracker_state);
	auth_state = MLX5_GET(tls_progress_params, ctx, auth_state);

	if (tracker_state != MLX5E_TLS_PROGRESS_PARAMS_RECORD_TRACKER_STATE_TRACKING ||
	    auth_state != MLX5E_TLS_PROGRESS_PARAMS_AUTH_STATE_NO_OFFLOAD)
		return 0;

	memcpy(info->rec_seq, &priv_rx->resync.sw_rcd_sn_be, sizeof(info->rec_seq));
	err = 0;

	sq = &c->async_icosq;
	spin_lock(&c->async_icosq_lock);

	cseg = post_static_params(sq, priv_rx);
	if (IS_ERR(cseg)) {
		err = PTR_ERR(cseg);
		goto unlock;
	}
	/* Do not increment priv_rx refcnt, CQE handling is empty */
	mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, cseg);
unlock:
	spin_unlock(&c->async_icosq_lock);

	return err;
}

/* Function is called with elevated refcount, it decreases it. */
void mlx5e_ktls_handle_get_psv_completion(struct mlx5e_icosq_wqe_info *wi,
					  struct mlx5e_icosq *sq)
{
	struct mlx5e_ktls_offload_context_rx *priv_rx = wi->accel.priv_rx;
	struct mlx5e_ktls_rx_resync_ctx *resync = &priv_rx->resync;

	if (unlikely(test_bit(MLX5E_PRIV_RX_FLAG_DELETING, priv_rx->flags)))
		goto out;

	dma_sync_single_for_cpu(resync->priv->mdev->device,
				resync->dma_addr,
				PROGRESS_PARAMS_PADDED_SIZE,
				DMA_FROM_DEVICE);

	resync->hw_seq = MLX5_GET(tls_progress_params, resync->progress.ctx, hw_resync_tcp_sn);
	if (resync->hw_seq == resync->sw_seq) {
		struct mlx5e_channel *c =
			container_of(sq, struct mlx5e_channel, async_icosq);

		resync_handle_seq_match(priv_rx, c);
	}
out:
	refcount_dec(&resync->refcnt);
}

/* Runs in NAPI.
 * Function elevates the refcount, unless no work is queued.
 */
static bool resync_queue_get_psv(struct sock *sk)
{
	struct mlx5e_ktls_offload_context_rx *priv_rx;
	struct mlx5e_ktls_rx_resync_ctx *resync;

	priv_rx = mlx5e_get_ktls_rx_priv_ctx(tls_get_ctx(sk));
	if (unlikely(!priv_rx))
		return false;

	if (unlikely(test_bit(MLX5E_PRIV_RX_FLAG_DELETING, priv_rx->flags)))
		return false;

	resync = &priv_rx->resync;
	refcount_inc(&resync->refcnt);
	if (unlikely(!queue_work(resync->priv->tls->rx_wq, &resync->work))) {
		refcount_dec(&resync->refcnt);
		return false;
	}

	return true;
}

/* Runs in NAPI */
static void resync_update_sn(struct net_device *netdev, struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *)(skb->data);
	struct sock *sk = NULL;
	int network_depth = 0;
	struct iphdr *iph;
	struct tcphdr *th;

	__vlan_get_protocol(skb, eth->h_proto, &network_depth);
	iph = (struct iphdr *)(skb->data + network_depth);

	if (iph->version == 4) {
		th = (void *)iph + sizeof(struct iphdr);

		sk = inet_lookup_established(dev_net(netdev), &tcp_hashinfo,
					     iph->saddr, th->source, iph->daddr,
					     th->dest, netdev->ifindex);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		struct ipv6hdr *ipv6h = (struct ipv6hdr *)iph;

		th = (void *)ipv6h + sizeof(struct ipv6hdr);

		sk = __inet6_lookup_established(dev_net(netdev), &tcp_hashinfo,
						&ipv6h->saddr, th->source,
						&ipv6h->daddr, ntohs(th->dest),
						netdev->ifindex, 0);
#endif
	}

	if (unlikely(!sk || sk->sk_state == TCP_TIME_WAIT))
		return;

	if (unlikely(!resync_queue_get_psv(sk)))
		return;

	skb->sk = sk;
	skb->destructor = sock_edemux;

	tls_offload_rx_force_resync_request(sk);
}

int mlx5e_ktls_rx_resync(struct net_device *netdev, struct sock *sk,
			 u32 seq, u8 *rcd_sn)
{
	struct mlx5e_ktls_offload_context_rx *priv_rx;
	struct mlx5e_ktls_rx_resync_ctx *resync;

	priv_rx = mlx5e_get_ktls_rx_priv_ctx(tls_get_ctx(sk));
	if (unlikely(!priv_rx))
		return 0;

	resync = &priv_rx->resync;
	resync->sw_rcd_sn_be = *(__be64 *)rcd_sn;
	resync->sw_seq = seq - (TLS_HEADER_SIZE - 1);

	if (resync->hw_seq == resync->sw_seq) {
		struct mlx5e_priv *priv;
		struct mlx5e_channel *c;

		priv = netdev_priv(netdev);
		c = priv->channels.c[priv_rx->rxq];

		if (!resync_handle_seq_match(priv_rx, c))
			return 0;
	}

	tls_offload_rx_force_resync_request(sk);

	return 0;
}

/* End of resync section */

void mlx5e_ktls_handle_rx_skb(struct mlx5e_rq *rq, struct sk_buff *skb,
			      struct mlx5_cqe64 *cqe, u32 *cqe_bcnt)
{
	switch (get_cqe_tls_offload(cqe)) {
	case CQE_TLS_OFFLOAD_DECRYPTED:
		skb->decrypted = 1;
		rq->stats->tls_decrypted_packets++;
		rq->stats->tls_decrypted_bytes += *cqe_bcnt;
		break;
	case CQE_TLS_OFFLOAD_RESYNC:
		resync_update_sn(rq->netdev, skb);
		rq->stats->tls_ooo++;
		break;
	default: /* CQE_TLS_OFFLOAD_ERROR: */
		rq->stats->tls_err++;
		break;
	}
}

void mlx5e_ktls_handle_ctx_completion(struct mlx5e_icosq_wqe_info *wi)
{
	struct mlx5e_ktls_offload_context_rx *priv_rx = wi->accel.priv_rx;
	struct accel_rule *rule = &priv_rx->rule;

	if (unlikely(test_bit(MLX5E_PRIV_RX_FLAG_DELETING, priv_rx->flags))) {
		complete(&priv_rx->add_ctx);
		return;
	}
	queue_work(rule->priv->tls->rx_wq, &rule->work);
}

int mlx5e_ktls_add_rx(struct net_device *netdev, struct sock *sk,
		      struct tls_crypto_info *crypto_info,
		      u32 start_offload_tcp_sn)
{
	struct mlx5e_ktls_offload_context_rx *priv_rx;
	struct mlx5e_ktls_rx_resync_ctx *resync;
	struct tls_context *tls_ctx;
	struct mlx5_core_dev *mdev;
	struct mlx5e_priv *priv;
	struct device *pdev;
	int rxq, err;
	u32 rqtn;

	tls_ctx = tls_get_ctx(sk);
	priv = netdev_priv(netdev);
	mdev = priv->mdev;
	pdev = mdev->device;
	priv_rx = kzalloc(sizeof(*priv_rx), GFP_KERNEL);
	if (unlikely(!priv_rx))
		return -ENOMEM;

	err = mlx5_ktls_create_key(mdev, crypto_info, &priv_rx->key_id);
	if (err)
		goto err_create_key;

	priv_rx->crypto_info  =
		*(struct tls12_crypto_info_aes_gcm_128 *)crypto_info;
	priv_rx->rx_ctx = tls_offload_ctx_rx(tls_ctx);
	priv_rx->rxq = mlx5e_accel_sk_get_rxq(sk);

	mlx5e_set_ktls_rx_priv_ctx(tls_ctx, priv_rx);

	rxq = priv_rx->rxq;
	rqtn = priv->direct_tir[rxq].rqt.rqtn;

	err = mlx5e_ktls_create_tir(mdev, &priv_rx->tirn, rqtn);
	if (err)
		goto err_create_tir;

	init_completion(&priv_rx->add_ctx);
	resync = &priv_rx->resync;
	resync->dma_addr = dma_map_single(pdev, &resync->progress,
					  PROGRESS_PARAMS_PADDED_SIZE, DMA_FROM_DEVICE);
	if (unlikely(dma_mapping_error(pdev, resync->dma_addr)))
		goto err_map_resync;

	accel_rule_init(&priv_rx->rule, priv, sk);
	resync_init(resync, priv);
	err = post_rx_param_wqes(priv->channels.c[rxq], priv_rx, start_offload_tcp_sn);
	if (err)
		goto err_post_wqes;

	KTLS_STATS_INC(priv, rxq, tls_ctx);

	return 0;

err_post_wqes:
	dma_unmap_single(pdev, resync->dma_addr,
			 PROGRESS_PARAMS_PADDED_SIZE, DMA_FROM_DEVICE);
err_map_resync:
	mlx5_core_destroy_tir(mdev, priv_rx->tirn);
err_create_tir:
	mlx5_ktls_destroy_key(mdev, priv_rx->key_id);
err_create_key:
	kfree(priv_rx);
	return err;
}

/* Elevated refcount on the resync object means there are
 * outstanding operations (uncompleted GET_PSV WQEs) that
 * will read the resync / priv_rx objects once completed.
 * Wait for them to avoid use-after-free.
 */
static void wait_for_resync(struct net_device *netdev,
			    struct mlx5e_ktls_rx_resync_ctx *resync)
{
#define MLX5E_KTLS_RX_RESYNC_TIMEOUT 20000 /* msecs */
	unsigned long exp_time = jiffies + msecs_to_jiffies(MLX5E_KTLS_RX_RESYNC_TIMEOUT);
	unsigned int refcnt;

	do {
		refcnt = refcount_read(&resync->refcnt);
		if (refcnt == 1)
			return;

		msleep(20);
	} while (time_before(jiffies, exp_time));

	netdev_warn(netdev,
		    "Failed waiting for kTLS RX resync refcnt to be released (%u).\n",
		    refcnt);
}

void mlx5e_ktls_del_rx(struct net_device *netdev, struct tls_context *tls_ctx)
{
	struct mlx5e_ktls_offload_context_rx *priv_rx;
	struct mlx5e_ktls_rx_resync_ctx *resync;
	struct mlx5_core_dev *mdev;
	struct mlx5e_priv *priv;
	struct device *pdev;

	priv = netdev_priv(netdev);
	mdev = priv->mdev;
	pdev = mdev->device;

	priv_rx = mlx5e_get_ktls_rx_priv_ctx(tls_ctx);
	set_bit(MLX5E_PRIV_RX_FLAG_DELETING, priv_rx->flags);
	mlx5e_set_ktls_rx_priv_ctx(tls_ctx, NULL);
	napi_synchronize(&priv->channels.c[priv_rx->rxq]->napi);
	if (!cancel_work_sync(&priv_rx->rule.work))
		/* completion is needed, as the priv_rx in the add flow
		 * is maintained on the wqe info (wi), not on the socket.
		 */
		wait_for_completion(&priv_rx->add_ctx);
	resync = &priv_rx->resync;
	if (cancel_work_sync(&resync->work))
		refcount_dec(&resync->refcnt);
	wait_for_resync(netdev, resync);

	KTLS_STATS_INC(priv, priv_rx->rxq, tls_del);
	if (priv_rx->rule.rule)
		mlx5e_accel_fs_del_sk(priv_rx->rule.rule);

	dma_unmap_single(pdev, resync->dma_addr, PROGRESS_PARAMS_PADDED_SIZE,
			 DMA_FROM_DEVICE);
	mlx5_core_destroy_tir(mdev, priv_rx->tirn);
	mlx5_ktls_destroy_key(mdev, priv_rx->key_id);
	kfree(priv_rx);
}
