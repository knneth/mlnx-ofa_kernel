// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// // Copyright (c) 2021 Mellanox Technologies.

#include "aso.h"
#include "ipsec_aso.h"

static int mlx5e_aso_send_ipsec_aso(struct mlx5e_priv *priv, u32 ipsec_obj_id,
				    struct mlx5e_aso_ctrl_param *param,
				    u32 *hard_cnt, u32 *soft_cnt,
				    u8 *event_arm, u32 *mode_param)
{
	struct mlx5e_ipsec_aso *ipsec_aso = priv->ipsec->ipsec_aso;
	struct mlx5e_aso *aso = ipsec_aso->aso;
	struct mlx5e_asosq *sq = &aso->sq;
	struct mlx5_wq_cyc *wq = &sq->wq;
	struct mlx5e_aso_wqe *aso_wqe;
	u16 pi, contig_wqebbs_room;
	int err = 0;

	memset(ipsec_aso->ctx, 0, ipsec_aso->size);

	mutex_lock(&priv->aso_lock);
	pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	contig_wqebbs_room = mlx5_wq_cyc_get_contig_wqebbs(wq, pi);

	if (unlikely(contig_wqebbs_room < MLX5E_ASO_WQEBBS)) {
		mlx5e_fill_asosq_frag_edge(sq, wq, pi, contig_wqebbs_room);
		pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	}

	aso_wqe = mlx5_wq_cyc_get_wqe(wq, pi);

	/* read enable always set */
	mlx5e_build_aso_wqe(aso, sq,
			    DIV_ROUND_UP(sizeof(*aso_wqe), MLX5_SEND_WQE_DS),
			    &aso_wqe->ctrl, &aso_wqe->aso_ctrl, ipsec_obj_id,
			    MLX5_ACCESS_ASO_OPC_MOD_IPSEC, param);

	aso_wqe->aso_ctrl.va_l = cpu_to_be32(ipsec_aso->dma_addr | ASO_CTRL_READ_EN);
	aso_wqe->aso_ctrl.va_h = cpu_to_be32(ipsec_aso->dma_addr >> 32);
	aso_wqe->aso_ctrl.l_key = cpu_to_be32(ipsec_aso->mkey.key);

	sq->db.aso_wqe[pi].opcode = MLX5_OPCODE_ACCESS_ASO;
	sq->db.aso_wqe[pi].with_data = false;
	sq->pc += MLX5E_ASO_WQEBBS;
	sq->doorbell_cseg = &aso_wqe->ctrl;

	mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, sq->doorbell_cseg);

	/* Ensure doorbell is written on uar_page before poll_cq */
	WRITE_ONCE(sq->doorbell_cseg, NULL);

	err = mlx5e_poll_aso_cq(&sq->cq);
	if (err)
		goto out;

	if (hard_cnt)
		*hard_cnt = MLX5_GET(ipsec_aso, ipsec_aso->ctx, remove_flow_pkt_cnt);
	if (soft_cnt)
		*soft_cnt = MLX5_GET(ipsec_aso, ipsec_aso->ctx, remove_flow_soft_lft);

	if (event_arm) {
		*event_arm = 0;
		if (MLX5_GET(ipsec_aso, ipsec_aso->ctx, esn_event_arm))
			*event_arm |= MLX5_ASO_ESN_ARM;
		if (MLX5_GET(ipsec_aso, ipsec_aso->ctx, soft_lft_arm))
			*event_arm |= MLX5_ASO_SOFT_ARM;
		if (MLX5_GET(ipsec_aso, ipsec_aso->ctx, hard_lft_arm))
			*event_arm |= MLX5_ASO_HARD_ARM;
		if (MLX5_GET(ipsec_aso, ipsec_aso->ctx, remove_flow_enable))
			*event_arm |= MLX5_ASO_REMOVE_FLOW_ENABLE;
	}

	if (mode_param)
		*mode_param = MLX5_GET(ipsec_aso, ipsec_aso->ctx, mode_parameter);

out:
	mutex_unlock(&priv->aso_lock);
	return err;
}

#define UPPER32_MASK GENMASK_ULL(63, 32)

int mlx5e_ipsec_aso_query(struct mlx5e_priv *priv, u32 obj_id,
			  u32 *hard_cnt, u32 *soft_cnt,
			  u8 *event_arm, u32 *mode_param)
{
	return mlx5e_aso_send_ipsec_aso(priv, obj_id, NULL, hard_cnt, soft_cnt,
					event_arm, mode_param);
}

int mlx5e_ipsec_aso_set(struct mlx5e_priv *priv, u32 obj_id, u8 flags,
			u32 comparator, u32 *hard_cnt, u32 *soft_cnt,
			u8 *event_arm, u32 *mode_param)
{
	struct mlx5e_aso_ctrl_param param = {};
	int err = 0;

	if (!flags)
		return -EINVAL;

	param.data_mask_mode = ASO_DATA_MASK_MODE_BITWISE_64BIT;
	param.condition_0_operand = ALWAYS_TRUE;
	param.condition_1_operand = ALWAYS_TRUE;

	if (flags & ARM_ESN_EVENT) {
		param.data_offset = MLX5_IPSEC_ASO_REMOVE_FLOW_PKT_CNT_OFFSET;
		param.bitwise_data = BIT(22) << 32;
		param.data_mask = param.bitwise_data;
		return mlx5e_aso_send_ipsec_aso(priv, obj_id, &param, NULL, NULL, NULL, NULL);
	}

	if (flags & SET_SOFT) {
		param.data_offset = MLX5_IPSEC_ASO_REMOVE_FLOW_SOFT_LFT_OFFSET;
		param.bitwise_data = (u64)(comparator) << 32;
		param.data_mask = UPPER32_MASK;
		err = mlx5e_aso_send_ipsec_aso(priv, obj_id, &param, hard_cnt, soft_cnt,
					       NULL, NULL);
		if (flags == SET_SOFT)
			return err;
	}

	/* For ASO_WQE big Endian format,
	 * ARM_SOFT is BIT(25 + 32)
	 * SET COUNTER BIT 31 is BIT(31)
	 */
	param.data_offset = MLX5_IPSEC_ASO_REMOVE_FLOW_PKT_CNT_OFFSET;

	if (flags & SET_CNT_BIT31)
		param.bitwise_data = IPSEC_SW_LIMIT;
	if (flags & ARM_SOFT)
		param.bitwise_data |= BIT(25 + 32);
	if (flags & CLEAR_SOFT)
		param.bitwise_data &= ~(BIT(25 + 32));

	param.data_mask = param.bitwise_data;
	return mlx5e_aso_send_ipsec_aso(priv, obj_id, &param, hard_cnt, soft_cnt, NULL, NULL);
}

int
mlx5e_ipsec_aso_setup(struct mlx5e_priv *priv)
{
	size_t size = MLX5_ST_SZ_BYTES(ipsec_aso);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_ipsec_aso *ipsec_aso;
	struct device *dma_device;
	dma_addr_t dma_addr;
	void *ctx;
	int err;

	ipsec_aso = kzalloc(sizeof(*ipsec_aso), GFP_KERNEL);
	if (!ipsec_aso)
		return -ENOMEM;

	ipsec_aso->aso = mlx5e_aso_get(priv);
	if (!ipsec_aso->aso) {
		err = PTR_ERR(ipsec_aso->aso);
		mlx5_core_warn(priv->mdev, "Failed to get aso wqe for ipsec\n");
		goto err_aso;
	}

	ctx = kzalloc(size, GFP_KERNEL);
	if (!ctx) {
		err = -ENOMEM;
		mlx5_core_warn(mdev, "Can't alloc aso ctx for ipsec\n");
		goto err_ctx;
	}

	dma_device = &mdev->pdev->dev;
	dma_addr = dma_map_single(dma_device, ctx, size, DMA_BIDIRECTIONAL);
	err = dma_mapping_error(dma_device, dma_addr);
	if (err) {
		mlx5_core_warn(mdev, "Can't dma aso for ipsec\n");
		goto err_dma;
	}

	err = mlx5e_create_mkey(mdev, ipsec_aso->aso->pdn, &ipsec_aso->mkey);
	if (err) {
		mlx5_core_warn(mdev, "Can't create mkey for ipsec\n");
		goto err_mkey;
	}

	ipsec_aso->ctx = ctx;
	ipsec_aso->dma_addr = dma_addr;
	ipsec_aso->size = size;
	priv->ipsec->ipsec_aso = ipsec_aso;

	return 0;

err_mkey:
	dma_unmap_single(dma_device, dma_addr, size, DMA_BIDIRECTIONAL);
err_dma:
	kfree(ctx);
err_ctx:
	mlx5e_aso_put(priv);
err_aso:
	kfree(ipsec_aso);
	return err;
}

void
mlx5e_ipsec_aso_cleanup(struct mlx5e_priv *priv)
{
	struct mlx5e_ipsec_aso *ipsec_aso = priv->ipsec->ipsec_aso;

	if (!ipsec_aso)
		return;

	mlx5_core_destroy_mkey(priv->mdev, &ipsec_aso->mkey);
	dma_unmap_single(&priv->mdev->pdev->dev, ipsec_aso->dma_addr,
			 ipsec_aso->size, DMA_BIDIRECTIONAL);
	kfree(ipsec_aso->ctx);
	mlx5e_aso_put(priv);
	kfree(priv->ipsec->ipsec_aso);
	priv->ipsec->ipsec_aso = NULL;
}
