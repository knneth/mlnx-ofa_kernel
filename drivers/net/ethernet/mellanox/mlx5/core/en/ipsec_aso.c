// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// // Copyright (c) 2021 Mellanox Technologies.

#include "lib/aso.h"
#include "en/ipsec_aso.h"

#define MLX5_IPSEC_ASO_DS_CNT (DIV_ROUND_UP(sizeof(struct mlx5_aso_wqe), MLX5_SEND_WQE_DS))
#define IPSEC_UPPER32_MASK GENMASK_ULL(63, 32)

enum {
	MLX5E_IPSEC_ASO_REMOVE_FLOW_PKT_CNT_OFFSET,
	MLX5E_IPSEC_ASO_REMOVE_FLOW_SOFT_LFT_OFFSET,
};

struct ipsec_umr {
	dma_addr_t dma_addr;
	u8 ctx[MLX5_ST_SZ_BYTES(ipsec_aso)];
	u32 mkey;
};

struct mlx5e_ipsec_aso {
	struct mlx5_core_dev *mdev;
	/* ASO */
	struct mlx5_aso *maso;
	/* Protects ipsec ASO */
	struct mutex aso_lock;
	/* UMR */
	struct ipsec_umr *umr;

	u32 pdn;
};

struct ipsec_aso_ctrl_param {
	u8   data_mask_mode;
	u8   condition_0_operand;
	u8   condition_1_operand;
	u8   condition_0_offset;
	u8   condition_1_offset;
	u8   data_offset;
	u8   condition_operand;
	u32  condition_0_data;
	u32  condition_0_mask;
	u32  condition_1_data;
	u32  condition_1_mask;
	u64  bitwise_data;
	u64  data_mask;
};

static void ipsec_aso_build_wqe_ctrl_seg(struct mlx5e_ipsec_aso *ipsec_aso,
                                         struct mlx5_wqe_aso_ctrl_seg *aso_ctrl,
                                         struct ipsec_aso_ctrl_param *params)
{
	struct ipsec_umr *umr = ipsec_aso->umr;
        memset(aso_ctrl, 0, sizeof(*aso_ctrl));
        if (umr->dma_addr) {
                aso_ctrl->va_l  = cpu_to_be32(umr->dma_addr | ASO_CTRL_READ_EN);
                aso_ctrl->va_h  = cpu_to_be32((u64)umr->dma_addr >> 32);
                aso_ctrl->l_key = cpu_to_be32(umr->mkey);
        }

        if (!params)
                return;

        aso_ctrl->data_mask_mode = params->data_mask_mode << 6;
        aso_ctrl->condition_1_0_operand = params->condition_1_operand |
                                                params->condition_0_operand << 4;
        aso_ctrl->condition_1_0_offset = params->condition_1_offset |
                                                params->condition_0_offset << 4;
        aso_ctrl->data_offset_condition_operand = params->data_offset |
                                                params->condition_operand << 6;
        aso_ctrl->condition_0_data = cpu_to_be32(params->condition_0_data);
        aso_ctrl->condition_0_mask = cpu_to_be32(params->condition_0_mask);
        aso_ctrl->condition_1_data = cpu_to_be32(params->condition_1_data);
        aso_ctrl->condition_1_mask = cpu_to_be32(params->condition_1_mask);
        aso_ctrl->bitwise_data = cpu_to_be64(params->bitwise_data);
        aso_ctrl->data_mask = cpu_to_be64(params->data_mask);
}

static int ipsec_aso_reg_mr(struct mlx5_core_dev *mdev, struct mlx5e_ipsec_aso *aso)
{
	struct ipsec_umr *umr;
	struct device *dma_device;
	dma_addr_t dma_addr;
	int err;

	umr = kzalloc(sizeof(*umr), GFP_KERNEL);
	if (!umr) {
		err = -ENOMEM;
		return err;
	}

	dma_device = &mdev->pdev->dev;
	dma_addr = dma_map_single(dma_device, umr->ctx, sizeof(umr->ctx), DMA_BIDIRECTIONAL);
	err = dma_mapping_error(dma_device, dma_addr);
	if (err) {
		mlx5_core_err(mdev, "Can't map dma device, err=%d\n", err);
		goto out_dma;
	}

	err = mlx5e_create_mkey(mdev, aso->pdn, &umr->mkey);
	if (err) {
		mlx5_core_err(mdev, "Can't create mkey, err=%d\n", err);
		goto out_mkey;
	}

	umr->dma_addr = dma_addr;

	aso->umr = umr;

	return 0;

out_mkey:
	dma_unmap_single(dma_device, dma_addr, sizeof(umr->ctx), DMA_BIDIRECTIONAL);
out_dma:
	kfree(umr);
	return err;
}

static void ipsec_aso_dereg_mr(struct mlx5_core_dev *mdev, struct mlx5e_ipsec_aso *aso)
{
	struct ipsec_umr *umr = aso->umr;

	mlx5_core_destroy_mkey(mdev, umr->mkey);
	dma_unmap_single(&mdev->pdev->dev, umr->dma_addr, sizeof(umr->ctx), DMA_BIDIRECTIONAL);
	kfree(umr);
}

static int ipsec_aso_post_wqe(struct mlx5e_ipsec_aso *aso,
			      struct mlx5e_ipsec_aso_in *in,
			      struct ipsec_aso_ctrl_param *params,
			      struct mlx5e_ipsec_aso_out *out)
{
	struct mlx5_aso_wqe *aso_wqe;
	struct mlx5_core_dev *mdev;
	struct mlx5_aso *maso;
	struct ipsec_umr *umr;
	u8 *event_arm;
	int err;

	mutex_lock(&aso->aso_lock);
	maso = aso->maso;
	mdev = aso->mdev;
	aso_wqe = mlx5_aso_get_wqe(maso);
	mlx5_aso_build_wqe(maso, MLX5_IPSEC_ASO_DS_CNT, aso_wqe, in->obj_id,
			   MLX5_ACCESS_ASO_OPC_MOD_IPSEC);
	ipsec_aso_build_wqe_ctrl_seg(aso, &aso_wqe->aso_ctrl, params);

	mlx5_aso_post_wqe(maso, false, &aso_wqe->ctrl);
	err = mlx5_aso_poll_cq(maso, false, 10);
	if (err)
		goto err_out;

	umr = aso->umr;
	out->hard_cnt = MLX5_GET(ipsec_aso, umr->ctx, remove_flow_pkt_cnt);
	out->soft_cnt = MLX5_GET(ipsec_aso, umr->ctx, remove_flow_soft_lft);

	event_arm = &out->event_arm;
	if (MLX5_GET(ipsec_aso, umr->ctx, esn_event_arm))
		*event_arm |= MLX5E_IPSEC_ASO_ESN_ARM;
	if (MLX5_GET(ipsec_aso, umr->ctx, soft_lft_arm))
		*event_arm |= MLX5E_IPSEC_ASO_SOFT_ARM;
	if (MLX5_GET(ipsec_aso, umr->ctx, hard_lft_arm))
		*event_arm |= MLX5E_IPSEC_ASO_HARD_ARM;
	if (MLX5_GET(ipsec_aso, umr->ctx, remove_flow_enable))
		*event_arm |= MLX5E_IPSEC_ASO_REMOVE_FLOW_ENABLE;

	out->mode_param = MLX5_GET(ipsec_aso, umr->ctx, mode_parameter);

err_out:
	mutex_unlock(&aso->aso_lock);
	return err;
}

int mlx5e_ipsec_aso_set(struct mlx5e_ipsec_aso *aso, struct mlx5e_ipsec_aso_in *in,
			struct mlx5e_ipsec_aso_out *out)
{
	struct ipsec_aso_ctrl_param params = {};
	int err = 0;
	u8 flags;

	if (!in || !in->flags)
		return -EINVAL;

	flags = in->flags;
	params.data_mask_mode = MLX5_ASO_DATA_MASK_MODE_BITWISE_64BIT;
	params.condition_0_operand = MLX5_ASO_ALWAYS_TRUE;
	params.condition_1_operand = MLX5_ASO_ALWAYS_TRUE;

	if (flags & MLX5E_IPSEC_FLAG_ARM_ESN_EVENT) {
		params.data_offset = MLX5E_IPSEC_ASO_REMOVE_FLOW_PKT_CNT_OFFSET;
		params.bitwise_data = BIT(22) << 32;
		params.data_mask = params.bitwise_data;
		return ipsec_aso_post_wqe(aso, in, &params, out);
	}

	if (flags & MLX5E_IPSEC_FLAG_SET_SOFT) {
		params.data_offset = MLX5E_IPSEC_ASO_REMOVE_FLOW_SOFT_LFT_OFFSET;
		params.bitwise_data = (u64)(in->comparator) << 32;
		params.data_mask = IPSEC_UPPER32_MASK;
		err = ipsec_aso_post_wqe(aso, in, &params, out);
		if (flags == MLX5E_IPSEC_FLAG_SET_SOFT)
			return err;
	}

	/* For ASO_WQE big Endian format,
	 * ARM_SOFT is BIT(25 + 32)
	 * SET COUNTER BIT 31 is BIT(31)
	 */
	params.data_offset = MLX5E_IPSEC_ASO_REMOVE_FLOW_PKT_CNT_OFFSET;

	if (flags & MLX5E_IPSEC_FLAG_SET_CNT_BIT31)
		params.bitwise_data = IPSEC_SW_LIMIT;
	if (flags & MLX5E_IPSEC_FLAG_ARM_SOFT)
		params.bitwise_data |= BIT(25 + 32);
	if (flags & MLX5E_IPSEC_FLAG_CLEAR_SOFT)
		params.bitwise_data &= ~(BIT(25 + 32));

	params.data_mask = params.bitwise_data;
	return ipsec_aso_post_wqe(aso, in, &params, out);
}

int mlx5e_ipsec_aso_query(struct mlx5e_ipsec_aso *aso, struct mlx5e_ipsec_aso_in *in,
			  struct mlx5e_ipsec_aso_out *out)
{
	return ipsec_aso_post_wqe(aso, in, NULL, out);
}

struct mlx5e_ipsec_aso *mlx5e_ipsec_aso_init(struct mlx5_core_dev *mdev)
{
	struct mlx5e_ipsec_aso *aso;
	struct mlx5_aso *maso;
	int err;

	aso = kzalloc(sizeof(*aso), GFP_KERNEL);
	if (!aso) {
		mlx5_core_err(mdev, "IPsec offload: Failed to alloc IPsec ASO.\n");
		return ERR_PTR(-ENOMEM);
	}

	aso->pdn = mdev->mlx5e_res.hw_objs.pdn;
	maso = mlx5_aso_create(mdev, aso->pdn);
	if (IS_ERR(maso)) {
		err = PTR_ERR(maso);
		goto err_aso;
	}

	err = ipsec_aso_reg_mr(mdev, aso);
	if (err)
		goto err_aso_reg;

	mutex_init(&aso->aso_lock);

	aso->maso = maso;
	aso->mdev = mdev;

	return aso;

err_aso_reg:
	mlx5_aso_destroy(maso);
err_aso:
	kfree(aso);

	return ERR_PTR(err);
}

void mlx5e_ipsec_aso_cleanup(struct mlx5e_ipsec_aso *aso)
{
	struct mlx5_core_dev *mdev;

	if (!aso)
		return;

	mdev = aso->mdev;
	ipsec_aso_dereg_mr(mdev, aso);
	mlx5_aso_destroy(aso->maso);
	kfree(aso);
}
