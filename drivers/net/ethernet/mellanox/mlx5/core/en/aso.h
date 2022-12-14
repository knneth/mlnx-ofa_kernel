/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_EN_ASO_H__
#define __MLX5_EN_ASO_H__

#include "txrx.h"
#include "params.h"

#define MLX5E_ASO_WQEBBS \
	(DIV_ROUND_UP(sizeof(struct mlx5e_aso_wqe), MLX5_SEND_WQE_BB))
#define MLX5E_ASO_WQEBBS_DATA \
	(DIV_ROUND_UP(sizeof(struct mlx5e_aso_wqe_data), MLX5_SEND_WQE_BB))
#define ASO_CTRL_READ_EN BIT(0)

enum {
	MLX5_ASO_SOFT_ARM = BIT(0),
	MLX5_ASO_HARD_ARM = BIT(1),
	MLX5_ASO_REMOVE_FLOW_ENABLE = BIT(2),
	MLX5_ASO_ESN_ARM = BIT(3),
};

struct mlx5e_aso_wqe {
	struct mlx5_wqe_ctrl_seg      ctrl;
	struct mlx5_wqe_aso_ctrl_seg  aso_ctrl;
};

struct mlx5e_aso_wqe_data {
	struct mlx5_wqe_ctrl_seg      ctrl;
	struct mlx5_wqe_aso_ctrl_seg  aso_ctrl;
	struct mlx5_wqe_aso_data_seg  aso_data;
};

struct mlx5e_aso_wqe_info {
	u8   opcode;
	bool with_data;
};

struct mlx5e_asosq {
	/* data path */
	u16                        cc;
	u16                        pc;

	struct mlx5_wqe_ctrl_seg  *doorbell_cseg;
	struct mlx5e_cq            cq;

	/* write@xmit, read@completion */
	struct {
		struct mlx5e_aso_wqe_info *aso_wqe;
	} db;

	/* read only */
	struct mlx5_wq_cyc         wq;
	void __iomem              *uar_map;
	u32                        sqn;
	unsigned long              state;

	/* control path */
	struct mlx5_wq_ctrl        wq_ctrl;
} ____cacheline_aligned_in_smp;

struct mlx5e_aso {
	u32 pdn;
	int refcnt;
	int cpu;
	struct mlx5e_priv *priv;
	struct mlx5e_cq_param cq_param;
	struct mlx5e_asosq sq;
	struct mlx5e_sq_param sq_param;
};

enum {
	LOGICAL_AND,
	LOGICAL_OR,
};

enum {
	ALWAYS_FALSE,
	ALWAYS_TRUE,
	EQUAL,
	NOT_EQUAL,
	GREATER_OR_EQUAL,
	LESSER_OR_EQUAL,
	LESSER,
	GREATER,
	CYCLIC_GREATER,
	CYCLIC_LESSER,
};

enum {
	ASO_DATA_MASK_MODE_BITWISE_64BIT,
	ASO_DATA_MASK_MODE_BYTEWISE_64BYTE,
	ASO_DATA_MASK_MODE_CALCULATED_64BYTE,
};

struct mlx5e_aso_ctrl_param {
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

enum {
	ARM_SOFT = BIT(0),
	SET_SOFT = BIT(1),
	SET_CNT_BIT31  = BIT(3),
	CLEAR_SOFT = BIT(4),
	ARM_ESN_EVENT = BIT(5),
};

enum {
	MLX5_ACCESS_ASO_OPC_MOD_IPSEC,
	MLX5_ACCESS_ASO_OPC_MOD_FLOW_METER = 0x2,
};

void mlx5e_build_aso_wqe(struct mlx5e_aso *aso, struct mlx5e_asosq *sq,
			 u8 ds_cnt, struct mlx5_wqe_ctrl_seg *cseg,
			 struct mlx5_wqe_aso_ctrl_seg *aso_ctrl,
			 u32 obj_id, u32 opc_mode,
			 struct mlx5e_aso_ctrl_param *param);
int mlx5e_poll_aso_cq(struct mlx5e_cq *cq);
void mlx5e_fill_asosq_frag_edge(struct mlx5e_asosq *sq,  struct mlx5_wq_cyc *wq,
				u16 pi, u16 nnops);

struct mlx5e_aso *mlx5e_aso_get(struct mlx5e_priv *priv);
void mlx5e_aso_put(struct mlx5e_priv *priv);
#endif
