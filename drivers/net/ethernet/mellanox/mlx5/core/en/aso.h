// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// // Copyright (c) 2020 Mellanox Technologies.

#include "en.h"
#include "en_accel/ipsec.h"
#include "linux/dma-mapping.h"
#include "en/txrx.h"
#include "en/params.h"

#ifndef __MLX5_EN_ASO_H__
#define __MLX5_EN_ASO_H__

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

struct mlx5e_ipsec_aso {
	struct mlx5_core_mkey mkey;
	dma_addr_t dma_addr;
	void *ctx;
	size_t size;
	u32 pdn;
	struct mlx5e_cq_param cq_param;
	int cpu;
	struct mlx5e_asosq sq;
	struct mlx5e_sq_param sq_param;
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

enum {
	MLX5_IPSEC_ASO_REMOVE_FLOW_PKT_CNT_OFFSET,
	MLX5_IPSEC_ASO_REMOVE_FLOW_SOFT_LFT_OFFSET,
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

int mlx5e_ipsec_aso_query(struct mlx5e_priv *priv, u32 obj_id,
			  u32 *hard_cnt, u32 *soft_cnt,
			  u8 *event_arm, u32 *mode_param);
int mlx5e_ipsec_aso_set(struct mlx5e_priv *priv, u32 obj_id, u8 flags,
			u32 comparator, u32 *hard_cnt, u32 *soft_cnt,
			u8 *event_arm, u32 *mode_param);
void mlx5e_aso_setup(struct mlx5e_priv *priv);
void mlx5e_aso_cleanup(struct mlx5e_priv *priv);
#endif
