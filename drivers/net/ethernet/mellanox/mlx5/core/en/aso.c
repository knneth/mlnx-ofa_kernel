// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include "aso.h"

void mlx5e_build_aso_wqe(struct mlx5e_aso *aso, struct mlx5e_asosq *sq,
			 u8 ds_cnt, struct mlx5_wqe_ctrl_seg *cseg,
			 struct mlx5_wqe_aso_ctrl_seg *aso_ctrl,
			 u32 obj_id, u32 opc_mode,
			 struct mlx5e_aso_ctrl_param *param)
{
	cseg->opmod_idx_opcode = cpu_to_be32((opc_mode << MLX5_WQE_CTRL_WQE_OPC_MOD_SHIFT) |
					     (sq->pc << MLX5_WQE_CTRL_WQE_INDEX_SHIFT) |
					     MLX5_OPCODE_ACCESS_ASO);
	cseg->qpn_ds     = cpu_to_be32((sq->sqn << MLX5_WQE_CTRL_QPN_SHIFT) | ds_cnt);
	cseg->fm_ce_se   = MLX5_WQE_CTRL_CQ_UPDATE;
	cseg->general_id = cpu_to_be32(obj_id);

	memset(aso_ctrl, 0, sizeof(*aso_ctrl));
	if (param) {
		aso_ctrl->data_mask_mode = param->data_mask_mode << 6;
		aso_ctrl->condition_1_0_operand = param->condition_1_operand |
						  param->condition_0_operand << 4;
		aso_ctrl->condition_1_0_offset = param->condition_1_offset |
						 param->condition_0_offset << 4;
		aso_ctrl->data_offset_condition_operand = param->data_offset |
							  param->condition_operand << 6;
		aso_ctrl->condition_0_data = cpu_to_be32(param->condition_0_data);
		aso_ctrl->condition_0_mask = cpu_to_be32(param->condition_0_mask);
		aso_ctrl->condition_1_data = cpu_to_be32(param->condition_1_data);
		aso_ctrl->condition_1_mask = cpu_to_be32(param->condition_1_mask);
		aso_ctrl->bitwise_data = cpu_to_be64(param->bitwise_data);
		aso_ctrl->data_mask = cpu_to_be64(param->data_mask);
	}
}

int mlx5e_poll_aso_cq(struct mlx5e_cq *cq)
{
	struct mlx5e_asosq *sq = container_of(cq, struct mlx5e_asosq, cq);
	struct mlx5_cqe64 *cqe;
	int i, err;
	u16 sqcc;

	err = 0;

	if (unlikely(!test_bit(MLX5E_SQ_STATE_ENABLED, &sq->state)))
		return -EIO;

	cqe = mlx5_cqwq_get_cqe(&cq->wq);

	if (likely(!cqe)) {
		/* Per Chip Design, if context is not in ICM cache,
		 * it will take 0.5us to read the context.
		 * We measure the total time in FW from doorbell ring
		 * until cqe update is 980us. So put 2us is sufficient.
		 */
		usleep_range(20, 50); /* WA for RM 2323775 */
		cqe = mlx5_cqwq_get_cqe(&cq->wq);
		if (!cqe) {
			mlx5_core_err(cq->mdev, "No ASO completion\n");
			return -EIO;
		}
	}

	/* sq->cc must be updated only after mlx5_cqwq_update_db_record(),
	 * otherwise a cq overrun may occur
	 */
	sqcc = sq->cc;

	i = 0;
	do {
		u16 wqe_counter;
		bool last_wqe;

		mlx5_cqwq_pop(&cq->wq);

		wqe_counter = be16_to_cpu(cqe->wqe_counter);

		do {
			struct mlx5e_aso_wqe_info *wi;
			u16 ci;

			last_wqe = (sqcc == wqe_counter);

			ci = mlx5_wq_cyc_ctr2ix(&sq->wq, sqcc);
			wi = &sq->db.aso_wqe[ci];

			if (last_wqe && unlikely(get_cqe_opcode(cqe) != MLX5_CQE_REQ)) {
				struct mlx5_err_cqe *err_cqe;

				mlx5_core_err(cq->mdev, "Bad OP in ASOSQ CQE: 0x%x\n",
					      get_cqe_opcode(cqe));

				err_cqe = (struct mlx5_err_cqe *)cqe;
				mlx5_core_err(cq->mdev, "vendor_err_synd=%x\n",
					      err_cqe->vendor_err_synd);
				mlx5_core_err(cq->mdev, "syndrome=%x\n",
					      err_cqe->syndrome);
				print_hex_dump(KERN_WARNING, "", DUMP_PREFIX_OFFSET,
					       16, 1, err_cqe,
					       sizeof(*err_cqe), false);
				err = -EIO;
				break;
			}

			if (likely(wi->opcode == MLX5_OPCODE_NOP)) {
				sqcc++;
			} else if (likely(wi->opcode == MLX5_OPCODE_ACCESS_ASO)) {
				if (wi->with_data)
					sqcc += MLX5E_ASO_WQEBBS_DATA;
				else
					sqcc += MLX5E_ASO_WQEBBS;
			} else {
				mlx5_core_err(cq->mdev,
					      "Bad OPCODE in ASOSQ WQE info: 0x%x\n",
					      wi->opcode);
				err = -EIO;
				break;
			}
		} while (!last_wqe);
	} while ((++i < MLX5E_TX_CQ_POLL_BUDGET) && (cqe = mlx5_cqwq_get_cqe(&cq->wq)));

	sq->cc = sqcc;

	mlx5_cqwq_update_db_record(&cq->wq);
	return err;
}

void mlx5e_fill_asosq_frag_edge(struct mlx5e_asosq *sq,  struct mlx5_wq_cyc *wq,
				u16 pi, u16 nnops)
{
	struct mlx5e_aso_wqe_info *edge_wi, *wi = &sq->db.aso_wqe[pi];

	edge_wi = wi + nnops;

	/* fill sq frag edge with nops to avoid wqe wrapping two pages */
	for (; wi < edge_wi; wi++) {
		wi->opcode = MLX5_OPCODE_NOP;
		mlx5e_post_nop(wq, sq->sqn, &sq->pc);
	}
}

static void mlx5e_aso_build_param(struct mlx5e_priv *priv, struct mlx5e_aso *aso)
{
	mlx5e_build_aso_cq_param(priv, &aso->cq_param);

	aso->cpu = cpumask_first(mlx5_comp_irq_get_affinity_mask(priv->mdev, 0));
	aso->sq_param.pdn = aso->pdn;
	mlx5e_build_asosq_param(priv, &aso->sq_param);
}

static int mlx5e_alloc_asosq_db(struct mlx5e_asosq *sq, int numa)
{
	int wq_sz = mlx5_wq_cyc_get_size(&sq->wq);

	sq->db.aso_wqe = kvzalloc_node(array_size(wq_sz,
						  sizeof(*sq->db.aso_wqe)),
				       GFP_KERNEL, numa);
	if (!sq->db.aso_wqe)
		return -ENOMEM;

	return 0;
}

static int mlx5e_alloc_asosq(struct mlx5e_priv *priv, struct mlx5e_aso *aso)
{
	struct mlx5e_sq_param *param = &aso->sq_param;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_asosq *sq = &aso->sq;
	struct mlx5_wq_cyc *wq = &sq->wq;
	void *sqc_wq;
	int err;

	sqc_wq = MLX5_ADDR_OF(sqc, param->sqc, wq);
	sq->uar_map = mdev->mlx5e_res.hw_objs.bfreg.map;

	param->wq.db_numa_node = cpu_to_node(aso->cpu);
	err = mlx5_wq_cyc_create(mdev, &param->wq, sqc_wq, wq, &sq->wq_ctrl);
	if (err)
		return err;
	wq->db = &wq->db[MLX5_SND_DBR];

	err = mlx5e_alloc_asosq_db(sq, cpu_to_node(aso->cpu));
	if (err)
		mlx5_wq_destroy(&sq->wq_ctrl);

	return err;
}

static void mlx5e_free_asosq_db(struct mlx5e_asosq *sq)
{
	kvfree(sq->db.aso_wqe);
}

static void mlx5e_free_asosq(struct mlx5e_asosq *sq)
{
	mlx5e_free_asosq_db(sq);
	mlx5_wq_destroy(&sq->wq_ctrl);
}

static int mlx5e_open_asosq(struct mlx5e_priv *priv, struct mlx5e_aso *aso)
{
	struct mlx5e_sq_param *param = &aso->sq_param;
	struct mlx5e_create_sq_param csp = {};
	struct mlx5e_asosq *sq = &aso->sq;
	int err;

	err = mlx5e_alloc_asosq(priv, aso);
	if (err)
		return err;

	csp.cqn             = sq->cq.mcq.cqn;
	csp.wq_ctrl         = &sq->wq_ctrl;
	csp.min_inline_mode = MLX5_INLINE_MODE_NONE;
	err = mlx5e_create_sq_rdy(priv->mdev, param, &csp, &sq->sqn);
	if (err) {
		mlx5_core_err(priv->mdev, "Failed to open aso sq, err=%d\n", err);
		goto err_free_asosq;
	}

	mlx5_core_dbg(priv->mdev, "aso sq->sqn = 0x%x\n", sq->sqn);

	set_bit(MLX5E_SQ_STATE_ENABLED, &sq->state);

	return 0;

err_free_asosq:
	mlx5e_free_asosq(sq);

	return err;
}

static void mlx5e_close_asosq(struct mlx5e_aso *aso)
{
	struct mlx5e_asosq *sq = &aso->sq;

	clear_bit(MLX5E_SQ_STATE_ENABLED, &sq->state);
	mlx5e_destroy_sq(aso->priv->mdev, sq->sqn);
	mlx5e_free_asosq(sq);
}

static int mlx5e_aso_alloc_cq(struct mlx5e_priv *priv,
			      struct mlx5e_cq_param *param,
			      struct mlx5e_cq *cq, int cpu)
{
	int err;

	param->wq.buf_numa_node = cpu_to_node(cpu);
	param->wq.db_numa_node  = cpu_to_node(cpu);
	param->eq_ix = 0; /* Use first completion vector */

	err = mlx5e_alloc_cq_common(priv, param, cq);

	/* no interrupt for aso cq */
	cq->napi    = NULL;

	return err;
}

static
int mlx5e_aso_open_cq(struct mlx5e_priv *priv,
		      struct mlx5e_cq_param *param,
		      struct mlx5e_cq *cq, int cpu)
{
	int err;

	err = mlx5e_aso_alloc_cq(priv, param, cq, cpu);
	if (err) {
		mlx5_core_err(priv->mdev, "Failed to allocate aso cq err=%d\n", err);
		return err;
	}

	cq->no_arm = true;
	err = mlx5e_create_cq(cq, param);
	if (err) {
		mlx5_core_err(priv->mdev, "Failed to create aso cq err=%d\n", err);
		goto err_free_cq;
	}

	return 0;

err_free_cq:
	mlx5e_free_cq(cq);
	return err;
}

static struct mlx5e_aso *
mlx5e_aso_setup(struct mlx5e_priv *priv)
{
	struct mlx5e_aso *aso;
	int err;

	aso = kzalloc(sizeof(*aso), GFP_KERNEL);
	if (!aso)
		return NULL;

	err = mlx5_core_alloc_pd(priv->mdev, &aso->pdn);
	if (err) {
		mlx5_core_err(priv->mdev, "Failed to alloc pd for aso, err=%d\n", err);
		goto err_pd;
	}

	mlx5e_aso_build_param(priv, aso);
	err = mlx5e_aso_open_cq(priv, &aso->cq_param, &aso->sq.cq, aso->cpu);
	if (err)
		goto err_cq;

	err = mlx5e_open_asosq(priv, aso);
	if (err)
		goto err_sq;

	aso->priv = priv;

	return aso;

err_sq:
	mlx5e_close_cq(&aso->sq.cq);
err_cq:
	mlx5_core_dealloc_pd(priv->mdev, aso->pdn);
err_pd:
	kfree(aso);
	return NULL;
}

struct mlx5e_aso *
mlx5e_aso_get(struct mlx5e_priv *priv)
{
	mutex_lock(&priv->aso_lock);
	if (!priv->aso)
		priv->aso = mlx5e_aso_setup(priv);
	if (priv->aso)
		priv->aso->refcnt++;
	mutex_unlock(&priv->aso_lock);

	return priv->aso;
}

void mlx5e_aso_put(struct mlx5e_priv *priv)
{
	mutex_lock(&priv->aso_lock);
	if (priv->aso && --priv->aso->refcnt == 0) {
		mlx5e_close_asosq(priv->aso);
		mlx5e_close_cq(&priv->aso->sq.cq);
		mlx5_core_dealloc_pd(priv->mdev, priv->aso->pdn);
		kfree(priv->aso);
		priv->aso = NULL;
	}
	mutex_unlock(&priv->aso_lock);
}
