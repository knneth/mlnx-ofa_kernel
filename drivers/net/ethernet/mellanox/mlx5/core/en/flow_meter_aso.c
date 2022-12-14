// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021 Mellanox Technologies. */

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/bitmap.h>
#include "mlx5_core.h"
#include "eswitch.h"
#include "en_rep.h"
#include "en/aso.h"
#include "flow_meter_aso.h"
#include "esw/vf_meter.h"

#define START_COLOR_SHIFT 28
#define METER_MODE_SHIFT 24
#define CBS_EXP_SHIFT 24
#define CBS_MAN_SHIFT 16
#define CIR_EXP_SHIFT 8

#ifndef S64_MAX
#define S64_MAX		((s64)(((u64)~0ULL) >> 1))
#endif

#ifndef BITS_TO_BYTES
#define BITS_TO_BYTES(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE)
#endif

/* cir = 8*(10^9)*cir_mantissa/(2^cir_exponent)) bits/s */
#define CONST_CIR 8000000000ULL
#define CALC_CIR(m, e)	((CONST_CIR * (m)) >> (e))

/* cbs = cbs_mantissa*2^cbs_exponent */
#define CALC_CBS(m, e)	((m) << (e))

static void
mlx5e_flow_meter_cir_calc(u64 cir, u8 *man, u8 *exp)
{
	s64 _cir, _delta, delta = S64_MAX;
	u8 e, _man = 0, _exp = 0;
	u64 m;

	for (e = 0; e <= 0x1F; e++) { /* exp width 5bit */
		m = cir << e;
		if ((s64)m < 0) /* overflow */
			break;
		m /= CONST_CIR;
		if (m > 0xFF) /* man width 8 bit */
			continue;
		_cir = CALC_CIR(m, e);
		_delta = cir - _cir;
		if (_delta < delta) {
			_man = m;
			_exp = e;
			if (!_delta)
				goto found;
			delta = _delta;
		}
	}

found:
	*man = _man;
	*exp = _exp;
}

static void
mlx5e_flow_meter_cbs_calc(u64 cbs, u8 *man, u8 *exp)
{
	s64 _cbs, _delta, delta = S64_MAX;
	u8 e, _man = 0, _exp = 0;
	u64 m;

	for (e = 0; e <= 0x1F; e++) { /* exp width 5bit */
		m = cbs >> e;
		if (m > 0xFF) /* man width 8 bit */
			continue;
		_cbs = CALC_CBS(m, e);
		_delta = cbs - _cbs;
		if (_delta < delta) {
			_man = m;
			_exp = e;
			if (!_delta)
				goto found;
			delta = _delta;
		}
	}

found:
	*man = _man;
	*exp = _exp;
}

static struct mlx5e_flow_meters *
mlx5e_get_flow_meters(struct mlx5_core_dev *mdev)
{
	struct mlx5e_rep_priv *rpriv;
	struct mlx5e_priv *priv;

	rpriv = mlx5_eswitch_get_uplink_priv(mdev->priv.eswitch, REP_ETH);
	priv = netdev_priv(rpriv->netdev);
	return  priv->flow_meters;
}

int
mlx5e_aso_send_flow_meter_aso(struct mlx5_core_dev *mdev, u32 obj_id,
			      u32 meter_id, int xps, u64 rate, u64 burst)
{
	struct mlx5e_aso_ctrl_param param = {};
	struct mlx5_wqe_aso_data_seg *aso_data;
	struct mlx5e_flow_meters *flow_meters;
	u8 cir_man, cir_exp, cbs_man, cbs_exp;
	struct mlx5e_aso_wqe_data *aso_wqe;
	u16 pi, contig_wqebbs_room;
	struct mlx5e_asosq *sq;
	struct mlx5_wq_cyc *wq;
	struct mlx5e_aso *aso;
	int err = 0;

	flow_meters = mlx5e_get_flow_meters(mdev);
	if (IS_ERR_OR_NULL(flow_meters))
		return -EOPNOTSUPP;
	aso = flow_meters->aso;
	sq = &aso->sq;
	wq = &sq->wq;

	/* HW treats each packet as 128 bytes in PPS mode */
	if (xps == MLX5_RATE_LIMIT_PPS) {
		rate <<= 10;
		burst <<= 7;
	}

	mlx5e_flow_meter_cir_calc(rate, &cir_man, &cir_exp);
	mlx5_core_dbg(mdev, "rate=%lld, cir=%lld, exp=%d, man=%d\n",
		      rate, CALC_CIR(cir_man, cir_exp), cir_exp, cir_man);
	mlx5e_flow_meter_cbs_calc(burst, &cbs_man, &cbs_exp);
	mlx5_core_dbg(mdev, "burst=%lld, cbs=%lld, exp=%d, man=%d\n",
		      burst, CALC_CBS((u64)cbs_man, cbs_exp), cbs_exp, cbs_man);

	if (!cir_man || !cbs_man)
		return -EINVAL;

	pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	contig_wqebbs_room = mlx5_wq_cyc_get_contig_wqebbs(wq, pi);

	if (unlikely(contig_wqebbs_room < MLX5E_ASO_WQEBBS_DATA)) {
		mlx5e_fill_asosq_frag_edge(sq, wq, pi, contig_wqebbs_room);
		pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	}

	aso_wqe = mlx5_wq_cyc_get_wqe(wq, pi);
	param.data_mask_mode = ASO_DATA_MASK_MODE_BYTEWISE_64BYTE;
	param.condition_operand = LOGICAL_OR;
	param.condition_0_operand = ALWAYS_TRUE;
	param.condition_1_operand = ALWAYS_TRUE;
	param.data_mask = 0x80FFFFFFULL << (meter_id ? 0 : 32);
	mlx5e_build_aso_wqe(aso, sq,
			    DIV_ROUND_UP(sizeof(*aso_wqe), MLX5_SEND_WQE_DS),
			    &aso_wqe->ctrl, &aso_wqe->aso_ctrl, obj_id,
			    MLX5_ACCESS_ASO_OPC_MOD_FLOW_METER, &param);

	aso_data = &aso_wqe->aso_data;
	memset(aso_data, 0, sizeof(*aso_data));
	aso_data->bytewise_data[meter_id * 8] = cpu_to_be32((0x1 << 31) | /* valid */
					(MLX5_FLOW_METER_COLOR_GREEN << START_COLOR_SHIFT));
	if (xps == MLX5_RATE_LIMIT_PPS)
		aso_data->bytewise_data[meter_id * 8] |=
			cpu_to_be32(MLX5_FLOW_METER_MODE_NUM_PACKETS << METER_MODE_SHIFT);
	else
		aso_data->bytewise_data[meter_id * 8] |=
			cpu_to_be32(MLX5_FLOW_METER_MODE_BYTES_IP_LENGTH << METER_MODE_SHIFT);

	aso_data->bytewise_data[meter_id * 8 + 2] = cpu_to_be32((cbs_exp << CBS_EXP_SHIFT) |
								(cbs_man << CBS_MAN_SHIFT) |
								(cir_exp << CIR_EXP_SHIFT) |
								 cir_man);

	sq->db.aso_wqe[pi].opcode = MLX5_OPCODE_ACCESS_ASO;
	sq->db.aso_wqe[pi].with_data = true;
	sq->pc += MLX5E_ASO_WQEBBS_DATA;
	sq->doorbell_cseg = &aso_wqe->ctrl;

	mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, sq->doorbell_cseg);

	/* Ensure doorbell is written on uar_page before poll_cq */
	WRITE_ONCE(sq->doorbell_cseg, NULL);

	err = mlx5e_poll_aso_cq(&sq->cq);

	return err;
}

static int
mlx5e_create_flow_meter_aso_obj(struct mlx5_core_dev *mdev, int *obj_id)
{
	u32 in[MLX5_ST_SZ_DW(create_flow_meter_aso_obj_in)] = {};
	u32 out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)];
	struct mlx5e_flow_meters *flow_meters;
	void *obj;
	int err;

	MLX5_SET(general_obj_in_cmd_hdr, in, opcode, MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr, in, obj_type,
		 MLX5_GENERAL_OBJECT_TYPES_FLOW_METER_ASO);
	flow_meters = mlx5e_get_flow_meters(mdev);
	MLX5_SET(general_obj_in_cmd_hdr, in, log_obj_range, flow_meters->log_granularity);

	obj = MLX5_ADDR_OF(create_flow_meter_aso_obj_in, in, flow_meter_aso_obj);
	MLX5_SET(flow_meter_aso_obj, obj, meter_aso_access_pd, flow_meters->aso->pdn);

	err = mlx5_cmd_exec(mdev, in, sizeof(in), out, sizeof(out));
	if (!err) {
		*obj_id = MLX5_GET(general_obj_out_cmd_hdr, out, obj_id);
		mlx5_core_dbg(mdev, "flow meter aso obj(0x%x) created\n", *obj_id);
	}

	return err;
}

static void
mlx5e_destroy_flow_meter_aso_obj(struct mlx5_core_dev *mdev, u32 obj_id)
{
	u32 in[MLX5_ST_SZ_DW(general_obj_in_cmd_hdr)] = {};
	u32 out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)];

	MLX5_SET(general_obj_in_cmd_hdr, in, opcode,
		 MLX5_CMD_OP_DESTROY_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr, in, obj_type,
		 MLX5_GENERAL_OBJECT_TYPES_FLOW_METER_ASO);
	MLX5_SET(general_obj_in_cmd_hdr, in, obj_id, obj_id);

	mlx5_cmd_exec(mdev, in, sizeof(in), out, sizeof(out));
	mlx5_core_dbg(mdev, "flow meter aso obj(0x%x) destroyed\n", obj_id);
}

struct mlx5e_flow_meter_aso_obj *
mlx5e_alloc_flow_meter(struct mlx5_core_dev *mdev, u32 *obj_id, int *idx)
{
	struct mlx5e_flow_meter_aso_obj *meters_obj;
	struct mlx5e_flow_meters *flow_meters;
	int err, pos, total;
	u32 id;

	flow_meters = mlx5e_get_flow_meters(mdev);
	if (IS_ERR_OR_NULL(flow_meters))
		return ERR_PTR(-EOPNOTSUPP);

	mutex_lock(&flow_meters->sync_lock);
	meters_obj = list_first_entry_or_null(&flow_meters->partial_list,
					      struct mlx5e_flow_meter_aso_obj,
					      entry);
	/* 2 meters in one object */
	total = 1 << (flow_meters->log_granularity + 1);
	if (!meters_obj) {
		err = mlx5e_create_flow_meter_aso_obj(mdev, &id);
		if (err)
			goto err_out;

		meters_obj = kzalloc(sizeof(*meters_obj) + BITS_TO_BYTES(total),
				     GFP_KERNEL);
		if (!meters_obj) {
			err = -ENOMEM;
			mlx5e_destroy_flow_meter_aso_obj(mdev, id);
			goto err_out;
		}

		meters_obj->base_id = id;
		meters_obj->total_meters = total;
		list_add(&meters_obj->entry, &flow_meters->partial_list);
		pos = 0;
	} else {
		pos = find_first_zero_bit(meters_obj->meters_map,
					  meters_obj->total_meters);
		if (pos == total - 1 ||
		    find_next_zero_bit(meters_obj->meters_map,
				       total, pos + 1) == total) {
			list_del(&meters_obj->entry);
			list_add(&meters_obj->entry, &flow_meters->full_list);
		}
	}

	bitmap_set(meters_obj->meters_map, pos, 1);
	*obj_id = meters_obj->base_id + pos / 2;
	*idx = pos % 2;
	mlx5_core_dbg(mdev, "flow meter allocated, obj_id=0x%x, index=%d",
		      *obj_id, *idx);

	mutex_unlock(&flow_meters->sync_lock);
	return meters_obj;

err_out:
	mutex_unlock(&flow_meters->sync_lock);
	return ERR_PTR(err);
}

void
mlx5e_free_flow_meter(struct mlx5_core_dev *mdev,
		      struct mlx5e_flow_meter_aso_obj *meters_obj,
		      u32 obj_id, int idx)
{
	struct mlx5e_flow_meters *flow_meters;
	int pos;

	flow_meters = mlx5e_get_flow_meters(mdev);
	pos = (obj_id - meters_obj->base_id) * 2 + idx;
	mutex_lock(&flow_meters->sync_lock);
	bitmap_clear(meters_obj->meters_map, pos, 1);
	mlx5_core_dbg(mdev, "flow meter freed, obj_id=0x%x, index=%d", obj_id, idx);
	if (bitmap_empty(meters_obj->meters_map, meters_obj->total_meters)) {
		list_del(&meters_obj->entry);
		mlx5e_destroy_flow_meter_aso_obj(mdev, meters_obj->base_id);
		kfree(meters_obj);
	}
	mutex_unlock(&flow_meters->sync_lock);
}

int
mlx5e_flow_meters_init(struct mlx5e_priv *priv)
{
	struct mlx5e_flow_meters *flow_meters;
	u64 general_obj_types;
	int err = 0;

	general_obj_types = MLX5_CAP_GEN_64(priv->mdev, general_obj_types);
	if (!(general_obj_types & MLX5_HCA_CAP_GENERAL_OBJECT_TYPES_FLOW_METER_ASO))
		return 0;

	flow_meters  = kzalloc(sizeof(*flow_meters), GFP_KERNEL);
	if (!flow_meters)
		return -ENOMEM;

	err = esw_vf_meter_create_meters(priv->mdev->priv.eswitch);
	if (err)
		goto err_out;

	flow_meters->log_granularity = min_t(int, 6,
					     MLX5_CAP_QOS(priv->mdev, log_meter_aso_granularity));
	mutex_init(&flow_meters->sync_lock);
	INIT_LIST_HEAD(&flow_meters->partial_list);
	INIT_LIST_HEAD(&flow_meters->full_list);

	flow_meters->aso = mlx5e_aso_setup(priv, 0);
	if (flow_meters->aso)
		priv->flow_meters = flow_meters;
	else
		goto err_out;

	return 0;

err_out:
	kfree(flow_meters);
	esw_vf_meter_destroy_meters(priv->mdev->priv.eswitch);
	return err;
}

void
mlx5e_flow_meters_cleanup(struct mlx5e_priv *priv)
{
	if (IS_ERR_OR_NULL(priv->flow_meters))
		return;

	esw_vf_meter_destroy_all(priv->mdev->priv.eswitch);
	mlx5e_aso_cleanup(priv, priv->flow_meters->aso);

	kfree(priv->flow_meters);
	priv->flow_meters = NULL;
}
