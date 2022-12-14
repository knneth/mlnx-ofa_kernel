// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include "en_tc.h"
#include "flow_meter.h"

#define MLX5_PACKET_COLOR_BITS (mlx5e_tc_attr_to_reg_mappings[PACKET_COLOR_TO_REG].mlen * 8)
#define MLX5_PACKET_COLOR_MASK GENMASK(MLX5_PACKET_COLOR_BITS - 1, 0)

#define START_COLOR_SHIFT 28
#define METER_MODE_SHIFT 24
#define CBS_EXP_SHIFT 24
#define CBS_MAN_SHIFT 16
#define CIR_EXP_SHIFT 8

/* cir = 8*(10^9)*cir_mantissa/(2^cir_exponent)) bits/s */
#define CONST_CIR 8000000000ULL
#define CALC_CIR(m, e)  ((CONST_CIR * (m)) >> (e))
#define MAX_CIR ((CONST_CIR * 0x100) - 1)

/* cbs = cbs_mantissa*2^cbs_exponent */
#define CALC_CBS(m, e)  ((m) << (e))
#define MAX_CBS ((0x100ULL << 0x1F) - 1)

struct mlx5e_flow_meters {
	enum mlx5_flow_namespace_type ns_type;
	struct mlx5e_aso *aso;
	int log_granularity;

	DECLARE_HASHTABLE(hashtbl, 8);

	struct mutex sync_lock; /* protect flow meter operations */
	struct list_head partial_list;
	struct list_head full_list;

	struct mlx5_post_action *post_action;

	struct mlx5_flow_table *post_meter;
	struct mlx5_flow_group *post_meter_fg;
	struct mlx5_flow_handle *fwd_green_rule;
	struct mlx5_flow_handle *drop_red_rule;
};

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
mlx5e_get_flow_meters(struct mlx5_core_dev *dev)
{
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5_rep_uplink_priv *uplink_priv;
	struct mlx5e_rep_priv *uplink_rpriv;

	if (is_mdev_switchdev_mode(dev)) {
		uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
		uplink_priv = &uplink_rpriv->uplink_priv;
		return uplink_priv->flow_meters;
	}

	return NULL;
}

int
mlx5e_aso_send_flow_meter_aso(struct mlx5_core_dev *mdev,
			      struct mlx5_meter_handle *meter,
			      struct mlx5_flow_meter_params *meter_params)
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
	u64 rate, burst;
	int err = 0;

	flow_meters = meter->flow_meters;
	aso = flow_meters->aso;
	sq = &aso->sq;
	wq = &sq->wq;

	rate = meter_params->rate;
	burst = meter_params->burst;
	/* HW treats each packet as 128 bytes in PPS mode */
	if (meter_params->mode == MLX5_RATE_LIMIT_PPS) {
		rate <<= 10;
		burst <<= 7;
	}

	if (!rate || rate > MAX_CIR || !burst || burst > MAX_CBS)
		return -EINVAL;

	mlx5_core_dbg(mdev, "meter mode=%d\n", meter_params->mode);
	mlx5e_flow_meter_cir_calc(rate, &cir_man, &cir_exp);
	mlx5_core_dbg(mdev, "rate=%lld, cir=%lld, exp=%d, man=%d\n",
		      rate, CALC_CIR(cir_man, cir_exp), cir_exp, cir_man);
	mlx5e_flow_meter_cbs_calc(burst, &cbs_man, &cbs_exp);
	mlx5_core_dbg(mdev, "burst=%lld, cbs=%lld, exp=%d, man=%d\n",
		      burst, CALC_CBS((u64)cbs_man, cbs_exp), cbs_exp, cbs_man);

	if (!cir_man || !cbs_man)
		return -EINVAL;

	mutex_lock(&aso->priv->aso_lock);
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
	param.data_mask = 0x80FFFFFFULL << (meter->idx ? 0 : 32);
	mlx5e_build_aso_wqe(aso, sq,
			    DIV_ROUND_UP(sizeof(*aso_wqe), MLX5_SEND_WQE_DS),
			    &aso_wqe->ctrl, &aso_wqe->aso_ctrl, meter->obj_id,
			    MLX5_ACCESS_ASO_OPC_MOD_FLOW_METER, &param);

	aso_data = &aso_wqe->aso_data;
	memset(aso_data, 0, sizeof(*aso_data));
	aso_data->bytewise_data[meter->idx * 8] = cpu_to_be32((0x1 << 31) | /* valid */
					(MLX5_FLOW_METER_COLOR_GREEN << START_COLOR_SHIFT));
	if (meter_params->mode == MLX5_RATE_LIMIT_PPS)
		aso_data->bytewise_data[meter->idx * 8] |=
			cpu_to_be32(MLX5_FLOW_METER_MODE_NUM_PACKETS << METER_MODE_SHIFT);
	else
		aso_data->bytewise_data[meter->idx * 8] |=
			cpu_to_be32(MLX5_FLOW_METER_MODE_BYTES_IP_LENGTH << METER_MODE_SHIFT);

	aso_data->bytewise_data[meter->idx * 8 + 2] = cpu_to_be32((cbs_exp << CBS_EXP_SHIFT) |
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
	mutex_unlock(&aso->priv->aso_lock);

	return err;
}

static int
mlx5e_create_flow_meter_aso_obj(struct mlx5_core_dev *dev,
				struct mlx5e_flow_meters *flow_meters, int *obj_id)
{
	u32 in[MLX5_ST_SZ_DW(create_flow_meter_aso_obj_in)] = {};
	u32 out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)];
	void *obj;
	int err;

	MLX5_SET(general_obj_in_cmd_hdr, in, opcode, MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr, in, obj_type,
		 MLX5_GENERAL_OBJECT_TYPES_FLOW_METER_ASO);
	MLX5_SET(general_obj_in_cmd_hdr, in, log_obj_range, flow_meters->log_granularity);

	obj = MLX5_ADDR_OF(create_flow_meter_aso_obj_in, in, flow_meter_aso_obj);
	MLX5_SET(flow_meter_aso_obj, obj, meter_aso_access_pd, flow_meters->aso->pdn);

	err = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
	if (!err) {
		*obj_id = MLX5_GET(general_obj_out_cmd_hdr, out, obj_id);
		mlx5_core_dbg(dev, "flow meter aso obj(0x%x) created\n", *obj_id);
	}

	return err;
}

static void
mlx5e_destroy_flow_meter_aso_obj(struct mlx5_core_dev *dev, u32 obj_id)
{
	u32 in[MLX5_ST_SZ_DW(general_obj_in_cmd_hdr)] = {};
	u32 out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)];

	MLX5_SET(general_obj_in_cmd_hdr, in, opcode, MLX5_CMD_OP_DESTROY_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr, in, obj_type,
		 MLX5_GENERAL_OBJECT_TYPES_FLOW_METER_ASO);
	MLX5_SET(general_obj_in_cmd_hdr, in, obj_id, obj_id);

	mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
	mlx5_core_dbg(dev, "flow meter aso obj(0x%x) destroyed\n", obj_id);
}

static struct mlx5_meter_handle *
__mlx5e_alloc_flow_meter(struct mlx5_core_dev *dev,
			 struct mlx5e_flow_meters *flow_meters)
{
	struct mlx5e_flow_meter_aso_obj *meters_obj;
	struct mlx5_meter_handle *meter;
	int err, pos, total;
	u32 id;

	meter = kzalloc(sizeof(*meter), GFP_KERNEL);
	if (!meter)
		return ERR_PTR(-ENOMEM);

	meters_obj = list_first_entry_or_null(&flow_meters->partial_list,
					      struct mlx5e_flow_meter_aso_obj,
					      entry);
	/* 2 meters in one object */
	total = 1 << (flow_meters->log_granularity + 1);
	if (!meters_obj) {
		err = mlx5e_create_flow_meter_aso_obj(dev, flow_meters, &id);
		if (err) {
			mlx5_core_err(dev, "Failed to create flow meter ASO object\n");
			goto err_create;
		}

		meters_obj = kzalloc(sizeof(*meters_obj) + BITS_TO_BYTES(total),
				     GFP_KERNEL);
		if (!meters_obj) {
			err = -ENOMEM;
			goto err_mem;
		}

		meters_obj->base_id = id;
		meters_obj->total_meters = total;
		list_add(&meters_obj->entry, &flow_meters->partial_list);
		pos = 0;
	} else {
		pos = find_first_zero_bit(meters_obj->meters_map, total);
		if (bitmap_weight(meters_obj->meters_map, total) == total - 1) {
			list_del(&meters_obj->entry);
			list_add(&meters_obj->entry, &flow_meters->full_list);
		}
	}

	bitmap_set(meters_obj->meters_map, pos, 1);
	meter->flow_meters = flow_meters;
	meter->meters_obj = meters_obj;
	meter->obj_id = meters_obj->base_id + pos / 2;
	meter->idx = pos % 2;

	mlx5_core_dbg(dev, "flow meter allocated, obj_id=0x%x, index=%d\n",
		      meter->obj_id, meter->idx);

	return meter;

err_mem:
	mlx5e_destroy_flow_meter_aso_obj(dev, id);
err_create:
	kfree(meter);
	return ERR_PTR(err);
}

static void
__mlx5e_free_flow_meter(struct mlx5_core_dev *dev,
			struct mlx5e_flow_meters *flow_meters,
			struct mlx5_meter_handle *meter)
{
	struct mlx5e_flow_meter_aso_obj *meters_obj;
	int n, pos;

	meters_obj = meter->meters_obj;
	pos = (meter->obj_id - meters_obj->base_id) * 2 + meter->idx;
	bitmap_clear(meters_obj->meters_map, pos, 1);
	n = bitmap_weight(meters_obj->meters_map, meters_obj->total_meters);
	if (n == 0) {
		list_del(&meters_obj->entry);
		mlx5e_destroy_flow_meter_aso_obj(dev, meters_obj->base_id);
		kfree(meters_obj);
	} else if (n == meters_obj->total_meters - 1) {
		list_del(&meters_obj->entry);
		list_add(&meters_obj->entry, &flow_meters->partial_list);
	}

	mlx5_core_dbg(dev, "flow meter freed, obj_id=0x%x, index=%d\n",
		      meter->obj_id, meter->idx);
	kfree(meter);
}

struct mlx5_meter_handle *
mlx5e_alloc_flow_meter(struct mlx5_core_dev *dev)
{
	struct mlx5e_flow_meters *flow_meters;
	struct mlx5_meter_handle *meter;

	flow_meters = mlx5e_get_flow_meters(dev);
	if (IS_ERR_OR_NULL(flow_meters))
		return ERR_PTR(-EOPNOTSUPP);

	mutex_lock(&flow_meters->sync_lock);
	meter = __mlx5e_alloc_flow_meter(dev, flow_meters);
	mutex_unlock(&flow_meters->sync_lock);

	return meter;
}

void
mlx5e_free_flow_meter(struct mlx5_core_dev *dev, struct mlx5_meter_handle *meter)
{
	struct mlx5e_flow_meters *flow_meters;

	flow_meters = meter->flow_meters;
	mutex_lock(&flow_meters->sync_lock);
	__mlx5e_free_flow_meter(dev, flow_meters, meter);
	mutex_unlock(&flow_meters->sync_lock);
}

struct mlx5_meter_handle *
mlx5e_get_flow_meter(struct mlx5_core_dev *mdev, struct mlx5_flow_meter_params *params)
{
	struct mlx5e_flow_meters *flow_meters;
	struct mlx5_meter_handle *meter;
	int err;

	flow_meters = mlx5e_get_flow_meters(mdev);
	if (IS_ERR_OR_NULL(flow_meters))
		return ERR_PTR(-EOPNOTSUPP);

	mutex_lock(&flow_meters->sync_lock);
	hash_for_each_possible(flow_meters->hashtbl, meter, hlist, params->index)
		if (meter->params.index == params->index)
			goto add_ref;

	meter = __mlx5e_alloc_flow_meter(mdev, flow_meters);
	if (IS_ERR(meter)) {
		err = PTR_ERR(meter);
		goto err_alloc;
	}

	hash_add(flow_meters->hashtbl, &meter->hlist, params->index);
	meter->params.index = params->index;

add_ref:
	meter->refcnt++;

	if (meter->params.mode != params->mode || meter->params.rate != params->rate ||
	    meter->params.burst != params->burst) {
		err = mlx5e_aso_send_flow_meter_aso(mdev, meter, params);
		if (err)
			goto err_update;

		meter->params.mode = params->mode;
		meter->params.rate = params->rate;
		meter->params.burst = params->burst;
	}

	mutex_unlock(&flow_meters->sync_lock);
	return meter;

err_update:
	if (--meter->refcnt == 0) {
		hash_del(&meter->hlist);
		__mlx5e_free_flow_meter(mdev, flow_meters, meter);
	}
err_alloc:
	mutex_unlock(&flow_meters->sync_lock);
	return ERR_PTR(err);
}

void
mlx5e_put_flow_meter(struct mlx5_core_dev *mdev, struct mlx5_meter_handle *meter)
{
	struct mlx5e_flow_meters *flow_meters;

	flow_meters = meter->flow_meters;
	mutex_lock(&flow_meters->sync_lock);
	if (--meter->refcnt == 0) {
		hash_del(&meter->hlist);
		__mlx5e_free_flow_meter(mdev, flow_meters, meter);
	}
	mutex_unlock(&flow_meters->sync_lock);
}

static void
__mlx5e_free_flow_meter_post_action(struct mlx5e_priv *priv,
				    struct mlx5e_flow_meters *flow_meters,
				    struct mlx5_flow_attr *attr)
{
	int i;

	for (i = 0; i < attr->parse_attr->meters.count; i++) {
		mlx5_post_action_del(priv, flow_meters->post_action,
				     attr->meter_attr.meters[i].post_action);
		attr->meter_attr.meters[i].post_action = NULL;
	}
}

void
mlx5e_free_flow_meter_post_action(struct mlx5e_priv *priv,
				  struct mlx5_flow_attr *attr)
{
	struct mlx5e_flow_meters *flow_meters;

	flow_meters = mlx5e_get_flow_meters(priv->mdev);
	if (IS_ERR_OR_NULL(flow_meters))
		return;

	__mlx5e_free_flow_meter_post_action(priv, flow_meters, attr);
}

void
mlx5e_tc_meter_unoffload(struct mlx5_core_dev *mdev, struct mlx5_flow_handle *rule,
			 struct mlx5_flow_attr *attr)
{
	struct mlx5_flow_attr *pre_attr = attr->meter_attr.pre_attr;
	struct mlx5e_flow_meters *flow_meters;
	struct mlx5e_priv *priv;

	flow_meters = mlx5e_get_flow_meters(mdev);
	if (IS_ERR_OR_NULL(flow_meters))
		return;

	priv = flow_meters->aso->priv;
	__mlx5e_free_flow_meter_post_action(priv, flow_meters, attr);
	mlx5_post_action_del(priv, flow_meters->post_action,
			     attr->meter_attr.last_post_action);
	mlx5_tc_rule_delete(priv, rule, pre_attr);
	mlx5_modify_header_dealloc(mdev, pre_attr->modify_hdr);

	kfree(attr->meter_attr.pre_attr);
}

static struct mlx5_post_action_handle *
__mlx5e_fill_flow_meter_post_action(struct mlx5e_priv *priv,
				    struct mlx5e_flow_meters *flow_meters,
				    struct mlx5_flow_attr *attr,
				    struct mlx5_post_action_handle *last)
{
	struct mlx5e_tc_mod_hdr_acts mod_acts = {};
	struct mlx5_post_action_handle *handle;
	struct mlx5_meter_handle *meter;
	struct mlx5_modify_hdr *mod_hdr;
	struct mlx5_flow_attr *mattr;
	int i, j, err;

	mattr = mlx5_alloc_flow_attr(flow_meters->ns_type);
	if (!mattr)
		return ERR_PTR(-ENOMEM);

	for (i = attr->parse_attr->meters.count - 1; i >= 0; i--) {
		memset(mattr, 0, sizeof(*mattr));
		mod_acts.num_actions = 0;

		err = mlx5_post_action_set_handle(priv->mdev, last, &mod_acts);
		if (err) {
			mlx5_core_err(priv->mdev, "Failed to set fte_id mapping for meter\n");
			goto err_setid;
		}

		mod_hdr = mlx5_modify_header_alloc(priv->mdev, flow_meters->ns_type,
						   mod_acts.num_actions, mod_acts.actions);
		if (IS_ERR(mod_hdr)) {
			err = PTR_ERR(mod_hdr);
			mlx5_core_err(priv->mdev, "Failed to create mod hdr for meter\n");
			goto err_alloc_mh;
		}

		meter = mlx5e_get_flow_meter(priv->mdev,
					     &attr->parse_attr->meters.params[i]);
		if (IS_ERR(meter)) {
			err = PTR_ERR(meter);
			mlx5_core_err(priv->mdev, "Failed to get hw flow meter\n");
			goto err_meter;
		}

		mattr->meter_attr.meters[0].handle = meter;
		mattr->modify_hdr = mod_hdr;
		mattr->dest_ft = flow_meters->post_meter;
		mattr->action = MLX5_FLOW_CONTEXT_ACTION_EXECUTE_ASO |
				MLX5_FLOW_CONTEXT_ACTION_MOD_HDR |
				MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
		/* move counter to the rule for the first meter */
		if (i == 0 && attr->counter) {
			mattr->counter = attr->counter;
			mattr->action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;
		}
		mattr->flags = MLX5_ESW_ATTR_FLAG_NO_IN_PORT;

		handle = mlx5_post_action_add(priv, flow_meters->post_action, mattr);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			goto err_post_action;
		}

		attr->meter_attr.meters[i].post_action = handle;

		last = handle;
	}

	dealloc_mod_hdr_actions(&mod_acts);
	kfree(mattr);
	return handle;

err_post_action:
	mlx5e_put_flow_meter(priv->mdev, meter);
err_meter:
	mlx5_modify_header_dealloc(priv->mdev, mod_hdr);
err_alloc_mh:
	dealloc_mod_hdr_actions(&mod_acts);
err_setid:
	for (j = i + 1; j < attr->parse_attr->meters.count; j++) {
		mlx5_post_action_del(priv, flow_meters->post_action,
				     attr->meter_attr.meters[j].post_action);
		attr->meter_attr.meters[j].post_action = NULL;
	}
	kfree(mattr);
	return ERR_PTR(err);
}

struct mlx5_post_action_handle *
mlx5e_fill_flow_meter_post_action(struct mlx5e_priv *priv,
				  struct mlx5_flow_attr *attr,
				  struct mlx5_post_action_handle *last)
{
	struct mlx5e_flow_meters *flow_meters;

	flow_meters = mlx5e_get_flow_meters(priv->mdev);
	if (IS_ERR_OR_NULL(flow_meters))
		return ERR_PTR(-EOPNOTSUPP);

	return __mlx5e_fill_flow_meter_post_action(priv, flow_meters, attr, last);
}

/* We translate the tc filter with police action to the following HW model:
 *
 * +---------------------+
 * + original flow table +
 * +---------------------+
 * +   original match    +
 * +---------------------+
 *         | set fte_id
 *         |(do decap)
 *         |
 *         +--------------------------------------<------------------------+
 *         v                                                               |
 * +---------------------+ counter on first meter                          |
 * +  post_action table  + do metering                                     |
 * +---------------------+ set new fte_id +--------------------+           |
 * +   fte_id match      +--------------->+  post_meter table  +           |
 * +---------------------+                +--------------------+  if GREEN |
 *         | if last fte_id               + packet color match +---------->+
 *         | original filter actions      +--------------------+
 *         v   (counter excluded)                   | drop if RED
 *                                                  v
 */

struct mlx5_flow_handle *
mlx5e_tc_meter_offload(struct mlx5_core_dev *mdev,
		       struct mlx5_flow_spec *spec, struct mlx5_flow_attr *attr)
{
	struct mlx5_post_action_handle *first, *last;
	struct mlx5e_tc_mod_hdr_acts mod_acts = {};
	struct mlx5e_flow_meters *flow_meters;
	struct mlx5_post_action *post_action;
	struct mlx5_flow_attr *pre_attr;
	struct mlx5_modify_hdr *mod_hdr;
	struct mlx5_flow_handle *rule;
	struct mlx5e_priv *priv;
	int err;

	flow_meters = mlx5e_get_flow_meters(mdev);
	if (IS_ERR_OR_NULL(flow_meters))
		return ERR_PTR(-EOPNOTSUPP);

	pre_attr = mlx5_alloc_flow_attr(flow_meters->ns_type);
	if (!pre_attr)
		return ERR_PTR(-ENOMEM);

	priv = flow_meters->aso->priv;
	post_action = flow_meters->post_action;

	memcpy(pre_attr, attr, ns_to_attr_sz(flow_meters->ns_type));
	pre_attr->action = attr->action & MLX5_FLOW_CONTEXT_ACTION_DECAP;
	attr->action &= ~MLX5_FLOW_CONTEXT_ACTION_COUNT;
	attr->flags |= MLX5_ESW_ATTR_FLAG_NO_IN_PORT;

	last = mlx5_post_action_add(priv, post_action, attr);
	if (IS_ERR(last)) {
		err = PTR_ERR(last);
		goto err_alloc_last;
	}

	first = __mlx5e_fill_flow_meter_post_action(priv, flow_meters, attr, last);
	if (IS_ERR(first)) {
		err = PTR_ERR(first);
		goto err_meters;
	}

	err = mlx5_post_action_set_handle(mdev, first, &mod_acts);
	if (err) {
		mlx5_core_err(mdev, "Failed to set fte_id mapping for meter\n");
		goto err_setid;
	}

	mod_hdr = mlx5_modify_header_alloc(mdev, flow_meters->ns_type,
					   mod_acts.num_actions, mod_acts.actions);
	if (IS_ERR(mod_hdr)) {
		err = PTR_ERR(mod_hdr);
		mlx5_core_err(mdev, "Failed to create mod hdr for meter pre-rule\n");
		goto err_alloc_mh;
	}

	pre_attr->modify_hdr = mod_hdr;
	pre_attr->dest_ft = mlx5_post_action_get_ft(post_action);
	pre_attr->action |= MLX5_FLOW_CONTEXT_ACTION_MOD_HDR | MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;

	rule = mlx5_tc_rule_insert(priv, spec, pre_attr);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		goto err_pre_rule;
	}

	attr->meter_attr.last_post_action = last;
	attr->meter_attr.pre_attr = pre_attr;
	/* set count flag back, so counter can be freed when deleting the rule */
	if (attr->counter)
		attr->action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;

	dealloc_mod_hdr_actions(&mod_acts);

	return rule;

err_pre_rule:
	mlx5_modify_header_dealloc(priv->mdev, mod_hdr);
err_alloc_mh:
	dealloc_mod_hdr_actions(&mod_acts);
err_setid:
	__mlx5e_free_flow_meter_post_action(priv, flow_meters, attr);
err_meters:
	mlx5_post_action_del(priv, post_action, last);
err_alloc_last:
	if (attr->counter)
		attr->action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;
	kfree(pre_attr);
	return ERR_PTR(err);
}

static int
mlx5e_post_meter_table_create(struct mlx5e_priv *priv,
			      struct mlx5e_flow_meters *flow_meters)
{
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_flow_namespace *root_ns;

	root_ns = mlx5_get_flow_namespace(priv->mdev, flow_meters->ns_type);
	if (!root_ns) {
		mlx5_core_warn(priv->mdev, "Failed to get namespace for flow meter\n");
		return -EOPNOTSUPP;
	}

	ft_attr.flags = MLX5_FLOW_TABLE_UNMANAGED;
	ft_attr.prio = FDB_SLOW_PATH;
	ft_attr.max_fte = 2;
	ft_attr.level = 1;

	flow_meters->post_meter = mlx5_create_flow_table(root_ns, &ft_attr);
	if (IS_ERR(flow_meters->post_meter)) {
		mlx5_core_warn(priv->mdev, "Failed to create post_meter table\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int
mlx5e_post_meter_fg_create(struct mlx5e_priv *priv,
			   struct mlx5e_flow_meters *flow_meters)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	void *misc2, *match_criteria;
	struct mlx5_flow_group *grp;
	u32 *flow_group_in;
	int err = 0;

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in)
		return -ENOMEM;

	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable,
		 MLX5_MATCH_MISC_PARAMETERS_2);
	match_criteria = MLX5_ADDR_OF(create_flow_group_in, flow_group_in,
				      match_criteria);
	misc2 = MLX5_ADDR_OF(fte_match_param, match_criteria, misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc2, metadata_reg_c_5, 0xFF);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 0);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, 1);

	grp = mlx5_create_flow_group(flow_meters->post_meter, flow_group_in);
	if (IS_ERR(grp)) {
		mlx5_core_warn(priv->mdev, "Failed to create post_meter flow group\n");
		err = PTR_ERR(grp);
		goto err_out;
	}

	flow_meters->post_meter_fg = grp;

err_out:
	kvfree(flow_group_in);
	return err;
}

static int
mlx5e_post_meter_rules_create(struct mlx5e_priv *priv,
			      struct mlx5e_flow_meters *flow_meters)
{
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_handle *rule;
	struct mlx5_flow_spec *spec;
	int err;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	mlx5e_tc_match_to_reg_match(spec, PACKET_COLOR_TO_REG,
				    MLX5_FLOW_METER_COLOR_RED, MLX5_PACKET_COLOR_MASK);
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_DROP;
	flow_act.flags |= FLOW_ACT_IGNORE_FLOW_LEVEL;

	rule = mlx5_add_flow_rules(flow_meters->post_meter, spec, &flow_act, NULL, 0);
	if (IS_ERR(rule)) {
		mlx5_core_warn(priv->mdev, "Failed to create post_meter flow drop rule\n");
		err = PTR_ERR(rule);
		goto err_red;
	}
	flow_meters->drop_red_rule = rule;

	mlx5e_tc_match_to_reg_match(spec, PACKET_COLOR_TO_REG,
				    MLX5_FLOW_METER_COLOR_GREEN, MLX5_PACKET_COLOR_MASK);
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest.ft = mlx5_post_action_get_ft(flow_meters->post_action);

	rule = mlx5_add_flow_rules(flow_meters->post_meter, spec, &flow_act, &dest, 1);
	if (IS_ERR(rule)) {
		mlx5_core_warn(priv->mdev, "Failed to create post_meter flow green rule\n");
		err = PTR_ERR(rule);
		goto err_green;
	}
	flow_meters->fwd_green_rule = rule;

	kvfree(spec);
	return 0;

err_green:
	mlx5_del_flow_rules(flow_meters->drop_red_rule);
err_red:
	kvfree(spec);
	return err;
}

static void
mlx5e_post_meter_rules_destroy(struct mlx5e_flow_meters *flow_meters)
{
	mlx5_del_flow_rules(flow_meters->drop_red_rule);
	mlx5_del_flow_rules(flow_meters->fwd_green_rule);
}

static void
mlx5e_post_meter_fg_destroy(struct mlx5e_flow_meters *flow_meters)
{
	mlx5_destroy_flow_group(flow_meters->post_meter_fg);
}

static void
mlx5e_post_meter_table_destroy(struct mlx5e_flow_meters *flow_meters)
{
	mlx5_destroy_flow_table(flow_meters->post_meter);
}

static int
mlx5e_post_meter_init(struct mlx5e_priv *priv, struct mlx5e_flow_meters *flow_meters)
{
	int err;

	err = mlx5e_post_meter_table_create(priv, flow_meters);
	if (err)
		return err;

	err = mlx5e_post_meter_fg_create(priv, flow_meters);
	if (err)
		goto err_fg;

	err = mlx5e_post_meter_rules_create(priv, flow_meters);
	if (err)
		goto err_rules;

	return 0;

err_rules:
	mlx5e_post_meter_fg_destroy(flow_meters);
err_fg:
	mlx5e_post_meter_table_destroy(flow_meters);
	return err;
}

static void
mlx5e_post_meter_cleanup(struct mlx5e_flow_meters *flow_meters)
{
	mlx5e_post_meter_rules_destroy(flow_meters);
	mlx5e_post_meter_fg_destroy(flow_meters);
	mlx5e_post_meter_table_destroy(flow_meters);
}

struct mlx5e_flow_meters *
mlx5e_flow_meters_init(struct mlx5e_priv *priv, enum mlx5_flow_namespace_type ns_type)
{
	struct mlx5e_flow_meters *flow_meters;
	struct mlx5_post_action *post_action;
	int err;

	if (!(MLX5_CAP_GEN_64(priv->mdev, general_obj_types) &
	      MLX5_HCA_CAP_GENERAL_OBJECT_TYPES_FLOW_METER_ASO))
		return NULL;

	flow_meters = kzalloc(sizeof(*flow_meters), GFP_KERNEL);
	if (!flow_meters)
		return NULL;

	flow_meters->aso = mlx5e_aso_get(priv);
	if (!flow_meters->aso) {
		mlx5_core_warn(priv->mdev, "Failed to create aso wqe\n");
		goto err_aso;
	}

	post_action = priv->mdev->priv.eswitch->offloads.post_action;
	if (IS_ERR_OR_NULL(post_action)) {
		mlx5_core_warn(priv->mdev,
			       "Failed to init flow meter, post action is missing\n");
		goto err_post_meter;
	}

	flow_meters->ns_type = ns_type;
	flow_meters->post_action = post_action;

	err = mlx5e_post_meter_init(priv, flow_meters);
	if (err)
		goto err_post_meter;

	flow_meters->log_granularity = min_t(int, 6,
					     MLX5_CAP_QOS(priv->mdev, log_meter_aso_granularity));
	mutex_init(&flow_meters->sync_lock);
	INIT_LIST_HEAD(&flow_meters->partial_list);
	INIT_LIST_HEAD(&flow_meters->full_list);

	return flow_meters;

err_post_meter:
	mlx5e_aso_put(priv);
err_aso:
	kfree(flow_meters);
	return NULL;
}

void
mlx5e_flow_meters_cleanup(struct mlx5e_flow_meters *flow_meters)
{
	if (!flow_meters)
		return;

	mlx5e_post_meter_cleanup(flow_meters);
	mlx5e_aso_put(flow_meters->aso->priv);

	kfree(flow_meters);
}
