/*
 * Copyright (c) 2016 Mellanox Technologies. All rights reserved.
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

#include "mlx5_ib.h"
#include "user_exp.h"
#include <linux/mlx5/qp.h>
#include <linux/mlx5/qp_exp.h>
#include <rdma/ib_verbs_exp.h>

int mlx5_ib_exp_get_cmd_data(struct mlx5_ib_dev *dev,
			     struct ib_udata *udata,
			     struct mlx5_ib_create_wq_data *data)
{
	struct mlx5_ib_exp_create_wq ucmd = {};

	if (ib_copy_from_udata(&ucmd, udata, min(sizeof(ucmd),
						 udata->inlen))) {
		mlx5_ib_dbg(dev, "copy failed\n");
		return -EFAULT;
	}

	data->buf_addr = ucmd.buf_addr;
	data->db_addr = ucmd.db_addr;
	data->rq_wqe_count = ucmd.rq_wqe_count;
	data->rq_wqe_shift = ucmd.rq_wqe_shift;
	data->user_index = ucmd.user_index;
	data->flags = ucmd.flags;
	data->comp_mask = ucmd.comp_mask;

	if (ucmd.comp_mask & MLX5_EXP_CREATE_WQ_MP_RQ) {
		if (!MLX5_CAP_GEN(dev->mdev, striding_rq))
			return -EOPNOTSUPP;

		if (ucmd.mp_rq.use_shift & ~IB_MP_RQ_2BYTES_SHIFT ||
		    ucmd.mp_rq.single_stride_log_num_of_bytes < MLX5_MIN_SINGLE_STRIDE_LOG_NUM_BYTES ||
		    ucmd.mp_rq.single_stride_log_num_of_bytes > MLX5_MAX_SINGLE_STRIDE_LOG_NUM_BYTES ||
		    ucmd.mp_rq.single_wqe_log_num_of_strides < MLX5_MIN_SINGLE_WQE_LOG_NUM_STRIDES ||
		    ucmd.mp_rq.single_wqe_log_num_of_strides > MLX5_MAX_SINGLE_WQE_LOG_NUM_STRIDES)
			return -EINVAL;

		data->mp_rq.use_shift = ucmd.mp_rq.use_shift;
		data->mp_rq.single_wqe_log_num_of_strides =
			ucmd.mp_rq.single_wqe_log_num_of_strides;
		data->mp_rq.single_stride_log_num_of_bytes =
			ucmd.mp_rq.single_stride_log_num_of_bytes;
	}

	if (ucmd.comp_mask & MLX5_EXP_CREATE_WQ_VLAN_OFFLOADS) {
		if ((ucmd.vlan_offloads & IB_WQ_CVLAN_STRIPPING) &&
		    (!(MLX5_CAP_GEN(dev->mdev, eth_net_offloads) &&
		       MLX5_CAP_ETH(dev->mdev, vlan_cap))))
			return -EOPNOTSUPP;
		data->vlan_offloads = ucmd.vlan_offloads;
	}

	if ((ucmd.flags & MLX5_EXP_WQ_FLAG_RX_END_PADDING) &&
	    !(MLX5_CAP_GEN(dev->mdev, end_pad)))
		return -EOPNOTSUPP;

	if ((ucmd.flags & MLX5_EXP_WQ_FLAG_SCATTER_FCS) &&
	    (!MLX5_CAP_GEN(dev->mdev, eth_net_offloads) ||
	     !MLX5_CAP_ETH(dev->mdev, scatter_fcs)))
		return -EOPNOTSUPP;

	return 0;
}

void mlx5_ib_exp_set_rq_attr(struct mlx5_ib_create_wq_data *data,
			     struct mlx5_ib_rwq *rwq)
{
	if (data->comp_mask & MLX5_EXP_CREATE_WQ_MP_RQ) {
		rwq->mp_rq.single_wqe_log_num_of_strides =
			data->mp_rq.single_wqe_log_num_of_strides;
		rwq->mp_rq.single_stride_log_num_of_bytes =
			data->mp_rq.single_stride_log_num_of_bytes;
		rwq->mp_rq.use_shift = data->mp_rq.use_shift;
		rwq->mp_rq.use_mp_rq = 1;
	}
	if (data->comp_mask & MLX5_EXP_CREATE_WQ_VLAN_OFFLOADS)
		rwq->vlan_offloads = data->vlan_offloads;

	rwq->flags = data->flags;
}

void mlx5_ib_exp_set_rqc(void *rqc, struct mlx5_ib_rwq *rwq)
{
	void *wq;

	wq = MLX5_ADDR_OF(rqc, rqc, wq);
	if (rwq->mp_rq.use_mp_rq) {
		MLX5_SET(wq, wq, wq_type, MLX5_WQ_TYPE_STRQ_CYCLIC);
		MLX5_SET(wq, wq, log_wqe_num_of_strides,
			 (rwq->mp_rq.single_wqe_log_num_of_strides -
			  MLX5_MIN_SINGLE_WQE_LOG_NUM_STRIDES));
		MLX5_SET(wq, wq, log_wqe_stride_size,
			 (rwq->mp_rq.single_stride_log_num_of_bytes -
			  MLX5_MIN_SINGLE_STRIDE_LOG_NUM_BYTES));
		if (rwq->mp_rq.use_shift == IB_MP_RQ_2BYTES_SHIFT)
			MLX5_SET(wq, wq, two_byte_shift_en, 0x1);
	}
	if (rwq->vlan_offloads & IB_WQ_CVLAN_STRIPPING)
		MLX5_SET(rqc, rqc, vsd, 0);

	if (rwq->flags & MLX5_EXP_WQ_FLAG_RX_END_PADDING)
		MLX5_SET(wq, wq, end_padding_mode, MLX5_WQ_END_PAD_MODE_ALIGN);
	else
		MLX5_SET(wq, wq, end_padding_mode, MLX5_WQ_END_PAD_MODE_NONE);

	if (rwq->flags & MLX5_EXP_WQ_FLAG_SCATTER_FCS)
		MLX5_SET(rqc, rqc, scatter_fcs, 1);
}

void mlx5_ib_exp_get_hash_parameters(struct ib_qp_init_attr *init_attr,
				     struct ib_rwq_ind_table **rwq_ind_tbl,
				     u64 *rx_hash_fields_mask,
				     u32 *ind_tbl_num,
				     u8 **rx_hash_key,
				     u8 *rx_hash_function,
				     u8 *rx_key_len)
{
	struct ib_exp_qp_init_attr *exp_init_attr =
		(struct ib_exp_qp_init_attr *)init_attr;
	struct ib_rx_hash_conf *conf = exp_init_attr->rx_hash_conf;

	*rx_hash_fields_mask = conf->rx_hash_fields_mask;
	*rwq_ind_tbl = conf->rwq_ind_tbl;
	*ind_tbl_num = conf->rwq_ind_tbl->ind_tbl_num;
	*rx_hash_key = conf->rx_hash_key;
	*rx_hash_function = conf->rx_hash_function;
	*rx_key_len = conf->rx_key_len;
}

bool mlx5_ib_exp_is_rss(struct ib_qp_init_attr *init_attr)
{
	if (((struct ib_exp_qp_init_attr *)init_attr)->rx_hash_conf)
		return true;
	return false;
}

u32 mlx5_ib_atomic_mode_qp(struct mlx5_ib_qp *qp)
{
	unsigned long mask;
	unsigned long tmp;
	struct mlx5_ib_dev *dev = to_mdev(qp->ibqp.device);

	mask = (qp->ibqp.qp_type == IB_EXP_QPT_DC_INI) ?
		MLX5_CAP_ATOMIC(dev->mdev, atomic_size_dc) :
		MLX5_CAP_ATOMIC(dev->mdev, atomic_size_qp);

	tmp = mask ? __fls(mask) : 0;
	if (tmp < 2)
		return MLX5_ATOMIC_MODE_NONE;

	if (tmp == 2)
		return MLX5_ATOMIC_MODE_CX;

	return tmp << MLX5_ATOMIC_MODE_OFF;
}

int mlx5_ib_exp_is_scat_cqe_dci(struct mlx5_ib_dev *dev,
				enum ib_sig_type sig_type,
				int scqe_sz) {
	return ((sig_type == IB_SIGNAL_ALL_WR) &&
		((scqe_sz == 128) || MLX5_CAP_GEN(dev->mdev, dc_req_scat_data_cqe)));
}

int mlx5_ib_exp_max_inl_recv(struct ib_qp_init_attr *init_attr)
{
	return ((struct ib_exp_qp_init_attr *)init_attr)->max_inl_recv;
}

struct ib_qp *mlx5_ib_exp_create_qp(struct ib_pd *pd,
				    struct ib_exp_qp_init_attr *init_attr,
				    struct ib_udata *udata)
{
	if (pd) {
		struct mlx5_ib_dev *dev;
		int use_inlr;
		int scqe_sz;
		int use_inlr_dci;

		dev = to_mdev(pd->device);

		if ((init_attr->create_flags & IB_QP_EXP_CREATE_ATOMIC_BE_REPLY) &&
		    (dev->atomic_cap != IB_ATOMIC_HCA_REPLY_BE) &&
		    mlx5_host_is_le()) {
			mlx5_ib_dbg(dev, "Create QP with atomic BE REPLY is not supported\n");
			return ERR_PTR(-EINVAL);
		}

		scqe_sz = mlx5_ib_get_cqe_size(dev, init_attr->send_cq);

		use_inlr_dci = (init_attr->qp_type == IB_EXP_QPT_DC_INI)    &&
			       init_attr->max_inl_recv			    &&
			       mlx5_ib_exp_is_scat_cqe_dci(dev,
							   init_attr->sq_sig_type,
							   scqe_sz);

		use_inlr = (init_attr->qp_type == IB_QPT_RC ||
			    init_attr->qp_type == IB_QPT_UC) &&
			    init_attr->max_inl_recv;

		if (use_inlr || use_inlr_dci) {
			int cqe_sz;

			/* DCI can receive only response messages. Hence,
			*  max_inl_recv is reported according to SCQE.
			*/
			cqe_sz = use_inlr_dci ? scqe_sz :
				mlx5_ib_get_cqe_size(dev, init_attr->recv_cq);

			if (cqe_sz == 128)
				init_attr->max_inl_recv = 64;
			else
				init_attr->max_inl_recv = 32;

		} else {
			init_attr->max_inl_recv = 0;
		}

	}

	return _mlx5_ib_create_qp(pd, (struct ib_qp_init_attr *)init_attr,
				  udata, 1);
}

static u32 atomic_mode_dct(struct mlx5_ib_dev *dev)
{
	unsigned long mask;
	unsigned long tmp;

	mask = MLX5_CAP_ATOMIC(dev->mdev, atomic_size_qp) &
	       MLX5_CAP_ATOMIC(dev->mdev, atomic_size_dc);

	tmp = find_last_bit(&mask, BITS_PER_LONG);
	if (tmp < 2)
		return MLX5_ATOMIC_MODE_DCT_NONE;

	if (tmp == 2)
		return MLX5_ATOMIC_MODE_DCT_CX;

	return tmp << MLX5_ATOMIC_MODE_DCT_OFF;
}

static u32 ib_to_dct_access(struct mlx5_ib_dev *dev, u32 ib_flags)
{
	u32 flags = 0;

	if (ib_flags & IB_ACCESS_REMOTE_READ)
		flags |= MLX5_DCT_BIT_RRE;
	if (ib_flags & IB_ACCESS_REMOTE_WRITE)
		flags |= (MLX5_DCT_BIT_RWE | MLX5_DCT_BIT_RRE);
	if (ib_flags & IB_ACCESS_REMOTE_ATOMIC) {
		flags |= (MLX5_DCT_BIT_RAE | MLX5_DCT_BIT_RWE | MLX5_DCT_BIT_RRE);
		flags |= atomic_mode_dct(dev);
	}

	return flags;
}

static void mlx5_ib_dct_event(struct mlx5_core_dct *dct, enum mlx5_event type)
{
	struct ib_dct *ibdct = &to_mibdct(dct)->ibdct;
	struct ib_event event;

	if (ibdct->event_handler) {
		event.device     = ibdct->device;
		event.element.dct = ibdct;
		switch (type) {
		case MLX5_EVENT_TYPE_WQ_INVAL_REQ_ERROR:
			event.event = IB_EXP_EVENT_DCT_REQ_ERR;
			break;
		case MLX5_EVENT_TYPE_WQ_ACCESS_ERROR:
			event.event = IB_EXP_EVENT_DCT_ACCESS_ERR;
			break;
		case MLX5_EVENT_TYPE_DCT_KEY_VIOLATION:
			event.event = IB_EXP_EVENT_DCT_KEY_VIOLATION;
			break;
		default:
			pr_warn("mlx5_ib: Unexpected event type %d on DCT %06x\n",
				type, dct->dctn);
			return;
		}

		ibdct->event_handler(&event, ibdct->dct_context);
	}
}

struct ib_dct *mlx5_ib_create_dct(struct ib_pd *pd,
				  struct ib_dct_init_attr *attr,
				  struct ib_udata *udata)
{
	u32 *in;
	int inlen = MLX5_ST_SZ_BYTES(create_dct_in);
	struct mlx5_ib_create_dct ucmd;
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_ib_dct *dct;
	void *dctc;
	int cqe_sz;
	int err;
	u32 flags = 0;
	u32 uidx = 0;
	u32 cqn;

	if (pd && pd->uobject) {
		if (ib_copy_from_udata(&ucmd, udata, sizeof(ucmd))) {
			mlx5_ib_err(dev, "copy failed\n");
			return ERR_PTR(-EFAULT);
		}

		if (udata->inlen)
			uidx = ucmd.uidx;
		else
			uidx = 0xffffff;
	} else {
		uidx = 0xffffff;
	}

	dct = kzalloc(sizeof(*dct), GFP_KERNEL);
	if (!dct)
		return ERR_PTR(-ENOMEM);

	in = kzalloc(inlen, GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_alloc;
	}

	dctc = MLX5_ADDR_OF(create_dct_in, in, dct_context_entry);
	cqn = to_mcq(attr->cq)->mcq.cqn;
	if (cqn & 0xff000000) {
		mlx5_ib_warn(dev, "invalid cqn 0x%x\n", cqn);
		err = -EINVAL;
		goto err_alloc;
	}

	MLX5_SET(dctc, dctc, cqn, cqn);

	flags = ib_to_dct_access(dev, attr->access_flags);
	if (flags & MLX5_DCT_BIT_RRE)
		MLX5_SET(dctc, dctc, rre, 1);
	if (flags & MLX5_DCT_BIT_RWE)
		MLX5_SET(dctc, dctc, rwe, 1);
	if (flags & MLX5_DCT_BIT_RAE) {
		MLX5_SET(dctc, dctc, rae, 1);
		MLX5_SET(dctc, dctc, atomic_mode,
			 flags >> MLX5_ATOMIC_MODE_DCT_OFF);
	}

	if (attr->inline_size) {
		cqe_sz = mlx5_ib_get_cqe_size(dev, attr->cq);
		if (cqe_sz == 128) {
			MLX5_SET(dctc, dctc, cs_res, MLX5_DCT_CS_RES_64);
			attr->inline_size = 64;
		} else {
			attr->inline_size = 0;
		}
	}

	MLX5_SET(dctc, dctc, min_rnr_nak , attr->min_rnr_timer);
	MLX5_SET(dctc, dctc, srqn_xrqn , to_msrq(attr->srq)->msrq.srqn);
	MLX5_SET(dctc, dctc, pd , to_mpd(pd)->pdn);
	MLX5_SET(dctc, dctc, tclass, attr->tclass);
	MLX5_SET(dctc, dctc, flow_label , attr->flow_label);
	MLX5_SET64(dctc, dctc, dc_access_key , attr->dc_key);
	MLX5_SET(dctc, dctc, mtu , attr->mtu);
	MLX5_SET(dctc, dctc, port , attr->port);
	MLX5_SET(dctc, dctc, pkey_index , attr->pkey_index);
	MLX5_SET(dctc, dctc, my_addr_index , attr->gid_index);
	MLX5_SET(dctc, dctc, hop_limit , attr->hop_limit);

	if (MLX5_CAP_GEN(dev->mdev, cqe_version)) {
		/* 0xffffff means we ask to work with cqe version 0 */
		MLX5_SET(dctc, dctc, user_index, uidx);
	}

	err = mlx5_core_create_dct(dev->mdev, &dct->mdct, in);
	if (err)
		goto err_alloc;

	dct->ibdct.dct_num = dct->mdct.dctn;
	dct->mdct.event = mlx5_ib_dct_event;
	kfree(in);
	return &dct->ibdct;

err_alloc:
	kfree(in);
	kfree(dct);
	return ERR_PTR(err);
}

int mlx5_ib_destroy_dct(struct ib_dct *dct)
{
	struct mlx5_ib_dev *dev = to_mdev(dct->device);
	struct mlx5_ib_dct *mdct = to_mdct(dct);
	int err;

	err = mlx5_core_destroy_dct(dev->mdev, &mdct->mdct);
	if (!err)
		kfree(mdct);

	return err;
}

int dct_to_ib_access(u32 dc_flags)
{
	u32 flags = 0;

	if (dc_flags & MLX5_DCT_BIT_RRE)
		flags |= IB_ACCESS_REMOTE_READ;
	if (dc_flags & MLX5_QP_BIT_RWE)
		flags |= IB_ACCESS_REMOTE_WRITE;
	if ((dc_flags & MLX5_ATOMIC_MODE_CX) == MLX5_ATOMIC_MODE_CX)
		flags |= IB_ACCESS_REMOTE_ATOMIC;

	return flags;
}

int mlx5_ib_query_dct(struct ib_dct *dct, struct ib_dct_attr *attr)
{
	struct mlx5_ib_dev *dev = to_mdev(dct->device);
	struct mlx5_ib_dct *mdct = to_mdct(dct);
	u32 dc_flags = 0;
	u32 *out;
	int outlen = MLX5_ST_SZ_BYTES(query_dct_out);
	void *dctc;
	int err;

	out = kzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = mlx5_core_dct_query(dev->mdev, &mdct->mdct, out, outlen);
	if (err)
		goto out;

	dctc = MLX5_ADDR_OF(query_dct_out, out, dct_context_entry);

	if (MLX5_GET(dctc, dctc, rre))
		dc_flags |= MLX5_DCT_BIT_RRE;
	if (MLX5_GET(dctc, dctc, rwe))
		dc_flags |= MLX5_DCT_BIT_RWE;
	if (MLX5_GET(dctc, dctc, rae))
		dc_flags |= MLX5_DCT_BIT_RAE;

	attr->dc_key = MLX5_GET64(dctc, dctc, dc_access_key);
	attr->port = MLX5_GET(dctc, dctc, port);
	attr->access_flags = dct_to_ib_access(dc_flags);
	attr->min_rnr_timer = MLX5_GET(dctc, dctc, min_rnr_nak);
	attr->tclass = MLX5_GET(dctc, dctc, tclass);
	attr->flow_label = MLX5_GET(dctc, dctc, flow_label);
	attr->mtu = MLX5_GET(dctc, dctc, mtu);
	attr->pkey_index = MLX5_GET(dctc, dctc, pkey_index);
	attr->gid_index = MLX5_GET(dctc, dctc, my_addr_index);
	attr->hop_limit = MLX5_GET(dctc, dctc, hop_limit);
	attr->key_violations = MLX5_GET(dctc, dctc,
					dc_access_key_violation_count);
	attr->state = MLX5_GET(dctc, dctc, state);

out:
	kfree(out);
	return err;
}

int mlx5_ib_arm_dct(struct ib_dct *dct, struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(dct->device);
	struct mlx5_ib_dct *mdct = to_mdct(dct);
	struct mlx5_ib_arm_dct ucmd;
	struct mlx5_ib_arm_dct_resp resp;
	int err;

	err = ib_copy_from_udata(&ucmd, udata, sizeof(ucmd));
	if (err) {
		mlx5_ib_err(dev, "copy failed\n");
		return err;
	}

	if (ucmd.reserved0 || ucmd.reserved1)
		return -EINVAL;

	err = mlx5_core_arm_dct(dev->mdev, &mdct->mdct);
	if (err)
		goto out;

	memset(&resp, 0, sizeof(resp));
	err = ib_copy_to_udata(udata, &resp, sizeof(resp));
	if (err)
		mlx5_ib_err(dev, "copy failed\n");

out:
	return err;
}

void mlx5_ib_set_mlx_seg(struct mlx5_mlx_seg *seg, struct mlx5_mlx_wr *wr)
{
	memset(seg, 0, sizeof(*seg));
	seg->stat_rate_sl = wr->sl & 0xf;
	seg->dlid = cpu_to_be16(wr->dlid);
	seg->flags = wr->icrc ? 8 : 0;
}
