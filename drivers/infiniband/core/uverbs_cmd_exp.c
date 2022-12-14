/*
 * Copyright (c) 2015 Mellanox Technologies.  All rights reserved.
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

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/moduleparam.h>
#include <linux/printk.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_umem_odp.h>
#include <linux/sched.h>

#include <asm/uaccess.h>
#include <linux/sched.h>

#include "uverbs.h"
#include "uverbs_exp.h"
#include "core_priv.h"

static struct uverbs_lock_class dct_lock_class	= { .name = "DCT-uobj" };

int ib_uverbs_exp_create_flow(struct ib_uverbs_file *file,
			      struct ib_device *ib_dev,
			      struct ib_udata *ucore,
			      struct ib_udata *uhw)
{
	return ib_uverbs_create_flow_common(file, ib_dev, ucore, uhw, true);
}

int ib_uverbs_exp_create_qp(struct ib_uverbs_file *file, struct ib_device *ib_dev,
			    struct ib_udata *ucore, struct ib_udata *uhw)
{
	struct ib_uqp_object           *obj;
	struct ib_device	       *device;
	struct ib_pd                   *pd = NULL;
	struct ib_xrcd		       *xrcd = NULL;
	struct ib_uobject	       *uninitialized_var(xrcd_uobj);
	struct ib_cq                   *scq = NULL, *rcq = NULL;
	struct ib_srq                  *srq = NULL;
	struct ib_qp                   *qp;
	struct ib_qp                   *parentqp = NULL;
	struct ib_exp_qp_init_attr     *attr;
	struct ib_uverbs_exp_create_qp *cmd_exp;
	struct ib_uverbs_exp_create_qp_resp resp_exp;
	int                             ret;
	struct ib_rx_hash_conf	rx_hash_conf;
	struct ib_rwq_ind_table *ind_tbl = NULL;
	int rx_qp = 0;
	int i;

	cmd_exp = kzalloc(sizeof(*cmd_exp), GFP_KERNEL);
	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!cmd_exp || !attr) {
		ret = -ENOMEM;
		goto err_cmd_attr;
	}

	ret = ib_copy_from_udata(cmd_exp, ucore, sizeof(*cmd_exp));
	if (ret)
		goto err_cmd_attr;

	if (!disable_raw_qp_enforcement &&
	    cmd_exp->qp_type == IB_QPT_RAW_PACKET && !capable(CAP_NET_RAW)) {
		ret = -EPERM;
		goto err_cmd_attr;
	}

	for (i = 0; i < sizeof(cmd_exp->reserved3); i++) {
		if (cmd_exp->reserved3[i] != 0) {
			ret = -EINVAL;
			goto err_cmd_attr;
		}
	}

	obj = kzalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj) {
		ret = -ENOMEM;
		goto err_cmd_attr;
	}

	init_uobj(&obj->uevent.uobject, cmd_exp->user_handle, file->ucontext,
		  &qp_lock_class);
	down_write(&obj->uevent.uobject.mutex);
	rx_qp = cmd_exp->rx_hash_conf.rx_hash_function ? 1 : 0;

	if (cmd_exp->qp_type == IB_QPT_XRC_TGT) {
		xrcd = idr_read_xrcd(cmd_exp->pd_handle, file->ucontext, &xrcd_uobj);
		if (!xrcd) {
			ret = -EINVAL;
			goto err_put;
		}
		device = xrcd->device;
	} else {
		if (cmd_exp->qp_type == IB_QPT_XRC_INI ||
		    cmd_exp->qp_type == IB_EXP_QPT_DC_INI) {
			cmd_exp->max_recv_wr = 0;
			cmd_exp->max_recv_sge = 0;
		} else {
			if (cmd_exp->is_srq) {
				srq = idr_read_srq(cmd_exp->srq_handle, file->ucontext);
				if (!srq || srq->srq_type != IB_SRQT_BASIC) {
					ret = -EINVAL;
					goto err_put;
				}
			}

			if (cmd_exp->recv_cq_handle != cmd_exp->send_cq_handle) {
				rcq = idr_read_cq(cmd_exp->recv_cq_handle, file->ucontext, 0);
				if (!rcq) {
					ret = -EINVAL;
					goto err_put;
				}
			}
		}

		if (!rx_qp)
			scq = idr_read_cq(cmd_exp->send_cq_handle, file->ucontext, !!rcq);
		rcq = rcq ?: scq;
		pd  = idr_read_pd(cmd_exp->pd_handle, file->ucontext);
		if (!pd || (!scq && !rx_qp)) {
			ret = -EINVAL;
			goto err_put;
		}

		device = pd->device;
	}

	attr->event_handler = ib_uverbs_qp_event_handler;
	attr->qp_context    = file;
	attr->send_cq       = scq;
	attr->recv_cq       = rcq;
	attr->srq           = srq;
	attr->xrcd	   = xrcd;
	attr->sq_sig_type   = cmd_exp->sq_sig_all ? IB_SIGNAL_ALL_WR : IB_SIGNAL_REQ_WR;
	attr->qp_type       = cmd_exp->qp_type;
	attr->create_flags  = 0;

	attr->cap.max_send_wr     = cmd_exp->max_send_wr;
	attr->cap.max_recv_wr     = cmd_exp->max_recv_wr;
	attr->cap.max_send_sge    = cmd_exp->max_send_sge;
	attr->cap.max_recv_sge    = cmd_exp->max_recv_sge;
	attr->cap.max_inline_data = cmd_exp->max_inline_data;
	attr->rx_hash_conf = NULL;

	if (cmd_exp->comp_mask & IB_UVERBS_EXP_CREATE_QP_CAP_FLAGS) {
		if (cmd_exp->qp_cap_flags & ~IBV_UVERBS_EXP_CREATE_QP_FLAGS) {
			ret = -EINVAL;
			goto err_put;
		}

		attr->create_flags |= cmd_exp->qp_cap_flags;

		/* convert user requset to kernel matching creation flag */

		if (attr->create_flags & IB_QP_EXP_USER_CREATE_ATOMIC_BE_REPLY) {
			attr->create_flags &= ~IB_QP_EXP_USER_CREATE_ATOMIC_BE_REPLY;
			attr->create_flags |= IB_QP_EXP_CREATE_ATOMIC_BE_REPLY;
		}
		if (attr->create_flags & IB_QP_EXP_USER_CREATE_RX_END_PADDING) {
			attr->create_flags &= ~IB_QP_EXP_USER_CREATE_RX_END_PADDING;
			attr->create_flags |= IB_QP_EXP_CREATE_RX_END_PADDING;
		}

		if (attr->create_flags & IB_QP_EXP_USER_CREATE_SCATTER_FCS) {
			attr->create_flags &= ~IB_QP_EXP_USER_CREATE_SCATTER_FCS;
			attr->create_flags |= IB_QP_CREATE_SCATTER_FCS;
		}
	}

	if (cmd_exp->comp_mask & IB_UVERBS_EXP_CREATE_QP_QPG) {
		struct ib_uverbs_qpg *qpg;

		if (cmd_exp->qp_type != IB_QPT_RAW_PACKET &&
		    cmd_exp->qp_type != IB_QPT_UD) {
			ret = -EINVAL;
			goto err_put;
		}
		qpg = &cmd_exp->qpg;
		switch (qpg->qpg_type) {
		case IB_QPG_PARENT:
			attr->parent_attrib.rss_child_count =
				qpg->parent_attrib.rss_child_count;
			attr->parent_attrib.tss_child_count =
				qpg->parent_attrib.tss_child_count;
			break;
		case IB_QPG_CHILD_RX:
		case IB_QPG_CHILD_TX:
			parentqp = idr_read_qp(qpg->parent_handle,
					       file->ucontext);
			if (!parentqp) {
				ret = -EINVAL;
				goto err_put;
			}
			attr->qpg_parent = parentqp;
			break;
		default:
			ret = -EINVAL;
			goto err_put;
		}
		attr->qpg_type = qpg->qpg_type;
	}

	if (cmd_exp->comp_mask & IB_UVERBS_EXP_CREATE_QP_INL_RECV)
		attr->max_inl_recv = cmd_exp->max_inl_recv;

	/* No comp mask bit is needed, the value of rx_hash_function is used */
	if (cmd_exp->rx_hash_conf.rx_hash_function) {
		ind_tbl = idr_read_rwq_indirection_table(cmd_exp->rx_hash_conf.rwq_ind_tbl_handle,
							 file->ucontext);
		if (!ind_tbl) {
			ret = -EINVAL;
			goto err_put;
		}
		rx_hash_conf.rwq_ind_tbl = ind_tbl;
		rx_hash_conf.rx_hash_fields_mask = cmd_exp->rx_hash_conf.rx_hash_fields_mask;
		rx_hash_conf.rx_hash_function = cmd_exp->rx_hash_conf.rx_hash_function;
		rx_hash_conf.rx_hash_key = cmd_exp->rx_hash_conf.rx_hash_key;
		rx_hash_conf.rx_key_len = cmd_exp->rx_hash_conf.rx_key_len;
		attr->rx_hash_conf = &rx_hash_conf;
	}

	attr->port_num = cmd_exp->port_num;
	obj->uevent.events_reported     = 0;
	INIT_LIST_HEAD(&obj->uevent.event_list);
	INIT_LIST_HEAD(&obj->mcast_list);

	if (cmd_exp->qp_type == IB_QPT_XRC_TGT)
		qp = ib_create_qp(pd, (struct ib_qp_init_attr *)attr);
	else
		qp = device->exp_create_qp(pd, attr, uhw);

	if (IS_ERR(qp)) {
		ret = PTR_ERR(qp);
		goto err_put;
	}

	if (cmd_exp->qp_type != IB_QPT_XRC_TGT) {
		qp->real_qp	  = qp;
		qp->device	  = device;
		qp->pd		  = pd;
		qp->send_cq	  = attr->send_cq;
		qp->recv_cq	  = attr->recv_cq;
		qp->srq		  = attr->srq;
		qp->rwq_ind_tbl   = ind_tbl;
		qp->event_handler = attr->event_handler;
		qp->qp_context	  = attr->qp_context;
		qp->qp_type	  = attr->qp_type;
		atomic_set(&qp->usecnt, 0);
		atomic_inc(&pd->usecnt);
		if (!rx_qp)
			atomic_inc(&attr->send_cq->usecnt);
		if (attr->recv_cq)
			atomic_inc(&attr->recv_cq->usecnt);
		if (attr->srq)
			atomic_inc(&attr->srq->usecnt);
		if (ind_tbl)
			atomic_inc(&ind_tbl->usecnt);
	}
	qp->uobject = &obj->uevent.uobject;

	obj->uevent.uobject.object = qp;
	ret = idr_add_uobj(&ib_uverbs_qp_idr, &obj->uevent.uobject);
	if (ret)
		goto err_destroy;

	memset(&resp_exp, 0, sizeof(resp_exp));
	resp_exp.qpn             = qp->qp_num;
	resp_exp.qp_handle       = obj->uevent.uobject.id;
	resp_exp.max_recv_sge    = attr->cap.max_recv_sge;
	resp_exp.max_send_sge    = attr->cap.max_send_sge;
	resp_exp.max_recv_wr     = attr->cap.max_recv_wr;
	resp_exp.max_send_wr     = attr->cap.max_send_wr;
	resp_exp.max_inline_data = attr->cap.max_inline_data;

	if (cmd_exp->comp_mask & IB_UVERBS_EXP_CREATE_QP_INL_RECV) {
		resp_exp.comp_mask |= IB_UVERBS_EXP_CREATE_QP_RESP_INL_RECV;
		resp_exp.max_inl_recv = attr->max_inl_recv;
	}

	ret = ib_copy_to_udata(ucore, &resp_exp, sizeof(resp_exp));
	if (ret)
		goto err_copy;

	if (xrcd) {
		obj->uxrcd = container_of(xrcd_uobj, struct ib_uxrcd_object, uobject);
		atomic_inc(&obj->uxrcd->refcnt);
		put_xrcd_read(xrcd_uobj);
	}

	if (pd)
		put_pd_read(pd);
	if (scq)
		put_cq_read(scq);
	if (rcq && rcq != scq)
		put_cq_read(rcq);
	if (srq)
		put_srq_read(srq);
	if (parentqp)
		put_qp_read(parentqp);
	if (ind_tbl)
		put_rwq_indirection_table_read(ind_tbl);

	mutex_lock(&file->mutex);
	list_add_tail(&obj->uevent.uobject.list, &file->ucontext->qp_list);
	mutex_unlock(&file->mutex);

	obj->uevent.uobject.live = 1;

	up_write(&obj->uevent.uobject.mutex);
	kfree(attr);
	kfree(cmd_exp);

	return 0;

err_copy:
	idr_remove_uobj(&ib_uverbs_qp_idr, &obj->uevent.uobject);

err_destroy:
	ib_destroy_qp(qp);

err_put:
	if (xrcd)
		put_xrcd_read(xrcd_uobj);
	if (pd)
		put_pd_read(pd);
	if (scq)
		put_cq_read(scq);
	if (rcq && rcq != scq)
		put_cq_read(rcq);
	if (srq)
		put_srq_read(srq);
	if (parentqp)
		put_qp_read(parentqp);
	if (ind_tbl)
		put_rwq_indirection_table_read(ind_tbl);

	put_uobj_write(&obj->uevent.uobject);

err_cmd_attr:
	kfree(attr);
	kfree(cmd_exp);
	return ret;
}

int ib_uverbs_exp_modify_cq(struct ib_uverbs_file *file, struct ib_device *ib_dev,
			    struct ib_udata *ucore, struct ib_udata *uhw)
{
	struct ib_uverbs_exp_modify_cq cmd;
	struct ib_cq               *cq;
	struct ib_cq_attr           attr;
	int                         ret;

	memset(&cmd, 0, sizeof(cmd));
	ret = ib_copy_from_udata(&cmd, ucore, sizeof(cmd));
	if (ret)
		return ret;

	if (cmd.comp_mask >= IB_UVERBS_EXP_CQ_ATTR_RESERVED)
		return -ENOSYS;

	cq = idr_read_cq(cmd.cq_handle, file->ucontext, 0);
	if (!cq)
		return -EINVAL;

	attr.moderation.cq_count  = cmd.cq_count;
	attr.moderation.cq_period = cmd.cq_period;
	attr.cq_cap_flags         = cmd.cq_cap_flags;

	ret = ib_exp_modify_cq(cq, &attr, cmd.attr_mask);

	put_cq_read(cq);

	return ret;
}

int ib_uverbs_exp_query_device(struct ib_uverbs_file *file,
			       struct ib_device *ib_dev,
			       struct ib_udata *ucore, struct ib_udata *uhw)
{
	struct ib_uverbs_exp_query_device_resp *resp;
	struct ib_uverbs_exp_query_device cmd;
	struct ib_exp_device_attr              *exp_attr;
	int                                    ret;

	ret = ib_copy_from_udata(&cmd, ucore, sizeof(cmd));
	if (ret)
		return ret;

	resp = kzalloc(sizeof(*resp), GFP_KERNEL);
	exp_attr = kzalloc(sizeof(*exp_attr), GFP_KERNEL);
	if (!exp_attr || !resp) {
		ret = -ENOMEM;
		goto out;
	}

	ret = ib_exp_query_device(file->device->ib_dev, exp_attr, uhw);
	if (ret)
		goto out;

	memset(resp, 0, sizeof(*resp));
	copy_query_dev_fields(file, ib_dev, &resp->base, &exp_attr->base);

	resp->comp_mask = 0;
	resp->device_cap_flags2 = 0;

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_WITH_TIMESTAMP_MASK) {
		resp->timestamp_mask = exp_attr->base.timestamp_mask;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_WITH_TIMESTAMP_MASK;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_WITH_HCA_CORE_CLOCK) {
		resp->hca_core_clock = exp_attr->base.hca_core_clock;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_WITH_HCA_CORE_CLOCK;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_DC_REQ_RD) {
		resp->dc_rd_req = exp_attr->dc_rd_req;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_DC_REQ_RD;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_DC_RES_RD) {
		resp->dc_rd_res = exp_attr->dc_rd_res;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_DC_RES_RD;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_MAX_DCT) {
		resp->max_dct = exp_attr->max_dct;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_MAX_DCT;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_MAX_DEVICE_CTX) {
		resp->max_device_ctx = exp_attr->max_device_ctx;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_MAX_DEVICE_CTX;
	}

	/* Handle experimental attr fields */
	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_CAP_FLAGS2 ||
	    exp_attr->base.device_cap_flags & IB_EXP_DEVICE_MASK) {
		resp->device_cap_flags2 = exp_attr->device_cap_flags2;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_CAP_FLAGS2;
		resp->device_cap_flags2 |= IB_EXP_DEVICE_MASK & exp_attr->base.device_cap_flags;
		resp->base.device_cap_flags &= ~IB_EXP_DEVICE_MASK;
		if (resp->device_cap_flags2 & IB_DEVICE_CROSS_CHANNEL) {
			resp->device_cap_flags2 &= ~IB_DEVICE_CROSS_CHANNEL;
			resp->device_cap_flags2 |= IB_EXP_DEVICE_CROSS_CHANNEL;
		}
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_RSS_TBL_SZ) {
		resp->max_rss_tbl_sz = exp_attr->max_rss_tbl_sz;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_RSS_TBL_SZ;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_UMR) {
		resp->umr_caps.max_reg_descriptors = exp_attr->umr_caps.max_reg_descriptors;
		resp->umr_caps.max_send_wqe_inline_klms = exp_attr->umr_caps.max_send_wqe_inline_klms;
		resp->umr_caps.max_umr_recursion_depth = exp_attr->umr_caps.max_umr_recursion_depth;
		resp->umr_caps.max_umr_stride_dimenson = exp_attr->umr_caps.max_umr_stride_dimenson;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_UMR;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_ODP) {
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_ODP;
		resp->odp_caps.general_odp_caps = exp_attr->odp_caps.general_odp_caps;
		resp->odp_caps.per_transport_caps.rc_odp_caps =
			exp_attr->odp_caps.per_transport_caps.rc_odp_caps;
		resp->odp_caps.per_transport_caps.uc_odp_caps =
			exp_attr->odp_caps.per_transport_caps.uc_odp_caps;
		resp->odp_caps.per_transport_caps.ud_odp_caps =
			exp_attr->odp_caps.per_transport_caps.ud_odp_caps;
		resp->odp_caps.per_transport_caps.dc_odp_caps =
			exp_attr->odp_caps.per_transport_caps.dc_odp_caps;
		resp->odp_caps.per_transport_caps.xrc_odp_caps =
			exp_attr->odp_caps.per_transport_caps.xrc_odp_caps;
		resp->odp_caps.per_transport_caps.raw_eth_odp_caps =
			exp_attr->odp_caps.per_transport_caps.raw_eth_odp_caps;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_INLINE_RECV_SZ) {
		resp->inline_recv_sz = exp_attr->inline_recv_sz;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_INLINE_RECV_SZ;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_EXT_ATOMIC_ARGS) {
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_EXT_ATOMIC_ARGS;
		resp->atomic_arg_sizes = exp_attr->atomic_arg_sizes;
		resp->max_fa_bit_boudary = exp_attr->max_fa_bit_boudary;
		resp->log_max_atomic_inline_arg = exp_attr->log_max_atomic_inline_arg;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_MAX_CTX_RES_DOMAIN) {
		resp->max_ctx_res_domain = exp_attr->max_ctx_res_domain;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_MAX_CTX_RES_DOMAIN;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_EXT_MASKED_ATOMICS) {
		struct ib_uverbs_exp_masked_atomic_caps *resp_atom;
		struct ib_exp_masked_atomic_caps *atom_caps;

		resp_atom = &resp->masked_atomic_caps;
		atom_caps = &exp_attr->masked_atomic_caps;
		resp_atom->masked_log_atomic_arg_sizes =
			atom_caps->masked_log_atomic_arg_sizes;
		resp_atom->masked_log_atomic_arg_sizes_network_endianness =
			atom_caps->masked_log_atomic_arg_sizes_network_endianness;
		resp_atom->max_fa_bit_boudary = exp_attr->max_fa_bit_boudary;
		resp_atom->log_max_atomic_inline_arg =
			exp_attr->log_max_atomic_inline_arg;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_EXT_MASKED_ATOMICS;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_TSO_CAPS) {
		resp->tso_caps.max_tso = exp_attr->tso_caps.max_tso;
		resp->tso_caps.supported_qpts = exp_attr->tso_caps.supported_qpts;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_TSO_CAPS;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_MAX_DEVICE_CTX) {
		resp->max_device_ctx = exp_attr->max_device_ctx;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_MAX_DEVICE_CTX;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_MAX_WQ_TYPE_RQ) {
		resp->max_wq_type_rq = exp_attr->max_wq_type_rq;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_MAX_WQ_TYPE_RQ;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_RX_HASH) {
		resp->rx_hash.max_rwq_indirection_tables = exp_attr->rx_hash_caps.max_rwq_indirection_tables;
		resp->rx_hash.max_rwq_indirection_table_size = exp_attr->rx_hash_caps.max_rwq_indirection_table_size;
		resp->rx_hash.supported_packet_fields = exp_attr->rx_hash_caps.supported_packet_fields;
		resp->rx_hash.supported_qps = exp_attr->rx_hash_caps.supported_qps;
		resp->rx_hash.supported_hash_functions = exp_attr->rx_hash_caps.supported_hash_functions;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_RX_HASH;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_MP_RQ) {
		resp->mp_rq_caps.allowed_shifts =  exp_attr->mp_rq_caps.allowed_shifts;
		resp->mp_rq_caps.supported_qps =  exp_attr->mp_rq_caps.supported_qps;
		resp->mp_rq_caps.max_single_stride_log_num_of_bytes =  exp_attr->mp_rq_caps.max_single_stride_log_num_of_bytes;
		resp->mp_rq_caps.min_single_stride_log_num_of_bytes =  exp_attr->mp_rq_caps.min_single_stride_log_num_of_bytes;
		resp->mp_rq_caps.max_single_wqe_log_num_of_strides =  exp_attr->mp_rq_caps.max_single_wqe_log_num_of_strides;
		resp->mp_rq_caps.min_single_wqe_log_num_of_strides =  exp_attr->mp_rq_caps.min_single_wqe_log_num_of_strides;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_MP_RQ;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_VLAN_OFFLOADS) {
		resp->vlan_offloads = exp_attr->vlan_offloads;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_VLAN_OFFLOADS;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_RX_PAD_END_ALIGN) {
		resp->rx_pad_end_addr_align = exp_attr->rx_pad_end_addr_align;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_RX_PAD_END_ALIGN;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_EC_CAPS) {
		resp->ec_caps.max_ec_data_vector_count =
				exp_attr->ec_caps.max_ec_data_vector_count;
		resp->ec_caps.max_ec_calc_inflight_calcs =
				exp_attr->ec_caps.max_ec_calc_inflight_calcs;
		resp->ec_w_mask = exp_attr->ec_w_mask;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_EC_CAPS;
	}

	if (exp_attr->exp_comp_mask & IB_EXP_DEVICE_ATTR_PACKET_PACING_CAPS) {
		resp->packet_pacing_caps.qp_rate_limit_min =
			exp_attr->packet_pacing_caps.qp_rate_limit_min;
		resp->packet_pacing_caps.qp_rate_limit_max =
			exp_attr->packet_pacing_caps.qp_rate_limit_max;
		resp->packet_pacing_caps.supported_qpts =
			exp_attr->packet_pacing_caps.supported_qpts;
		resp->comp_mask |= IB_EXP_DEVICE_ATTR_PACKET_PACING_CAPS;
	}

	ret = ib_copy_to_udata(ucore, resp, min_t(size_t, sizeof(*resp), ucore->outlen));
out:
	kfree(exp_attr);
	kfree(resp);
	return ret;
}

int ib_uverbs_exp_create_mr(struct ib_uverbs_file *file,
			    struct ib_device *ib_dev,
			    struct ib_udata *ucore,
			    struct ib_udata *uhw)
{
	struct ib_uverbs_exp_create_mr          cmd_exp;
	struct ib_uverbs_exp_create_mr_resp     resp_exp;
	struct ib_pd                            *pd = NULL;
	struct ib_mr                            *mr = NULL;
	struct ib_uobject                       *uobj = NULL;
	int ret;

	if (ucore->outlen + uhw->outlen < sizeof(resp_exp))
		return -ENOSPC;

	ret = ib_copy_from_udata(&cmd_exp, ucore, sizeof(cmd_exp));
	if (ret)
		return ret;

	uobj = kmalloc(sizeof(*uobj), GFP_KERNEL);
	if (!uobj)
		return -ENOMEM;

	init_uobj(uobj, 0, file->ucontext, &mr_lock_class);
	down_write(&uobj->mutex);

	pd = idr_read_pd(cmd_exp.pd_handle, file->ucontext);
	if (!pd) {
		ret = -EINVAL;
		goto err_free;
	}
	/* We first get a new "obj id" to be passed later to reg mr for
	 * further use as mr_id.
	 */
	ret = idr_add_uobj(&ib_uverbs_mr_idr, uobj);
	if (ret)
		goto err_put;

	mr = ib_alloc_mr(pd, cmd_exp.create_flags, cmd_exp.max_reg_descriptors);
	if (IS_ERR(mr)) {
		ret = PTR_ERR(mr);
		goto err_remove_uobj;
	}

	mr->device  = pd->device;
	mr->pd      = pd;
	mr->uobject = uobj;

	uobj->object = mr;

	memset(&resp_exp, 0, sizeof(resp_exp));
	resp_exp.lkey = mr->lkey;
	resp_exp.rkey = mr->rkey;
	resp_exp.handle = uobj->id;

	ret = ib_copy_to_udata(ucore, &resp_exp, sizeof(resp_exp));
	if (ret)
		goto err_copy;

	put_pd_read(pd);

	mutex_lock(&file->mutex);
	list_add_tail(&uobj->list, &file->ucontext->mr_list);
	mutex_unlock(&file->mutex);

	uobj->live = 1;

	up_write(&uobj->mutex);

	return 0;

err_copy:
	ib_dereg_mr(mr);

err_remove_uobj:
	idr_remove_uobj(&ib_uverbs_mr_idr, uobj);

err_put:
	put_pd_read(pd);

err_free:
	put_uobj_write(uobj);
	return ret;
}

static struct ib_mr *idr_read_mr(int mr_handle, struct ib_ucontext *context)
{
	return idr_read_obj(&ib_uverbs_mr_idr, mr_handle, context, 0);
}

static void put_mr_read(struct ib_mr *mr)
{
	put_uobj_read(mr->uobject);
}

int ib_uverbs_exp_query_mkey(struct ib_uverbs_file *file,
			     struct ib_device *ib_dev,
			     struct ib_udata *ucore,
			     struct ib_udata *uhw)
{
	struct ib_uverbs_exp_query_mkey cmd_exp;
	struct ib_uverbs_exp_query_mkey_resp resp_exp;
	struct ib_mr *mr;
	struct ib_mkey_attr mkey_attr;
	int ret;

	memset(&cmd_exp, 0, sizeof(cmd_exp));
	ret = ib_copy_from_udata(&cmd_exp, ucore, sizeof(cmd_exp));
	if (ret)
		return ret;

	mr = idr_read_mr(cmd_exp.handle, file->ucontext);
	if (!mr)
		return -EINVAL;

	ret = ib_exp_query_mkey(mr, 0, &mkey_attr);
	if (ret)
		return ret;

	put_mr_read(mr);

	memset(&resp_exp, 0, sizeof(resp_exp));
	resp_exp.max_reg_descriptors = mkey_attr.max_reg_descriptors;

	ret = ib_copy_to_udata(ucore, &resp_exp, sizeof(resp_exp));
	if (ret)
		return ret;

	return 0;
}
EXPORT_SYMBOL(ib_uverbs_exp_query_mkey);

enum ib_uverbs_cq_exp_create_flags {
	IB_UVERBS_CQ_EXP_TIMESTAMP	= 1 << 1,
};

static u32 create_cq_exp_flags_to_ex_flags(__u64 create_flags)
{
	switch (create_flags) {
	case IB_UVERBS_CQ_EXP_TIMESTAMP:
		return IB_CQ_FLAGS_TIMESTAMP_COMPLETION;
	default:
		return 0;
	}
}

#define KEEP_ACCESS_FLAGS (IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | \
			   IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_ATOMIC | \
			   IB_ACCESS_MW_BIND | IB_ZERO_BASED | \
			   IB_ACCESS_ON_DEMAND)
static int translate_exp_access_flags(u64 exp_access_flags)
{
	int access_flags = exp_access_flags & KEEP_ACCESS_FLAGS;

	if (exp_access_flags & IB_UVERBS_EXP_ACCESS_ON_DEMAND)
		access_flags |= IB_ACCESS_ON_DEMAND;
	if (exp_access_flags & IB_UVERBS_EXP_ACCESS_PHYSICAL_ADDR)
		access_flags |= IB_EXP_ACCESS_PHYSICAL_ADDR;

	return access_flags;
}

int ib_uverbs_exp_reg_mr(struct ib_uverbs_file *file, struct ib_device *ib_dev,
			 struct ib_udata *ucore, struct ib_udata *uhw)
{
	struct ib_uverbs_exp_reg_mr cmd;
	struct ib_uverbs_exp_reg_mr_resp resp;
	struct ib_uobject *uobj;
	struct ib_pd      *pd;
	struct ib_mr      *mr;
	int access_flags;
	int                ret;
	const int min_cmd_size = offsetof(typeof(cmd), comp_mask) +
					  sizeof(cmd.comp_mask);

	if (ucore->inlen < min_cmd_size) {
		pr_debug("%s: command input length too short\n", __func__);
		return -EINVAL;
	}

	ret = ib_copy_from_udata(&cmd, ucore, sizeof(cmd));
	if (ret)
		return ret;

	if (cmd.comp_mask >= IB_UVERBS_EXP_REG_MR_EX_RESERVED) {
		pr_debug("%s: invalid bit in command comp_mask field\n",
			 __func__);
		return -EINVAL;
	}

	if ((cmd.start & ~PAGE_MASK) != (cmd.hca_va & ~PAGE_MASK)) {
		pr_debug("%s: HCA virtual address doesn't match host address\n",
			 __func__);
		return -EINVAL;
	}

	access_flags = translate_exp_access_flags(cmd.exp_access_flags);

	ret = ib_check_mr_access(access_flags);
	if (ret)
		return ret;

	uobj = kmalloc(sizeof(*uobj), GFP_KERNEL);
	if (!uobj)
		return -ENOMEM;

	init_uobj(uobj, 0, file->ucontext, &mr_lock_class);
	down_write(&uobj->mutex);

	pd = idr_read_pd(cmd.pd_handle, file->ucontext);
	if (!pd) {
		pr_debug("ib_uverbs_reg_mr: invalid PD\n");
		ret = -EINVAL;
		goto err_free;
	}

	if (cmd.exp_access_flags & IB_UVERBS_EXP_ACCESS_ON_DEMAND) {
#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
		struct ib_exp_device_attr exp_attr;

		ret = ib_exp_query_device(pd->device, &exp_attr, uhw);
		if (ret || !(exp_attr.device_cap_flags2 &
			     IB_EXP_DEVICE_ODP)) {
			pr_debug("ib_uverbs_reg_mr: ODP requested on device without ODP support\n");
			ret = -EINVAL;
			goto err_put;
		}
#else
		pr_debug("ib_uverbs_reg_mr: ODP requested but the RDMA subsystem was compiled without ODP support\n");
		ret = -EINVAL;
		goto err_put;
#endif
	}
	/* We first get a new "obj id" to be passed later to reg mr for
	 *   further use as mr_id.
	 */
	ret = idr_add_uobj(&ib_uverbs_mr_idr, uobj);
	if (ret)
		goto err_put;

	if (!pd->device->exp_reg_user_mr) {
		ret = -ENOSYS;
		goto err_put;
	}
	mr = pd->device->exp_reg_user_mr(pd, cmd.start, cmd.length, cmd.hca_va,
					 access_flags, uhw, uobj->id);
	if (IS_ERR(mr)) {
		ret = PTR_ERR(mr);
		goto err_remove_uobj;
	}

	mr->device  = pd->device;
	mr->pd      = pd;
	mr->uobject = uobj;
	atomic_inc(&pd->usecnt);

	uobj->object = mr;

	memset(&resp, 0, sizeof(resp));
	resp.lkey      = mr->lkey;
	resp.rkey      = mr->rkey;
	resp.mr_handle = uobj->id;

	ret = ib_copy_to_udata(ucore, &resp, sizeof(resp));
	if (ret)
		goto err_copy;

	put_pd_read(pd);

	mutex_lock(&file->mutex);
	list_add_tail(&uobj->list, &file->ucontext->mr_list);
	mutex_unlock(&file->mutex);

	uobj->live = 1;

	up_write(&uobj->mutex);

	return 0;

err_copy:
	ib_dereg_mr(mr);

err_remove_uobj:
	idr_remove_uobj(&ib_uverbs_mr_idr, uobj);

err_put:
	put_pd_read(pd);

err_free:
	put_uobj_write(uobj);
	return ret;
}

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
int ib_uverbs_exp_prefetch_mr(struct ib_uverbs_file *file,
			      struct ib_device *ib_dev,
			      struct ib_udata *ucore,
			      struct ib_udata *uhw)
{
	struct ib_uverbs_exp_prefetch_mr  cmd;
	struct ib_mr                     *mr;
	int                               ret = -EINVAL;

	if (ucore->inlen < sizeof(cmd))
		return -EINVAL;

	ret = ib_copy_from_udata(&cmd, ucore, sizeof(cmd));
	if (ret)
		return ret;

	ucore->inbuf += sizeof(cmd);
	ucore->inlen -= sizeof(cmd);

	if (cmd.comp_mask)
		return -EINVAL;

	mr = idr_read_obj(&ib_uverbs_mr_idr, cmd.mr_handle, file->ucontext, 0);
	if (!mr)
		return -EINVAL;

	if (!mr->device->exp_prefetch_mr)
		return -ENOSYS;

	ret = mr->device->exp_prefetch_mr(mr, cmd.start, cmd.length, cmd.flags);

	put_uobj_read(mr->uobject);

	if (ret)
		return ret;

	ib_umem_odp_account_prefetch_handled(ib_dev);

	return ret;
}
#endif /* CONFIG_INFINIBAND_ON_DEMAND_PAGING */

int ib_uverbs_exp_create_cq(struct ib_uverbs_file *file, struct ib_device *ib_dev,
			    struct ib_udata *ucore, struct ib_udata *uhw)
{
	int out_len = ucore->outlen + uhw->outlen;
	struct ib_uverbs_exp_create_cq cmd_exp;
	struct ib_uverbs_ex_create_cq	cmd_ex;
	struct ib_uverbs_create_cq_resp resp;
	int ret;
	struct ib_ucq_object           *obj;

	if (out_len < sizeof(resp))
		return -ENOSPC;

	ret = ib_copy_from_udata(&cmd_exp, ucore, sizeof(cmd_exp));
	if (ret)
		return ret;

	if (cmd_exp.comp_mask >= IB_UVERBS_EXP_CREATE_CQ_ATTR_RESERVED)
		return -ENOSYS;

	if (cmd_exp.comp_mask & IB_UVERBS_EXP_CREATE_CQ_CAP_FLAGS &&
	   /* Check that there is no bit that is not supported */
	    cmd_exp.create_flags & ~(IB_UVERBS_CQ_EXP_TIMESTAMP))
		return -EINVAL;

	memset(&cmd_ex, 0, sizeof(cmd_ex));
	cmd_ex.user_handle = cmd_exp.user_handle;
	cmd_ex.cqe = cmd_exp.cqe;
	cmd_ex.comp_vector = cmd_exp.comp_vector;
	cmd_ex.comp_channel = cmd_exp.comp_channel;
	cmd_ex.flags = create_cq_exp_flags_to_ex_flags(cmd_exp.create_flags);

	obj = create_cq(file, ib_dev, ucore, uhw, &cmd_ex,
			sizeof(cmd_ex), ib_uverbs_create_cq_cb,
			NULL);

	if (IS_ERR(obj))
		return PTR_ERR(obj);

	return 0;
}

int ib_uverbs_exp_modify_qp(struct ib_uverbs_file *file, struct ib_device *ib_dev,
			    struct ib_udata *ucore, struct ib_udata *uhw)
{
	struct ib_uverbs_exp_modify_qp	cmd = {};
	int ret;
	struct ib_qp		       *qp;
	struct ib_qp_attr	       *attr;
	u32				exp_mask;

	if (ucore->inlen < offsetof(typeof(cmd), comp_mask) +  sizeof(cmd.comp_mask))
		return -EINVAL;

	ret = ib_copy_from_udata(&cmd, ucore, min(sizeof(cmd), ucore->inlen));
	if (ret)
		return ret;

	if (cmd.comp_mask >= IB_UVERBS_EXP_QP_ATTR_RESERVED)
		return -ENOSYS;

	/* Verify that upper & lower 32 bits from user can fit into qp_attr_mask which is 32 bits
	 * and there is no overflow.
	*/
	if ((cmd.exp_attr_mask << IBV_EXP_ATTR_MASK_SHIFT >= 1ULL << 32) ||
	    (cmd.attr_mask >= IBV_EXP_QP_ATTR_FIRST))
		return -EINVAL;

	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	qp = idr_read_qp(cmd.qp_handle, file->ucontext);
	if (!qp) {
		kfree(attr);
		return -EINVAL;
	}

	attr->qp_state            = cmd.qp_state;
	attr->cur_qp_state        = cmd.cur_qp_state;
	attr->path_mtu            = cmd.path_mtu;
	attr->path_mig_state      = cmd.path_mig_state;
	attr->qkey                = cmd.qkey;
	attr->rq_psn              = cmd.rq_psn & 0xffffff;
	attr->sq_psn              = cmd.sq_psn & 0xffffff;
	attr->dest_qp_num         = cmd.dest_qp_num;
	attr->qp_access_flags     = cmd.qp_access_flags;
	attr->pkey_index          = cmd.pkey_index;
	attr->alt_pkey_index      = cmd.alt_pkey_index;
	attr->en_sqd_async_notify = cmd.en_sqd_async_notify;
	attr->max_rd_atomic       = cmd.max_rd_atomic;
	attr->max_dest_rd_atomic  = cmd.max_dest_rd_atomic;
	attr->min_rnr_timer       = cmd.min_rnr_timer;
	attr->port_num            = cmd.port_num;
	attr->timeout             = cmd.timeout;
	attr->retry_cnt           = cmd.retry_cnt;
	attr->rnr_retry           = cmd.rnr_retry;
	attr->alt_port_num        = cmd.alt_port_num;
	attr->alt_timeout         = cmd.alt_timeout;
	attr->dct_key             = cmd.dct_key;
	attr->rate_limit	  = cmd.rate_limit;

	memcpy(attr->ah_attr.grh.dgid.raw, cmd.dest.dgid, 16);
	attr->ah_attr.grh.flow_label        = cmd.dest.flow_label;
	attr->ah_attr.grh.sgid_index        = cmd.dest.sgid_index;
	attr->ah_attr.grh.hop_limit         = cmd.dest.hop_limit;
	attr->ah_attr.grh.traffic_class     = cmd.dest.traffic_class;
	attr->ah_attr.dlid                  = cmd.dest.dlid;
	attr->ah_attr.sl                    = cmd.dest.sl;
	attr->ah_attr.src_path_bits         = cmd.dest.src_path_bits;
	attr->ah_attr.static_rate           = cmd.dest.static_rate;
	attr->ah_attr.ah_flags              = cmd.dest.is_global ? IB_AH_GRH : 0;
	attr->ah_attr.port_num              = cmd.dest.port_num;

	memcpy(attr->alt_ah_attr.grh.dgid.raw, cmd.alt_dest.dgid, 16);
	attr->alt_ah_attr.grh.flow_label    = cmd.alt_dest.flow_label;
	attr->alt_ah_attr.grh.sgid_index    = cmd.alt_dest.sgid_index;
	attr->alt_ah_attr.grh.hop_limit     = cmd.alt_dest.hop_limit;
	attr->alt_ah_attr.grh.traffic_class = cmd.alt_dest.traffic_class;
	attr->alt_ah_attr.dlid              = cmd.alt_dest.dlid;
	attr->alt_ah_attr.sl                = cmd.alt_dest.sl;
	attr->alt_ah_attr.src_path_bits     = cmd.alt_dest.src_path_bits;
	attr->alt_ah_attr.static_rate       = cmd.alt_dest.static_rate;
	attr->alt_ah_attr.ah_flags          = cmd.alt_dest.is_global ? IB_AH_GRH : 0;
	attr->alt_ah_attr.port_num          = cmd.alt_dest.port_num;

	if (cmd.comp_mask & IB_UVERBS_EXP_QP_ATTR_FLOW_ENTROPY) {
		if (offsetof(typeof(cmd), flow_entropy) + sizeof(cmd.flow_entropy) <= ucore->inlen) {
			attr->flow_entropy = cmd.flow_entropy;
		} else {
			ret = -EINVAL;
			goto out;
		}
	}

	if ((cmd.exp_attr_mask << IBV_EXP_ATTR_MASK_SHIFT) &
	    IB_EXP_QP_RATE_LIMIT)
		cmd.attr_mask |= IB_QP_RATE_LIMIT;

	exp_mask = (cmd.exp_attr_mask << IBV_EXP_ATTR_MASK_SHIFT) & IBV_EXP_QP_ATTR_MASK;
	if (qp->real_qp == qp) {
		if ((qp->qp_type != IB_EXP_QPT_DC_INI) && (cmd.attr_mask & IB_QP_AV)) {
			ret = ib_resolve_eth_dmac(qp->device, &attr->ah_attr);
			if (ret)
				goto out;
		}
		ret = qp->device->modify_qp(qp, attr,
			modify_qp_mask(qp->qp_type, cmd.attr_mask | exp_mask), uhw);
	} else {
		ret = ib_modify_qp(qp, attr, modify_qp_mask(qp->qp_type, cmd.attr_mask | exp_mask));
	}

out:
	put_qp_read(qp);
	kfree(attr);

	return ret;
}

static struct ib_dct *idr_read_dct(int dct_handle, struct ib_ucontext *context)
{
	return idr_read_obj(&ib_uverbs_dct_idr, dct_handle, context, 0);
}

static void put_dct_read(struct ib_dct *dct)
{
	put_uobj_read(dct->uobject);
}

int ib_uverbs_exp_create_dct(struct ib_uverbs_file *file, struct ib_device *ib_dev,
			     struct ib_udata *ucore, struct ib_udata *uhw)
{
	int out_len			= ucore->outlen + uhw->outlen;
	struct ib_uverbs_create_dct	 *cmd;
	struct ib_uverbs_create_dct_resp resp;
	struct ib_udct_object		*obj;
	struct ib_dct			*dct;
	int                             ret;
	struct ib_dct_init_attr		*attr;
	struct ib_pd			*pd = NULL;
	struct ib_cq			*cq = NULL;
	struct ib_srq			*srq = NULL;

	if (out_len < sizeof(resp))
		return -ENOSPC;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr || !cmd) {
		ret = -ENOMEM;
		goto err_cmd_attr;
	}

	ret = ib_copy_from_udata(cmd, ucore, sizeof(*cmd));
	if (ret)
		goto err_cmd_attr;

	obj = kmalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj) {
		ret = -ENOMEM;
		goto err_cmd_attr;
	}

	init_uobj(&obj->uevent.uobject, cmd->user_handle, file->ucontext,
		  &dct_lock_class);
	down_write(&obj->uevent.uobject.mutex);

	pd = idr_read_pd(cmd->pd_handle, file->ucontext);
	if (!pd) {
		ret = -EINVAL;
		goto err_pd;
	}

	cq = idr_read_cq(cmd->cq_handle, file->ucontext, 0);
	if (!cq) {
		ret = -EINVAL;
		goto err_put;
	}

	srq = idr_read_srq(cmd->srq_handle, file->ucontext);
	if (!srq) {
		ret = -EINVAL;
		goto err_put;
	}

	if (cmd->create_flags & ~IB_DCT_CREATE_FLAGS_MASK) {
		ret = -EINVAL;
		goto err_put;
	}

	attr->cq = cq;
	attr->access_flags = cmd->access_flags;
	attr->min_rnr_timer = cmd->min_rnr_timer;
	attr->srq = srq;
	attr->tclass = cmd->tclass;
	attr->flow_label = cmd->flow_label;
	attr->dc_key = cmd->dc_key;
	attr->mtu = cmd->mtu;
	attr->port = cmd->port;
	attr->pkey_index = cmd->pkey_index;
	attr->gid_index = cmd->gid_index;
	attr->hop_limit = cmd->hop_limit;
	attr->create_flags = cmd->create_flags;
	attr->inline_size = cmd->inline_size;
	attr->event_handler = ib_uverbs_dct_event_handler;
	attr->dct_context   = file;

	obj->uevent.events_reported = 0;
	INIT_LIST_HEAD(&obj->uevent.event_list);
	dct = ib_exp_create_dct(pd, attr, uhw);
	if (IS_ERR(dct)) {
		ret = PTR_ERR(dct);
		goto err_put;
	}

	dct->device        = file->device->ib_dev;
	dct->uobject       = &obj->uevent.uobject;
	dct->event_handler = attr->event_handler;
	dct->dct_context   = attr->dct_context;

	obj->uevent.uobject.object = dct;
	ret = idr_add_uobj(&ib_uverbs_dct_idr, &obj->uevent.uobject);
	if (ret)
		goto err_dct;

	memset(&resp, 0, sizeof(resp));
	resp.dct_handle = obj->uevent.uobject.id;
	resp.dctn = dct->dct_num;
	resp.inline_size = attr->inline_size;

	ret = ib_copy_to_udata(ucore, &resp, sizeof(resp));
	if (ret)
		goto err_copy;

	mutex_lock(&file->mutex);
	list_add_tail(&obj->uevent.uobject.list, &file->ucontext->dct_list);
	mutex_unlock(&file->mutex);

	obj->uevent.uobject.live = 1;

	put_srq_read(srq);
	put_cq_read(cq);
	put_pd_read(pd);

	up_write(&obj->uevent.uobject.mutex);
	kfree(attr);
	kfree(cmd);

	return 0;

err_copy:
	idr_remove_uobj(&ib_uverbs_dct_idr, &obj->uevent.uobject);

err_dct:
	ib_exp_destroy_dct(dct);

err_put:
	if (srq)
		put_srq_read(srq);

	if (cq)
		put_cq_read(cq);

	put_pd_read(pd);

err_pd:
	put_uobj_write(&obj->uevent.uobject);

err_cmd_attr:
	kfree(attr);
	kfree(cmd);
	return ret;
}

int ib_uverbs_exp_destroy_dct(struct ib_uverbs_file *file, struct ib_device *ib_dev,
			      struct ib_udata *ucore, struct ib_udata *uhw)
{
	int out_len				= ucore->outlen + uhw->outlen;
	struct ib_uverbs_destroy_dct		cmd;
	struct ib_uverbs_destroy_dct_resp	resp;
	struct ib_uobject		       *uobj;
	struct ib_udct_object		       *obj;
	struct ib_dct			       *dct;
	int					ret;

	if (out_len < sizeof(resp))
		return -ENOSPC;

	ret = ib_copy_from_udata(&cmd, ucore, sizeof(cmd));
	if (ret)
		return ret;

	uobj = idr_write_uobj(&ib_uverbs_dct_idr, cmd.dct_handle, file->ucontext);
	if (!uobj)
		return -EINVAL;

	dct      = uobj->object;
	obj = container_of(uobj, struct ib_udct_object, uevent.uobject);

	ret = ib_exp_destroy_dct(dct);
	if (!ret)
		uobj->live = 0;

	put_uobj_write(uobj);

	if (ret)
		return ret;

	idr_remove_uobj(&ib_uverbs_dct_idr, uobj);

	mutex_lock(&file->mutex);
	list_del(&uobj->list);
	mutex_unlock(&file->mutex);

	memset(&resp, 0, sizeof(resp));
	resp.events_reported = obj->uevent.events_reported;

	put_uobj(uobj);

	ret = ib_copy_to_udata(ucore, &resp, sizeof(resp));
	if (ret)
		return ret;

	return 0;
}

int ib_uverbs_exp_arm_dct(struct ib_uverbs_file *file, struct ib_device *ib_dev,
			  struct ib_udata *ucore, struct ib_udata *uhw)
{
	int out_len			= ucore->outlen + uhw->outlen;
	struct ib_uverbs_arm_dct	cmd;
	struct ib_uverbs_arm_dct_resp	resp;
	struct ib_dct		       *dct;
	int				err;

	if (out_len < sizeof(resp))
		return -ENOSPC;

	err = ib_copy_from_udata(&cmd, ucore, sizeof(cmd));
	if (err)
		return err;

	dct = idr_read_dct(cmd.dct_handle, file->ucontext);
	if (!dct)
		return -EINVAL;

	err = dct->device->exp_arm_dct(dct, uhw);
	put_dct_read(dct);
	if (err)
		return err;

	memset(&resp, 0, sizeof(resp));
	err = ib_copy_to_udata(ucore, &resp, sizeof(resp));

	return err;
}

int ib_uverbs_exp_query_dct(struct ib_uverbs_file *file, struct ib_device *ib_dev,
			    struct ib_udata *ucore, struct ib_udata *uhw)
{
	int out_len			= ucore->outlen + uhw->outlen;
	struct ib_uverbs_query_dct	cmd;
	struct ib_uverbs_query_dct_resp	resp;
	struct ib_dct		       *dct;
	struct ib_dct_attr	       *attr;
	int				err;

	if (out_len < sizeof(resp))
		return -ENOSPC;

	err = ib_copy_from_udata(&cmd, ucore, sizeof(cmd));
	if (err)
		return err;

	attr = kmalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr) {
		err = -ENOMEM;
		goto out;
	}

	dct = idr_read_dct(cmd.dct_handle, file->ucontext);
	if (!dct) {
		err = -EINVAL;
		goto out;
	}

	err = ib_exp_query_dct(dct, attr);

	put_dct_read(dct);

	if (err)
		goto out;

	memset(&resp, 0, sizeof(resp));

	resp.dc_key = attr->dc_key;
	resp.access_flags = attr->access_flags;
	resp.flow_label = attr->flow_label;
	resp.key_violations = attr->key_violations;
	resp.port = attr->port;
	resp.min_rnr_timer = attr->min_rnr_timer;
	resp.tclass = attr->tclass;
	resp.mtu = attr->mtu;
	resp.pkey_index = attr->pkey_index;
	resp.gid_index = attr->gid_index;
	resp.hop_limit = attr->hop_limit;
	resp.state = attr->state;

	err = ib_copy_to_udata(ucore, &resp, sizeof(resp));

out:
	kfree(attr);

	return err;
}

int ib_uverbs_exp_create_wq(struct ib_uverbs_file *file,
			    struct ib_device *ib_dev,
			    struct ib_udata *ucore,
			    struct ib_udata *uhw)
{
	return ib_uverbs_ex_create_wq(file, ib_dev, ucore, uhw);
}

int ib_uverbs_exp_modify_wq(struct ib_uverbs_file *file,
			    struct ib_device *ib_dev,
			    struct ib_udata *ucore,
			    struct ib_udata *uhw)
{
	return ib_uverbs_ex_modify_wq(file, ib_dev, ucore, uhw);
}

int ib_uverbs_exp_destroy_wq(struct ib_uverbs_file *file,
			     struct ib_device *ib_dev,
			     struct ib_udata *ucore,
			     struct ib_udata *uhw)
{
	return ib_uverbs_ex_destroy_wq(file, ib_dev, ucore, uhw);
}

int ib_uverbs_exp_create_rwq_ind_table(struct ib_uverbs_file *file,
				       struct ib_device *ib_dev,
				       struct ib_udata *ucore,
				       struct ib_udata *uhw)
{
	return ib_uverbs_ex_create_rwq_ind_table(file, ib_dev, ucore, uhw);
}

int ib_uverbs_exp_destroy_rwq_ind_table(struct ib_uverbs_file *file,
					struct ib_device *ib_dev,
					struct ib_udata *ucore,
					struct ib_udata *uhw)
{
	return ib_uverbs_ex_destroy_rwq_ind_table(file, ib_dev, ucore, uhw);
}
