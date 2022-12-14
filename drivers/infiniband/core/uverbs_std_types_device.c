// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018, Mellanox Technologies inc.  All rights reserved.
 */

#include <rdma/uverbs_std_types.h>
#include "rdma_core.h"
#include "uverbs.h"
#include <rdma/uverbs_ioctl.h>
#include <rdma/opa_addr.h>

void copy_port_attr_to_resp(struct ib_port_attr *attr,
			    struct ib_uverbs_query_port_resp *resp,
			    struct ib_device *ib_dev, u8 port_num)
{
	resp->state = attr->state;
	resp->max_mtu = attr->max_mtu;
	resp->active_mtu = attr->active_mtu;
	resp->gid_tbl_len = attr->gid_tbl_len;
	resp->port_cap_flags = make_port_cap_flags(attr);
	resp->max_msg_sz = attr->max_msg_sz;
	resp->bad_pkey_cntr = attr->bad_pkey_cntr;
	resp->qkey_viol_cntr = attr->qkey_viol_cntr;
	resp->pkey_tbl_len = attr->pkey_tbl_len;

	if (rdma_is_grh_required(ib_dev, port_num))
		resp->flags |= IB_UVERBS_QPF_GRH_REQUIRED;

	if (rdma_cap_opa_ah(ib_dev, port_num)) {
		resp->lid = OPA_TO_IB_UCAST_LID(attr->lid);
		resp->sm_lid = OPA_TO_IB_UCAST_LID(attr->sm_lid);
	} else {
		resp->lid = ib_lid_cpu16(attr->lid);
		resp->sm_lid = ib_lid_cpu16(attr->sm_lid);
	}

	resp->lmc = attr->lmc;
	resp->max_vl_num = attr->max_vl_num;
	resp->sm_sl = attr->sm_sl;
	resp->subnet_timeout = attr->subnet_timeout;
	resp->init_type_reply = attr->init_type_reply;
	resp->active_width = attr->active_width;
	resp->active_speed = attr->active_speed;
	resp->phys_state = attr->phys_state;
	resp->link_layer = rdma_port_get_link_layer(ib_dev, port_num);
}

static int UVERBS_HANDLER(UVERBS_METHOD_QUERY_PORT)(
	struct ib_uverbs_file *file, struct uverbs_attr_bundle *attrs)
{
	struct ib_device *ib_dev;
	struct ib_port_attr attr = {};
	struct ib_uverbs_query_port_resp_ex resp = {};
	struct ib_ucontext *ucontext;
	int ret;
	u8 port_num;

	ucontext = ib_uverbs_get_ucontext(file);
	if (IS_ERR(ucontext))
		return PTR_ERR(ucontext);
	ib_dev = ucontext->device;

	/* FIXME: Extend the UAPI_DEF_OBJ_NEEDS_FN stuff.. */
	if (!ib_dev->query_port)
		return -EOPNOTSUPP;

	ret = uverbs_get_const(&port_num, attrs,
			       UVERBS_ATTR_QUERY_PORT_PORT_NUM);
	if (ret)
		return ret;

	ret = ib_query_port(ib_dev, port_num, &attr);
	if (ret)
		return ret;

	copy_port_attr_to_resp(&attr, &resp.legacy_resp, ib_dev, port_num);
	resp.port_cap_flags2 = attr.port_cap_flags2;

	return uverbs_copy_to_struct_or_zero(attrs, UVERBS_ATTR_QUERY_PORT_RESP,
					     &resp, sizeof(resp));
}

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_QUERY_PORT,
	UVERBS_ATTR_CONST_IN(UVERBS_ATTR_QUERY_PORT_PORT_NUM, u8, UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(
		UVERBS_ATTR_QUERY_PORT_RESP,
		UVERBS_ATTR_STRUCT(struct ib_uverbs_query_port_resp_ex,
				   reserved),
		UA_MANDATORY));

DECLARE_UVERBS_GLOBAL_METHODS(UVERBS_OBJECT_DEVICE,
			      &UVERBS_METHOD(UVERBS_METHOD_QUERY_PORT));

//const struct uapi_definition uverbs_def_obj_device[] = {
//	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(UVERBS_OBJECT_DEVICE),
//	{},
//};
