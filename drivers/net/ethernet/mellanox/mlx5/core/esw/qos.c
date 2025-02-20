// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include "eswitch.h"
#include "lib/mlx5.h"
#include "esw/qos.h"
#include "en/port.h"
#include "mlx5_devm.h"
#define CREATE_TRACE_POINTS
#include "diag/qos_tracepoint.h"

/* Minimum supported BW share value by the HW is 1 Mbit/sec */
#define MLX5_MIN_BW_SHARE 1

static struct mlx5_qos_domain *esw_qos_domain_alloc(bool shared)
{
	struct mlx5_qos_domain *qos_domain;

	qos_domain = kzalloc(sizeof(*qos_domain), GFP_KERNEL);
	if (!qos_domain)
		return NULL;

	mutex_init(&qos_domain->lock);
	INIT_LIST_HEAD(&qos_domain->nodes);
	qos_domain->shared = shared;
	if (shared)
		refcount_set(&qos_domain->refcnt, 1);

	return qos_domain;
}

static void esw_qos_devcom_lock(struct mlx5_devcom_comp_dev *devcom, bool shared)
{
	if (shared)
		mlx5_devcom_comp_lock(devcom);
}

static void esw_qos_devcom_unlock(struct mlx5_devcom_comp_dev *devcom, bool shared)
{
	if (shared)
		mlx5_devcom_comp_unlock(devcom);
}

static int esw_qos_domain_init(struct mlx5_eswitch *esw, bool shared)
{
	struct mlx5_devcom_comp_dev *devcom = esw->dev->priv.hca_devcom_comp;

	if (shared && IS_ERR_OR_NULL(devcom)) {
		esw_info(esw->dev, "Cross-esw QoS cannot be initialized because devcom is unavailable.");
		shared = false;
	}

	esw_qos_devcom_lock(devcom, shared);
	if (shared) {
		struct mlx5_devcom_comp_dev *pos;
		struct mlx5_core_dev *peer_dev;

		mlx5_devcom_for_each_peer_entry(devcom, peer_dev, pos) {
			struct mlx5_eswitch *peer_esw = peer_dev->priv.eswitch;

			if (peer_esw->qos.domain && peer_esw->qos.domain->shared) {
				esw->qos.domain = peer_esw->qos.domain;
				refcount_inc(&esw->qos.domain->refcnt);
				goto unlock;
			}
		}
	}

	/* If no shared domain found, this esw will create one.
	 * Doing it with the devcom comp lock held prevents races with other
	 * eswitches doing concurrent init.
	 */
	esw->qos.domain = esw_qos_domain_alloc(shared);
unlock:
	esw_qos_devcom_unlock(devcom, shared);
	return esw->qos.domain ? 0 : -ENOMEM;
}

static void esw_qos_domain_release(struct mlx5_eswitch *esw)
{
	struct mlx5_devcom_comp_dev *devcom = esw->dev->priv.hca_devcom_comp;
	struct mlx5_qos_domain *domain = esw->qos.domain;
	bool shared = domain->shared;

	/* Shared domains are released with the devcom comp lock held to
	 * prevent races with other eswitches doing concurrent init.
	 */
	esw_qos_devcom_lock(devcom, shared);
	if (!shared || refcount_dec_and_test(&domain->refcnt))
		kfree(domain);
	esw->qos.domain = NULL;
	esw_qos_devcom_unlock(devcom, shared);
}

static const char * const sched_node_type_str[] = {
	[SCHED_NODE_TYPE_VPORTS_TSAR] = "vports TSAR",
	[SCHED_NODE_TYPE_VPORT] = "vport",
	[SCHED_NODE_TYPE_VPORT_TC] = "vport TC",
	[SCHED_NODE_TYPE_VPORTS_TC_TSAR] = "vports TC TSAR",
	[SCHED_NODE_TYPE_TC_ARBITER_TSAR] = "TC Arbiter TSAR",
	[SCHED_NODE_TYPE_VPORTS_AND_TC_ARBITERS_TSAR] = "vports and TC Arbiters TSAR"
};

static void
esw_qos_node_set_parent(struct mlx5_esw_sched_node *node, struct mlx5_esw_sched_node *parent)
{
	list_del_init(&node->entry);
	node->parent = parent;
	list_add_tail(&node->entry, &parent->children);
	node->esw = parent->esw;
}

static bool esw_sched_node_has_tc_arbiter(struct mlx5_esw_sched_node *node)
{
	struct mlx5_esw_sched_node *child;

	list_for_each_entry(child, &node->children, entry) {
		if (child->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR)
			return true;
	}

	return false;
}

u32 mlx5_esw_qos_vport_get_sched_elem_ix(const struct mlx5_vport *vport)
{
	if (!vport->qos.sched_node)
		return 0;

	return vport->qos.sched_node->ix;
}

struct mlx5_esw_sched_node *
mlx5_esw_qos_vport_get_parent(const struct mlx5_vport *vport)
{
	if (!vport->qos.sched_node)
		return NULL;
	if (!vport->qos.tc.arbiter_node)
		return vport->qos.sched_node->parent;
	return vport->qos.tc.arbiter_node->parent ?: vport->qos.tc.arbiter_node;
}

static int esw_qos_num_tcs(struct mlx5_core_dev *dev)
{
	int num_tcs = mlx5_max_tc(dev) + 1;

	return num_tcs < IEEE_8021QAZ_MAX_TCS ? num_tcs : IEEE_8021QAZ_MAX_TCS;
}

static int esw_qos_rate_limit_config(struct mlx5_core_dev *dev, u32 rl_elem_ix, u32 max_rate)
{
	u32 sched_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	u32 bitmask;

	MLX5_SET(scheduling_context, sched_ctx, max_average_bw, max_rate);
	bitmask = MODIFY_SCHEDULING_ELEMENT_IN_MODIFY_BITMASK_MAX_AVERAGE_BW;

	return mlx5_modify_scheduling_element_cmd(dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  sched_ctx,
						  rl_elem_ix,
						  bitmask);
}

static int esw_qos_create_rate_limit_element(struct mlx5_core_dev *dev, u32 *rl_elem_ix,
					     u32 max_rate)
{
	u32 sched_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	int err = 0;

	if (!mlx5_qos_element_type_supported(dev,
					     SCHEDULING_CONTEXT_ELEMENT_TYPE_RATE_LIMIT,
					     SCHEDULING_HIERARCHY_E_SWITCH))
		return -EOPNOTSUPP;

	MLX5_SET(scheduling_context, sched_ctx, max_average_bw, max_rate);
	MLX5_SET(scheduling_context, sched_ctx, element_type,
		 SCHEDULING_CONTEXT_ELEMENT_TYPE_RATE_LIMIT);
	err = mlx5_create_scheduling_element_cmd(dev,
						 SCHEDULING_HIERARCHY_E_SWITCH,
						 sched_ctx,
						 rl_elem_ix);
	if (err)
		esw_warn(dev, "create rate limit element failed (err=%d)\n", err);

	return err;
}

static void esw_qos_sched_elem_config_warn(struct mlx5_esw_sched_node *node, int err)
{
	switch (node->type) {
	case SCHED_NODE_TYPE_VPORTS_TC_TSAR:
		esw_warn(node->esw->dev,
			 "E-Switch modify %s scheduling element failed (tc=%d,err=%d)\n",
			 sched_node_type_str[node->type], node->tc, err);
		return;
	case SCHED_NODE_TYPE_VPORT_TC:
		esw_warn(node->esw->dev,
			 "E-Switch modify %s scheduling element failed (vport=%d,tc=%d,err=%d)\n",
			 sched_node_type_str[node->type], node->vport->vport, node->tc, err);
		return;
	case SCHED_NODE_TYPE_VPORT:
		esw_warn(node->esw->dev,
			 "E-Switch modify %s scheduling element failed (vport=%d,err=%d)\n",
			 sched_node_type_str[node->type], node->vport->vport, err);
		return;
	case SCHED_NODE_TYPE_VPORTS_AND_TC_ARBITERS_TSAR:
	case SCHED_NODE_TYPE_TC_ARBITER_TSAR:
	case SCHED_NODE_TYPE_VPORTS_TSAR:
		esw_warn(node->esw->dev,
			 "E-Switch modify %s scheduling element failed (err=%d)\n",
			 sched_node_type_str[node->type], err);
		return;
	default:
		esw_warn(node->esw->dev,
			 "E-Switch modify scheduling element failed (err=%d)\n", err);
		return;
	}
}

static int esw_qos_sched_elem_config(struct mlx5_esw_sched_node *node, u32 max_rate, u32 bw_share,
				     struct netlink_ext_ack *extack)
{
	u32 sched_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	struct mlx5_core_dev *dev = node->esw->dev;
	u32 bitmask = 0;
	int err;

	if (!MLX5_CAP_GEN(dev, qos) || !MLX5_CAP_QOS(dev, esw_scheduling))
		return -EOPNOTSUPP;

	MLX5_SET(scheduling_context, sched_ctx, max_average_bw, max_rate);
	MLX5_SET(scheduling_context, sched_ctx, bw_share, bw_share);
	bitmask |= MODIFY_SCHEDULING_ELEMENT_IN_MODIFY_BITMASK_MAX_AVERAGE_BW;
	bitmask |= MODIFY_SCHEDULING_ELEMENT_IN_MODIFY_BITMASK_BW_SHARE;

	err = mlx5_modify_scheduling_element_cmd(dev,
						 SCHEDULING_HIERARCHY_E_SWITCH,
						 sched_ctx,
						 node->ix,
						 bitmask);
	if (err) {
		esw_qos_sched_elem_config_warn(node, err);
		NL_SET_ERR_MSG_MOD(extack, "E-Switch modify scheduling element failed");

		return err;
	}

	if (node->type == SCHED_NODE_TYPE_VPORTS_TSAR)
		trace_mlx5_esw_node_qos_config(dev, node, node->ix, bw_share, max_rate);
	else if (node->type == SCHED_NODE_TYPE_VPORT)
		trace_mlx5_esw_vport_qos_config(dev, node->vport, bw_share, max_rate);

	return err;
}

int
mlx5_esw_get_esw_and_vport(struct devlink *devlink, struct devlink_port *port,
			   struct mlx5_eswitch **esw, struct mlx5_vport **vport,
			   struct netlink_ext_ack *extack)
{
	u16 vport_num;

	*esw = mlx5_devlink_eswitch_get(devlink);
	if (IS_ERR(*esw)) {
		NL_SET_ERR_MSG_MOD(extack, "Esw not found");
		return PTR_ERR(*esw);
	}

	vport_num = mlx5_esw_devlink_port_index_to_vport_num(port->index);
	*vport = mlx5_eswitch_get_vport(*esw, vport_num);
	if (IS_ERR(*vport)) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to get vport");
		return PTR_ERR(*vport);
	}

	return 0;
}

static u32 esw_qos_calculate_min_rate_divider(struct mlx5_eswitch *esw,
					      struct mlx5_esw_sched_node *parent)
{
	struct list_head *nodes = parent ? &parent->children : &esw->qos.domain->nodes;
	u32 fw_max_bw_share = MLX5_CAP_QOS(esw->dev, max_tsar_bw_share);
	struct mlx5_esw_sched_node *node;
	u32 max_guarantee = 0;

	/* Find max min_rate across all nodes.
	 * This will correspond to fw_max_bw_share in the final bw_share calculation.
	 */
	list_for_each_entry(node, nodes, entry) {
		if (node->esw == esw && node->ix != esw->qos.root_tsar_ix &&
		    node->min_rate > max_guarantee)
			max_guarantee = node->min_rate;
	}

	if (max_guarantee)
		return max_t(u32, max_guarantee / fw_max_bw_share, 1);

	/* If nodes max min_rate divider is 0 but their parent has bw_share
	 * configured, then set bw_share for nodes to minimal value.
	 */

	if (parent && parent->bw_share)
		return 1;

	/* If the node nodes has min_rate configured, a divider of 0 sets all
	 * nodes' bw_share to 0, effectively disabling min guarantees.
	 */
	return 0;
}

static u32 esw_qos_calc_bw_share(u32 min_rate, u32 divider, u32 fw_max)
{
	if (!divider)
		return 0;
	return min_t(u32, max_t(u32, DIV_ROUND_UP(min_rate, divider), MLX5_MIN_BW_SHARE), fw_max);
}

static int esw_qos_update_sched_node_bw_share(struct mlx5_esw_sched_node *node,
					      u32 divider,
					      struct netlink_ext_ack *extack)
{
	u32 fw_max_bw_share = MLX5_CAP_QOS(node->esw->dev, max_tsar_bw_share);
	u32 bw_share;
	int err;

	bw_share = esw_qos_calc_bw_share(node->min_rate, divider, fw_max_bw_share);

	if (bw_share == node->bw_share)
		return 0;

	err = esw_qos_sched_elem_config(node, node->max_rate, bw_share, extack);
	if (err)
		return err;

	node->bw_share = bw_share;

	return err;
}

static int esw_qos_normalize_min_rate(struct mlx5_eswitch *esw,
				      struct mlx5_esw_sched_node *parent,
				      struct netlink_ext_ack *extack)
{
	struct list_head *nodes = parent ? &parent->children : &esw->qos.domain->nodes;
	u32 divider = esw_qos_calculate_min_rate_divider(esw, parent);
	struct mlx5_esw_sched_node *node;

	list_for_each_entry(node, nodes, entry) {
		int err;

		if (node->esw != esw || node->ix == esw->qos.root_tsar_ix)
			continue;

		err = esw_qos_update_sched_node_bw_share(node, divider, extack);
		if (err)
			return err;

		if (list_empty(&node->children) || node->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR)
			continue;

		err = esw_qos_normalize_min_rate(node->esw, node, extack);
		if (err)
			return err;
	}

	return 0;
}

int esw_qos_set_vport_min_rate(struct mlx5_vport *vport,
			       u32 min_rate, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	u32 fw_max_bw_share, previous_min_rate;
	bool min_rate_supported;
	int err;

	esw_assert_qos_lock_held(vport->dev->priv.eswitch);
	fw_max_bw_share = MLX5_CAP_QOS(vport_node->esw->dev, max_tsar_bw_share);
	min_rate_supported = MLX5_CAP_QOS(vport_node->esw->dev, esw_bw_share) &&
				fw_max_bw_share >= MLX5_MIN_BW_SHARE;
	if (min_rate && !min_rate_supported)
		return -EOPNOTSUPP;
	if (min_rate == vport_node->min_rate)
		return 0;

	previous_min_rate = vport_node->min_rate;
	vport_node->min_rate = min_rate;
	err = esw_qos_normalize_min_rate(vport_node->parent->esw, vport_node->parent, extack);
	if (err)
		vport_node->min_rate = previous_min_rate;

	return err;
}

int esw_qos_set_vport_max_rate(struct mlx5_vport *vport,
			       u32 max_rate, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	u32 act_max_rate = max_rate;
	bool max_rate_supported;
	int err;

	esw_assert_qos_lock_held(vport->dev->priv.eswitch);
	max_rate_supported = MLX5_CAP_QOS(vport_node->esw->dev, esw_rate_limit);

	if (max_rate && !max_rate_supported)
		return -EOPNOTSUPP;
	if (max_rate == vport_node->max_rate)
		return 0;

	/* Use parent node limit if new max rate is 0. */
	if (!max_rate)
		act_max_rate = vport_node->parent->max_rate;

	err = esw_qos_sched_elem_config(vport_node, act_max_rate, vport_node->bw_share, extack);
	if (!err)
		vport_node->max_rate = max_rate;

	return err;
}

int esw_qos_set_node_min_rate(struct mlx5_esw_sched_node *node,
			      u32 min_rate, struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = node->esw;
	u32 previous_min_rate;
	int err;

	if (!MLX5_CAP_QOS(esw->dev, esw_bw_share) ||
	    MLX5_CAP_QOS(esw->dev, max_tsar_bw_share) < MLX5_MIN_BW_SHARE)
		return -EOPNOTSUPP;

	if (min_rate == node->min_rate)
		return 0;

	previous_min_rate = node->min_rate;
	node->min_rate = min_rate;
	err = esw_qos_normalize_min_rate(esw, NULL, extack);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch node min rate setting failed");

		/* Attempt restoring previous configuration */
		node->min_rate = previous_min_rate;
		if (esw_qos_normalize_min_rate(esw, NULL, extack))
			NL_SET_ERR_MSG_MOD(extack, "E-Switch BW share restore failed");
	}

	return err;
}

int esw_qos_set_node_max_rate(struct mlx5_esw_sched_node *node,
			      u32 max_rate, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node;
	int err;

	if (node->max_rate == max_rate)
		return 0;

	err = esw_qos_sched_elem_config(node, max_rate, node->bw_share, extack);
	if (err)
		return err;

	node->max_rate = max_rate;

	if (node->type != SCHED_NODE_TYPE_VPORTS_TSAR)
		return err;

	/* Any unlimited vports in the node should be set with the value of the node. */
	list_for_each_entry(vport_node, &node->children, entry) {
		if (vport_node->max_rate)
			continue;

		err = esw_qos_sched_elem_config(vport_node, max_rate, vport_node->bw_share, extack);
		if (err)
			NL_SET_ERR_MSG_MOD(extack,
					   "E-Switch vport implicit rate limit setting failed");
	}

	return err;
}

static int esw_qos_create_node_sched_elem(struct mlx5_core_dev *dev, u32 parent_element_id,
					  u32 max_rate, u32 bw_share, u32 *tsar_ix)
{
	u32 tsar_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	void *attr;

	if (!mlx5_qos_element_type_supported(dev,
					     SCHEDULING_CONTEXT_ELEMENT_TYPE_TSAR,
					     SCHEDULING_HIERARCHY_E_SWITCH) ||
	    !mlx5_qos_tsar_type_supported(dev,
					  TSAR_ELEMENT_TSAR_TYPE_DWRR,
					  SCHEDULING_HIERARCHY_E_SWITCH))
		return -EOPNOTSUPP;

	MLX5_SET(scheduling_context, tsar_ctx, element_type,
		 SCHEDULING_CONTEXT_ELEMENT_TYPE_TSAR);
	MLX5_SET(scheduling_context, tsar_ctx, parent_element_id, parent_element_id);
	attr = MLX5_ADDR_OF(scheduling_context, tsar_ctx, element_attributes);
	MLX5_SET(tsar_element, attr, tsar_type, TSAR_ELEMENT_TSAR_TYPE_DWRR);
	MLX5_SET(scheduling_context, tsar_ctx, max_average_bw, max_rate);
	MLX5_SET(scheduling_context, tsar_ctx, bw_share, bw_share);

	return mlx5_create_scheduling_element_cmd(dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  tsar_ctx,
						  tsar_ix);
}

static int
esw_qos_vport_create_sched_element(struct mlx5_vport *vport, struct mlx5_esw_sched_node *parent,
				   u32 max_rate, u32 bw_share, u32 *sched_elem_ix)
{
	u32 sched_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	struct mlx5_core_dev *dev = parent->esw->dev;
	void *attr;
	int err;

	if (!mlx5_qos_element_type_supported(dev,
					     SCHEDULING_CONTEXT_ELEMENT_TYPE_VPORT,
					     SCHEDULING_HIERARCHY_E_SWITCH))
		return -EOPNOTSUPP;

	MLX5_SET(scheduling_context, sched_ctx, element_type,
		 SCHEDULING_CONTEXT_ELEMENT_TYPE_VPORT);
	attr = MLX5_ADDR_OF(scheduling_context, sched_ctx, element_attributes);
	MLX5_SET(vport_element, attr, vport_number, vport->vport);
	if (vport->dev != dev) {
		/* The port is assigned to a node on another eswitch. */
		MLX5_SET(vport_element, attr, eswitch_owner_vhca_id_valid, true);
		MLX5_SET(vport_element, attr, eswitch_owner_vhca_id,
			 MLX5_CAP_GEN(vport->dev, vhca_id));
	}
	MLX5_SET(scheduling_context, sched_ctx, parent_element_id, parent->ix);
	MLX5_SET(scheduling_context, sched_ctx, max_average_bw, max_rate);
	MLX5_SET(scheduling_context, sched_ctx, bw_share, bw_share);

	err = mlx5_create_scheduling_element_cmd(dev,
						 SCHEDULING_HIERARCHY_E_SWITCH,
						 sched_ctx,
						 sched_elem_ix);
	if (err) {
		esw_warn(dev,
			 "E-Switch create vport scheduling element failed (vport=%d,err=%d)\n",
			 vport->vport, err);
		return err;
	}

	return 0;
}

static void esw_qos_destroy_sysfs_rate_group(struct mlx5_eswitch *esw,
					     struct mlx5_vport *vport,
					     struct mlx5_esw_sched_node *group)
{
	if (!group)
		return;
	if (group == esw->qos.node0)
		return;

	if (vport->vport != MLX5_VPORT_PF)
		group->num_vports--;
	if (group->group_id && !group->num_vports &&
	    !mlx5_esw_is_sf_vport(esw, vport->vport)) {
		if (group->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR)
			esw_qos_destroy_vports_tc_nodes(group, true, NULL);
		esw_qos_destroy_node(group, NULL);
	    }
}

static int
esw_qos_vport_tc_create_sched_element(struct mlx5_vport *vport, struct mlx5_esw_sched_node *parent,
				      u32 max_rate, u32 bw_share, u32 rate_limit_elem_ix,
				      u32 *sched_elem_ix)
{
	u32 sched_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	struct mlx5_core_dev *dev = parent->esw->dev;
	void *attr;
	int err;

	if (!mlx5_qos_element_type_supported(dev,
					     SCHEDULING_CONTEXT_ELEMENT_TYPE_VPORT_TC,
					     SCHEDULING_HIERARCHY_E_SWITCH))
		return -EOPNOTSUPP;

	MLX5_SET(scheduling_context, sched_ctx, element_type,
		 SCHEDULING_CONTEXT_ELEMENT_TYPE_VPORT_TC);
	attr = MLX5_ADDR_OF(scheduling_context, sched_ctx, element_attributes);
	MLX5_SET(vport_tc_element, attr, vport_number, vport->vport);
	if (vport->dev != dev) {
		/* The port is assigned to a node on another eswitch. */
		MLX5_SET(vport_element, attr, eswitch_owner_vhca_id_valid, true);
		MLX5_SET(vport_element, attr, eswitch_owner_vhca_id,
			 MLX5_CAP_GEN(vport->dev, vhca_id));
	}

	MLX5_SET(vport_tc_element, attr, traffic_class, parent->tc);
	MLX5_SET(scheduling_context, sched_ctx, max_bw_obj_id, rate_limit_elem_ix);
	MLX5_SET(scheduling_context, sched_ctx, parent_element_id, parent->ix);
	err = mlx5_create_scheduling_element_cmd(dev,
						 SCHEDULING_HIERARCHY_E_SWITCH,
						 sched_ctx,
						 sched_elem_ix);
	if (err)
		esw_warn(dev, "Create Vport TC element failed (vport=%d,tc=%d,err=%d)\n",
			 vport->vport, parent->tc, err);

	return err;
}

static int esw_qos_update_node_scheduling_element(struct mlx5_vport *vport,
						  struct mlx5_esw_sched_node *curr_node,
						  struct mlx5_esw_sched_node *new_node,
						  struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	u32 max_rate;
	int err;

	err = mlx5_destroy_scheduling_element_cmd(curr_node->esw->dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  vport_node->ix);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch destroy vport scheduling element failed");
		return err;
	}

	/* Use new node max rate if vport max rate is unlimited. */
	max_rate = vport_node->max_rate ? vport_node->max_rate : new_node->max_rate;
	err = esw_qos_vport_create_sched_element(vport, new_node, max_rate,
						 vport_node->bw_share,
						 &vport_node->ix);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch vport node set failed.");
		goto err_sched;
	}

	esw_qos_node_set_parent(vport->qos.sched_node, new_node);

	return 0;

err_sched:
	max_rate = vport_node->max_rate ? vport_node->max_rate : curr_node->max_rate;
	if (esw_qos_vport_create_sched_element(vport, curr_node, max_rate,
					       vport_node->bw_share,
					       &vport_node->ix))
		esw_warn(curr_node->esw->dev, "E-Switch vport node restore failed (vport=%d)\n",
			 vport->vport);

	return err;
}

int esw_qos_vport_update_node(struct mlx5_vport *vport, struct mlx5_esw_sched_node *node,
			      struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	struct mlx5_esw_sched_node *new_node, *curr_node;
	int err;

	esw_assert_qos_lock_held(esw);
	curr_node = vport_node->parent;
	new_node = node ?: esw->qos.node0;
	if (curr_node == new_node)
		return 0;

	err = esw_qos_update_node_scheduling_element(vport, curr_node, new_node, extack);
	if (err)
		return err;

	/* Recalculate bw share weights of old and new nodes */
	if (vport_node->bw_share || new_node->bw_share) {
		esw_qos_normalize_min_rate(curr_node->esw, curr_node, extack);
		esw_qos_normalize_min_rate(new_node->esw, new_node, extack);
	}

	return 0;
}

static struct mlx5_esw_sched_node *
__esw_qos_alloc_node(struct mlx5_eswitch *esw, u32 tsar_ix, enum sched_node_type type,
		     struct mlx5_esw_sched_node *parent)
{
	struct list_head *parent_children;
	struct mlx5_esw_sched_node *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return NULL;

	node->esw = esw;
	node->ix = tsar_ix;
	node->type = type;
	node->parent = parent;
	INIT_LIST_HEAD(&node->children);
	parent_children = parent ? &parent->children : &esw->qos.domain->nodes;
	list_add_tail(&node->entry, parent_children);

	return node;
}

static void __esw_qos_free_node(struct mlx5_esw_sched_node *node)
{
	list_del(&node->entry);
	kfree(node);
}

static struct mlx5_esw_sched_node *
esw_qos_create_vports_tc_node(struct mlx5_esw_sched_node *parent,
			      u8 tc, struct netlink_ext_ack *extack)
{
	u32 tsar_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	struct mlx5_core_dev *dev = parent->esw->dev;
	struct mlx5_esw_sched_node *vports_tc_node;
	int tsar_ix, err;
	void *attr;

	if (!mlx5_qos_element_type_supported(dev,
					     SCHEDULING_CONTEXT_ELEMENT_TYPE_TSAR,
					     SCHEDULING_HIERARCHY_E_SWITCH) ||
	    !mlx5_qos_tsar_type_supported(dev,
					  TSAR_ELEMENT_TSAR_TYPE_DWRR,
					  SCHEDULING_HIERARCHY_E_SWITCH))
		return ERR_PTR(-EOPNOTSUPP);

	attr = MLX5_ADDR_OF(scheduling_context, tsar_ctx, element_attributes);
	MLX5_SET(tsar_element, attr, tsar_type, TSAR_ELEMENT_TSAR_TYPE_DWRR);
	MLX5_SET(tsar_element, attr, traffic_class, tc);
	MLX5_SET(scheduling_context, tsar_ctx, parent_element_id, parent->ix);
	MLX5_SET(scheduling_context, tsar_ctx, element_type, SCHEDULING_CONTEXT_ELEMENT_TYPE_TSAR);

	err = mlx5_create_scheduling_element_cmd(dev,
						 SCHEDULING_HIERARCHY_E_SWITCH,
						 tsar_ctx,
						 &tsar_ix);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch create scheduling element failed");
		return ERR_PTR(err);
	}

	vports_tc_node = __esw_qos_alloc_node(parent->esw, tsar_ix,
					      SCHED_NODE_TYPE_VPORTS_TC_TSAR, parent);
	if (IS_ERR(vports_tc_node)) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch alloc node failed");
		err = PTR_ERR(vports_tc_node);
		goto err_alloc_node;
	}

	vports_tc_node->tc = tc;

	return vports_tc_node;

err_alloc_node:
	mlx5_destroy_scheduling_element_cmd(dev, SCHEDULING_HIERARCHY_E_SWITCH, tsar_ix);

	return ERR_PTR(err);
}

static struct mlx5_esw_sched_node *
esw_qos_lookup_vports_tc_node(struct mlx5_esw_sched_node *tc_arbiter_node, u8 tc)
{
	struct mlx5_esw_sched_node *vports_tc_node;

	list_for_each_entry(vports_tc_node, &tc_arbiter_node->children, entry) {
		if (vports_tc_node->tc == tc)
			return vports_tc_node;
	}

	return NULL;
}

static int esw_qos_destroy_vports_tc_node(struct mlx5_esw_sched_node *vports_tc_node, bool force)
{
	int err;

	err = mlx5_destroy_scheduling_element_cmd(vports_tc_node->esw->dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  vports_tc_node->ix);
	if (err) {
		esw_warn(vports_tc_node->esw->dev,
			 "Failed to destroy vports TC node (tc=%d)\n", vports_tc_node->tc);
		if (!force)
			return err;
	}

	__esw_qos_free_node(vports_tc_node);

	return err;
}


int
esw_qos_destroy_vports_tc_nodes(struct mlx5_esw_sched_node *tc_arbiter_node, bool force,
				struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vports_tc_node, *tmp;
	struct mlx5_eswitch *esw = tc_arbiter_node->esw;
	int num_tcs = esw_qos_num_tcs(esw->dev);
	int err, ret = 0, i;

	list_for_each_entry_safe(vports_tc_node, tmp, &tc_arbiter_node->children, entry) {
		err = esw_qos_destroy_vports_tc_node(vports_tc_node, force);
		if (err) {
			NL_SET_ERR_MSG_MOD(extack, "E-Switch destroy Vports TC node failed");
			ret = err;
			if (!force)
				goto err_restore;
		}
	}

	return ret;

err_restore:
	/* Restore previously destroyed vports TC nodes if an error occurs. */
	for (i = 0; i < num_tcs; i++) {
		if (esw_qos_lookup_vports_tc_node(tc_arbiter_node, i))
			continue;

		vports_tc_node = esw_qos_create_vports_tc_node(tc_arbiter_node, i, extack);
		if (IS_ERR(vports_tc_node))
			esw_warn(esw->dev, "Restore vports TC node failed (tc=%d)\n", i);
	}

	return ret;
}

static int esw_qos_create_vports_tc_nodes(struct mlx5_esw_sched_node *tc_arbiter_node,
					  struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = tc_arbiter_node->esw;
	struct mlx5_esw_sched_node *vports_tc_node;
	int num_tcs = esw_qos_num_tcs(esw->dev);
	int err, i;

	for (i = 0; i < num_tcs; i++) {
		vports_tc_node = esw_qos_create_vports_tc_node(tc_arbiter_node, i, extack);
		if (IS_ERR(vports_tc_node)) {
			err = PTR_ERR(vports_tc_node);
			esw_warn(esw->dev,
				 "Failed to create vports TC node (tc=%d, err=%d)\n", i, err);
			goto err_tc_node_create;
		}
	}

	return 0;

err_tc_node_create:
	esw_qos_destroy_vports_tc_nodes(tc_arbiter_node, true, NULL);
	return err;
}

static int esw_qos_normalize_vports_tcs(struct mlx5_esw_sched_node *tc_arbiter_node, bool force,
					struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vports_tc_node;
	int err, ret = 0;

	list_for_each_entry(vports_tc_node, &tc_arbiter_node->children, entry) {
		err = esw_qos_normalize_min_rate(vports_tc_node->esw, vports_tc_node, extack);
		if (err) {
			ret = err;
			if (!force)
				return ret;
		}
	}

	return ret;
}

static int
esw_qos_create_tc_arbiter_sched_elem(struct mlx5_core_dev *dev, u32 parent_tsar_ix, u32 max_rate,
				     u32 bw_share, u32 *tsar_ix, struct netlink_ext_ack *extack)
{
	u32 tsar_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	void *attr;
	int err;

	if (!mlx5_qos_tsar_type_supported(dev,
					  TSAR_ELEMENT_TSAR_TYPE_TC_ARB,
					  SCHEDULING_HIERARCHY_E_SWITCH)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "E-Switch TC Arbiter scheduling element is not supported");

		return -EOPNOTSUPP;
	}

	attr = MLX5_ADDR_OF(scheduling_context, tsar_ctx, element_attributes);
	MLX5_SET(tsar_element, attr, tsar_type, TSAR_ELEMENT_TSAR_TYPE_TC_ARB);
	MLX5_SET(scheduling_context, tsar_ctx, parent_element_id, parent_tsar_ix);
	MLX5_SET(scheduling_context, tsar_ctx, element_type, SCHEDULING_CONTEXT_ELEMENT_TYPE_TSAR);
	MLX5_SET(scheduling_context, tsar_ctx, max_average_bw, max_rate);
	MLX5_SET(scheduling_context, tsar_ctx, bw_share, bw_share);
	err = mlx5_create_scheduling_element_cmd(dev,
						 SCHEDULING_HIERARCHY_E_SWITCH,
						 tsar_ctx,
						 tsar_ix);
	if (err)
		NL_SET_ERR_MSG_MOD(extack, "E-Switch create TC Arbiter TSAR for node failed");

	return err;
}

static struct mlx5_esw_sched_node *
__esw_qos_create_vports_sched_node(struct mlx5_eswitch *esw, u32 group_id,
				   struct mlx5_esw_sched_node *parent,
				   struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node;
	u32 tsar_ix;
	int err;

	err = esw_qos_create_node_sched_elem(esw->dev, esw->qos.root_tsar_ix, 0, 0, &tsar_ix);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch create TSAR for node failed");
		return ERR_PTR(err);
	}

	node = __esw_qos_alloc_node(esw, tsar_ix, SCHED_NODE_TYPE_VPORTS_TSAR, parent);
	if (!node) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch alloc node failed");
		err = -ENOMEM;
		goto err_alloc_node;
	}

	node->group_id = group_id;
	node->dev = esw->dev;
	if (group_id != MLX5_ESW_QOS_NON_SYSFS_GROUP) {
		err = mlx5_create_vf_group_sysfs(esw->dev, group_id, &node->kobj);
		if (err)
			goto err_group_sysfs;
	}

	err = esw_qos_normalize_min_rate(esw, NULL, extack);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch nodes normalization failed");
		goto err_min_rate;
	}
	trace_mlx5_esw_node_qos_create(esw->dev, node, node->tsar_ix);
	init_completion(&node->free_group_comp);

	return node;

err_min_rate:
        if (group_id != MLX5_ESW_QOS_NON_SYSFS_GROUP)
                kobject_put(&node->kobj);
err_group_sysfs:
	__esw_qos_free_node(node);
err_alloc_node:
	if (mlx5_destroy_scheduling_element_cmd(esw->dev,
						SCHEDULING_HIERARCHY_E_SWITCH,
						tsar_ix))
		NL_SET_ERR_MSG_MOD(extack, "E-Switch destroy TSAR for node failed");
	return ERR_PTR(err);
}

static int esw_qos_get(struct mlx5_eswitch *esw, struct netlink_ext_ack *extack);
static void esw_qos_put(struct mlx5_eswitch *esw);

struct mlx5_esw_sched_node *
esw_qos_create_vports_sched_node(struct mlx5_eswitch *esw, u32 group_id,
				 struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node;
	int err;

	esw_assert_qos_lock_held(esw);
	if (!MLX5_CAP_QOS(esw->dev, log_esw_max_sched_depth))
		return ERR_PTR(-EOPNOTSUPP);

	err = esw_qos_get(esw, extack);
	if (err)
		return ERR_PTR(err);

	node = __esw_qos_create_vports_sched_node(esw, group_id, NULL, extack);
	if (IS_ERR(node))
		esw_qos_put(esw);

	return node;
}

static int __esw_qos_destroy_node(struct mlx5_esw_sched_node *node,
				  struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = node->esw;
	int err;

	if (node->group_id != MLX5_ESW_QOS_NON_SYSFS_GROUP)
		mlx5_destroy_vf_group_sysfs(node);
	else
		complete_all(&node->free_group_comp);

	trace_mlx5_esw_node_qos_destroy(esw->dev, node, node->ix);

	err = mlx5_destroy_scheduling_element_cmd(esw->dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  node->ix);
	if (err)
		NL_SET_ERR_MSG_MOD(extack, "E-Switch destroy TSAR_ID failed");

	wait_for_completion(&node->free_group_comp);
	__esw_qos_free_node(node);

	err = esw_qos_normalize_min_rate(esw, NULL, extack);
	if (err)
		NL_SET_ERR_MSG_MOD(extack, "E-Switch nodes normalization failed");


	return err;
}

int esw_qos_destroy_node(struct mlx5_esw_sched_node *node,
			 struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = node->esw;
	int err;

	err = __esw_qos_destroy_node(node, extack);
	esw_qos_put(esw);

	return err;
}

static int esw_qos_create(struct mlx5_eswitch *esw, struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = esw->dev;
	int err;

	if (!MLX5_CAP_GEN(dev, qos) || !MLX5_CAP_QOS(dev, esw_scheduling))
		return -EOPNOTSUPP;

	err = esw_qos_create_node_sched_elem(esw->dev, 0, 0, 0, &esw->qos.root_tsar_ix);
	if (err) {
		esw_warn(dev, "E-Switch create root TSAR failed (%d)\n", err);
		return err;
	}

	if (MLX5_CAP_QOS(dev, log_esw_max_sched_depth)) {
		esw->qos.node0 = __esw_qos_create_vports_sched_node(esw, 0, NULL, extack);
	} else {
		/* The eswitch doesn't support scheduling nodes.
		 * Create a software-only node0 using the root TSAR to attach vport QoS to.
		 */
		if (!__esw_qos_alloc_node(esw, esw->qos.root_tsar_ix,
					  SCHED_NODE_TYPE_VPORTS_TSAR, NULL))
			esw->qos.node0 = ERR_PTR(-ENOMEM);
	}
	if (IS_ERR(esw->qos.node0)) {
		err = PTR_ERR(esw->qos.node0);
		esw_warn(dev, "E-Switch create rate node 0 failed (%d)\n", err);
		goto err_node0;
	}
	refcount_set(&esw->qos.refcnt, 1);

	return 0;

err_node0:
	if (mlx5_destroy_scheduling_element_cmd(esw->dev, SCHEDULING_HIERARCHY_E_SWITCH,
						esw->qos.root_tsar_ix))
		esw_warn(esw->dev, "E-Switch destroy root TSAR failed.\n");

	return err;
}

static void esw_qos_destroy(struct mlx5_eswitch *esw)
{
	int err;

	if (esw->qos.node0->tsar_ix != esw->qos.root_tsar_ix)
		__esw_qos_destroy_node(esw->qos.node0, NULL);
	else
		__esw_qos_free_node(esw->qos.node0);
	esw->qos.node0 = NULL;

 	err = mlx5_destroy_scheduling_element_cmd(esw->dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  esw->qos.root_tsar_ix);
	if (err)
		esw_warn(esw->dev, "E-Switch destroy root TSAR failed (%d)\n", err);
}

static int esw_qos_get(struct mlx5_eswitch *esw, struct netlink_ext_ack *extack)
{
	int err = 0;

	esw_assert_qos_lock_held(esw);
	if (!refcount_inc_not_zero(&esw->qos.refcnt)) {
		/* esw_qos_create() set refcount to 1 only on success.
		 * No need to decrement on failure.
		 */
		err = esw_qos_create(esw, extack);
	}

	return err;
}

static void esw_qos_put(struct mlx5_eswitch *esw)
{
	esw_assert_qos_lock_held(esw);
	if (refcount_dec_and_test(&esw->qos.refcnt))
		esw_qos_destroy(esw);
}

static int
esw_qos_tc_arbiter_scheduling_teardown(struct mlx5_esw_sched_node *tc_arbiter_node, bool force,
				       struct netlink_ext_ack *extack)
{
	int err, ret = 0;

	/* Clean up all Vports TC nodes within the TC arbiter node. */
	err = esw_qos_destroy_vports_tc_nodes(tc_arbiter_node, force, extack);
	if (err) {
		ret = err;
		if (!force)
			return err;
	}

	/* Destroy the scheduling element for the TC arbiter node itself. */
	err = mlx5_destroy_scheduling_element_cmd(tc_arbiter_node->esw->dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  tc_arbiter_node->ix);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to destroy TC arbiter scheduling element.");
		ret = err;
		if (!force) {
			/* If the destruction of the TC arbiter scheduling element fails,
			 * attempt to restore the TC nodes.
			 */
			if (esw_qos_create_vports_tc_nodes(tc_arbiter_node, extack))
				esw_warn(tc_arbiter_node->esw->dev,
					 "TC Arbiter node restore failed\n");
		}
	}

	return ret;
}

static int
esw_qos_tc_arbiter_scheduling_setup(struct mlx5_esw_sched_node *tc_arbiter_node,
				    struct mlx5_esw_sched_node *parent,
				    struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = tc_arbiter_node->esw;
	struct mlx5_core_dev *dev = esw->dev;
	int parent_tsar_ix;
	int err;

	if (!MLX5_CAP_QOS(dev, log_esw_max_sched_depth)) {
		NL_SET_ERR_MSG_MOD(extack, "Setting up TC Arbiter for a node is not supported.");
		return -EOPNOTSUPP;
	}

	parent_tsar_ix = parent ? parent->ix : esw->qos.root_tsar_ix;
	/* Create a scheduling element for the TC arbiter under the parent TSAR. */
	err = esw_qos_create_tc_arbiter_sched_elem(dev,
						   parent_tsar_ix,
						   tc_arbiter_node->max_rate,
						   tc_arbiter_node->bw_share,
						   &tc_arbiter_node->ix,
						   extack);
	if (err)
		return err;
	/* Initialize the vports TC nodes within created TC arbiter TSAR. */
	err = esw_qos_create_vports_tc_nodes(tc_arbiter_node, extack);
	if (err) {
		/* If initialization fails, clean up the scheduling element
		 * for the TC arbiter node.
		 */
		mlx5_destroy_scheduling_element_cmd(dev,
						    SCHEDULING_HIERARCHY_E_SWITCH,
						    tc_arbiter_node->ix);
	}

	return err;
}

static struct mlx5_esw_sched_node *
esw_qos_create_tc_arbiter_node(struct mlx5_vport *vport, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	struct mlx5_esw_sched_node *parent, *tc_arbiter_node;
	int err;

	/* Allocate TC arbiter node. */
	parent = vport_node->parent;
	tc_arbiter_node = __esw_qos_alloc_node(vport_node->parent->esw, 0,
					       SCHED_NODE_TYPE_TC_ARBITER_TSAR,
					       parent);
	if (IS_ERR(tc_arbiter_node)) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch alloc node failed");
		return tc_arbiter_node;
	}

	/* Set up scheduling for the TC arbiter node. */
	tc_arbiter_node->max_rate = vport_node->max_rate;
	tc_arbiter_node->min_rate = vport_node->min_rate;
	tc_arbiter_node->bw_share = vport_node->bw_share;
	err = esw_qos_tc_arbiter_scheduling_setup(tc_arbiter_node, vport_node->parent,
						  extack);
	if (err) {
		list_del(&tc_arbiter_node->entry);
		goto err_out;
	}

	return tc_arbiter_node;

err_out:
	kfree(tc_arbiter_node);
	return ERR_PTR(err);
}

static int
esw_qos_destroy_vport_tc(struct mlx5_esw_sched_node *node, struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = node->parent->esw->dev;
	int err;

	err = mlx5_destroy_scheduling_element_cmd(dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  node->ix);
	if (err) {
		esw_warn(dev,
			 "Failed to destroy vport TC scheduling element (vport=%d,tc=%d,err=%d)\n",
			  node->vport->vport, node->tc, err);
		NL_SET_ERR_MSG_MOD(extack, "Failed to destroy vport TC scheduling element");
	}

	return err;
}

static int
esw_qos_init_vport_tc(struct mlx5_vport *vport, struct mlx5_esw_sched_node *parent,
		      struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node;
	u8 tc = parent->tc;
	u32 sched_elem_ix;
	int err;

	err = esw_qos_vport_tc_create_sched_element(vport, parent, 0, 0,
						    vport->qos.tc.esw_rate_limit_elem_ix,
						    &sched_elem_ix);
	if (err)
		return err;

	node = __esw_qos_alloc_node(parent->esw, sched_elem_ix, SCHED_NODE_TYPE_VPORT_TC, parent);
	if (!node) {
		err = -ENOMEM;
		goto err_alloc;
	}

	node->max_rate = vport->qos.sched_node->max_rate;
	node->min_rate = vport->qos.sched_node->min_rate;
	node->tc = tc;
	node->vport = vport;
	vport->qos.tc.sched_nodes[tc] = node;

	return 0;

err_alloc:
	if (mlx5_destroy_scheduling_element_cmd(parent->esw->dev,
						SCHEDULING_HIERARCHY_E_SWITCH,
						sched_elem_ix))
		esw_warn(parent->esw->dev,
			 "Failed to destroy vport TC scheduling element (vport=%d,tc=%d)\n",
			 vport->vport, tc);

	return err;
}

static int
esw_qos_cleanup_vport_tcs(struct mlx5_vport *vport, bool force, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *tc_arbiter_node = vport->qos.tc.arbiter_node;
	struct mlx5_core_dev *dev = tc_arbiter_node->esw->dev;
	int num_tcs = esw_qos_num_tcs(dev);
	int err, ret = 0, i;

	for (i = 0; i < num_tcs ; i++) {
		err = esw_qos_destroy_vport_tc(vport->qos.tc.sched_nodes[i], extack);
		if (err) {
			ret = err;
			if (!force)
				goto err_out;
		}
	}

	err = mlx5_destroy_scheduling_element_cmd(dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  vport->qos.tc.esw_rate_limit_elem_ix);
	if (err) {
		esw_warn(dev,
			 "Failed to destroy vport rate limit element (vport=%d,err=%d)\n",
			 vport->vport, err);
		NL_SET_ERR_MSG_MOD(extack, "Failed to destroy vport rate limit element");
		ret = err;
		if (!force)
			goto err_out;
	}

	for (i = 0; i < num_tcs; i++)
		__esw_qos_free_node(vport->qos.tc.sched_nodes[i]);

	esw_qos_normalize_vports_tcs(tc_arbiter_node, force, extack);

	kfree(vport->qos.tc.sched_nodes);
	memset(&vport->qos.tc, 0, sizeof(vport->qos.tc));

	return ret;

err_out:
	for (--i; i >= 0; i--) {
		struct mlx5_esw_sched_node *parent, *node;
		u32 bw_share;

		node = vport->qos.tc.sched_nodes[i];
		parent = node->parent;
		bw_share = node->bw_share;
		if (esw_qos_vport_tc_create_sched_element(vport, parent, 0, bw_share,
							  vport->qos.tc.esw_rate_limit_elem_ix,
							  &node->ix)) {
			esw_warn(parent->esw->dev,
				 "vport tc restore failed (vport=%d)(tc=%d)\n", vport->vport, i);
			continue;
		}
	}

	return err;
}

static int esw_qos_init_vport_tcs(struct mlx5_vport *vport,
				  struct mlx5_esw_sched_node *tc_arbiter_node,
				  struct netlink_ext_ack *extack)
{
	int num_tcs = esw_qos_num_tcs(tc_arbiter_node->esw->dev);
	int err, i;

	vport->qos.tc.sched_nodes = kcalloc(num_tcs, sizeof(struct mlx5_esw_sched_node *),
					    GFP_KERNEL);
	if (!vport->qos.tc.sched_nodes)
		return -ENOMEM;

	err = esw_qos_create_rate_limit_element(tc_arbiter_node->esw->dev,
						&vport->qos.tc.esw_rate_limit_elem_ix,
						vport->qos.sched_node->max_rate);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to create vport rate limit element.");
		goto err_create_rate_limit;
	}

	for (i = 0; i < num_tcs; i++) {
		struct mlx5_esw_sched_node *vports_tc_node;

		vports_tc_node = esw_qos_lookup_vports_tc_node(tc_arbiter_node, i);
		if (!vports_tc_node) {
			NL_SET_ERR_MSG_MOD(extack, "Failed to get vports TC node.");
			goto err_init_vport_tc;
		}
		err = esw_qos_init_vport_tc(vport, vports_tc_node, extack);
		if (err)
			goto err_init_vport_tc;
	}

	esw_qos_normalize_vports_tcs(tc_arbiter_node, false, extack);
	vport->qos.tc.arbiter_node = tc_arbiter_node;

	return 0;

err_init_vport_tc:
	for (--i; i >= 0; i--) {
		esw_qos_destroy_vport_tc(vport->qos.tc.sched_nodes[i], NULL);
		__esw_qos_free_node(vport->qos.tc.sched_nodes[i]);
	}

	esw_qos_normalize_vports_tcs(tc_arbiter_node, true, NULL);

	if (mlx5_destroy_scheduling_element_cmd(tc_arbiter_node->esw->dev,
						SCHEDULING_HIERARCHY_E_SWITCH,
						vport->qos.tc.esw_rate_limit_elem_ix))
		esw_warn(tc_arbiter_node->esw->dev,
			 "Failed to destroy vport rate limit element (vport=%d)\n",
			 vport->vport);

err_create_rate_limit:
	kfree(vport->qos.tc.sched_nodes);
	memset(&vport->qos.tc, 0, sizeof(vport->qos.tc));

	return err;
}

static int esw_qos_vport_tc_prepare(struct mlx5_vport *vport, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node, *parent;
	int err;

	esw_assert_qos_lock_held(vport->dev->priv.eswitch);
	vport_node = vport->qos.sched_node;
	if (!vport_node)
		return 0;

	parent = vport_node->parent;
	err = mlx5_destroy_scheduling_element_cmd(parent->esw->dev, SCHEDULING_HIERARCHY_E_SWITCH,
						  vport_node->ix);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack,
				   "E-Switch destroying vport scheduling element for cleaning up the vport QoS failed.");
		return err;
	}

	/* Clear the bandwidth share for the vport node, preserving the
	 * min_rate and max_rate as they are shared with the TC QoS
	 * configuration.
	 */
	vport_node->bw_share = 0;

	list_del_init(&vport_node->entry);
	esw_qos_normalize_min_rate(parent->esw, parent, extack);

	return 0;
}

static int esw_qos_vport_qos_restore(struct mlx5_vport *vport, struct mlx5_esw_sched_node *parent,
				     struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node;
	int err;

	esw_assert_qos_lock_held(vport->dev->priv.eswitch);
	vport_node = vport->qos.sched_node;
	if (!vport_node)
		return 0;

	/* Validate that the parent node is a tsar for vports nodes,
	 * else we cannot restore the vport QoS.
	 */
	if (parent->type != SCHED_NODE_TYPE_VPORTS_TSAR &&
	    parent->type != SCHED_NODE_TYPE_VPORTS_AND_TC_ARBITERS_TSAR) {
		err = -EIO;
		NL_SET_ERR_MSG_MOD(extack,
				   "E-Switch cannot restore vport QoS to non vports parent node.");
		return err;
	}

	err = esw_qos_vport_create_sched_element(vport, parent, vport_node->max_rate, 0,
						 &vport_node->ix);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack,
				   "E-Switch creating vport scheduling element for restoring the vport QoS failed.");
		return err;
	}

	esw_qos_node_set_parent(vport_node, parent);
	esw_qos_normalize_min_rate(parent->esw, parent, extack);

	return 0;
}

int esw_qos_vport_tc_disable(struct mlx5_vport *vport,
			     struct mlx5_esw_sched_node *node,
			     struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	struct mlx5_esw_sched_node *tc_arbiter_node;
	int err;

	esw_assert_qos_lock_held(esw);

	/* Save current state if we need to restore. */
	tc_arbiter_node = vport->qos.tc.arbiter_node;
	if (!tc_arbiter_node)
		return 0;

	/* Cleanup vport TC level QoS configurations. */
	err = esw_qos_cleanup_vport_tcs(vport, false, extack);
	if (err)
		return err;

	node = node ?: esw->qos.node0;
	/* Restore the vport level QoS.*/
	err = esw_qos_vport_qos_restore(vport, node, extack);
	if (err) {
		if (esw_qos_init_vport_tcs(vport, tc_arbiter_node, extack))
			esw_warn(esw->dev, "vport tc restore failed (vport=%d)\n", vport->vport);
	}

	return err;
}


static int esw_qos_vport_tc_enable(struct mlx5_vport *vport,
				   struct mlx5_esw_sched_node *tc_arbiter_node,
				   struct netlink_ext_ack *extack)
{
	int err;

	esw_assert_qos_lock_held(vport->dev->priv.eswitch);

	if (!MLX5_CAP_QOS(tc_arbiter_node->esw->dev, log_esw_max_rate_limit))
		return -EOPNOTSUPP;

	if (vport->qos.tc.arbiter_node)
		return 0;

	/* Cleanup the regular QoS configurations. */
	err = esw_qos_vport_tc_prepare(vport, extack);
	if (err)
		return err;

	/* Initialize the vport TC level QoS. */
	err = esw_qos_init_vport_tcs(vport, tc_arbiter_node, extack);
	if (err) {
		if (esw_qos_vport_qos_restore(vport, vport->qos.sched_node->parent, extack))
			esw_warn(vport->dev,
				 "vport restore QoS settings failed (vport=%d)\n", vport->vport);
	}

	return err;
}


static void
esw_qos_restore_vports_in_tc_arbiter_node(struct mlx5_esw_sched_node *tc_arbiter_node,
					  struct mlx5_esw_sched_node *node,
					  struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vports_tc_node;

	list_for_each_entry(vports_tc_node, &tc_arbiter_node->children, entry) {
		struct mlx5_esw_sched_node *child, *tmp;

		list_for_each_entry_safe(child, tmp, &vports_tc_node->children, entry) {
			if (esw_qos_cleanup_vport_tcs(child->vport, true, extack))
				continue;

			/* Try restoring the vport level QoS only if we
			 * were able to destroy all the vport tc level QoS.
			 */
			if (esw_qos_vport_qos_restore(child->vport, node, extack))
				esw_warn(child->vport->dev,
					 "vport restore failed (vport=%d)\n", child->vport->vport);
		}
	}
}

static int
esw_qos_disable_tc_qos_for_vports(struct mlx5_esw_sched_node *tc_arbiter_node,
				  struct mlx5_esw_sched_node *node,
				  struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vports_tc_node, *child, *tmp;
	struct mlx5_vport *vport;
	int err = 0;

	list_for_each_entry(vports_tc_node, &tc_arbiter_node->children, entry) {
		list_for_each_entry_safe(child, tmp, &vports_tc_node->children, entry) {
			vport = child->vport;
			/* Disable TC QoS for the current vport and assign it to the node. */
			err = esw_qos_vport_tc_disable(vport, node, extack);
			if (err)
				goto err_out;
		}
	}

	return err;

err_out:
	/* On error, enable TC QoS for the previously disabled vports. */
	list_for_each_entry_safe(child, tmp, &node->children, entry) {
		vport = child->vport;
		/* Re-enable TC QoS and reassign the vport to the TC arbiter node */
		if (esw_qos_vport_tc_enable(vport, tc_arbiter_node, extack))
			esw_warn(vport->dev, "Failed to restore vport tc QoS %d\n", vport->vport);
	}

	return err;
}

static int
esw_qos_tc_arbiter_node_disable_tc_qos(struct mlx5_esw_sched_node *tc_arbiter_node,
				       struct mlx5_esw_sched_node *node,
				       struct netlink_ext_ack *extack)
{
	u32 parent_tsar_ix;
	int err;

	parent_tsar_ix = node->parent ? node->parent->ix :
			 node->esw->qos.root_tsar_ix;

	/* Create scheduling element for the node. */
	err = esw_qos_create_node_sched_elem(node->esw->dev, parent_tsar_ix, node->max_rate,
					     node->bw_share, &node->ix);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Failed to create scheduling element for vports node when disabliing vports TC QoS");
		return err;
	}

	/* Disable TC QoS for vports in the arbiter node. */
	err = esw_qos_disable_tc_qos_for_vports(tc_arbiter_node, node, extack);
	if (err) {
		/* If disabling fails, destroy the scheduling element created earlier. */
		mlx5_destroy_scheduling_element_cmd(node->esw->dev, SCHEDULING_HIERARCHY_E_SWITCH,
						    node->ix);
		esw_warn(node->esw->dev, "vports node destroy scheduling element failed.\n");
	}

	return err;
}

static int
esw_qos_tc_qos_enable_for_vports_in_node(struct mlx5_esw_sched_node *node,
					 struct mlx5_esw_sched_node *tc_arbiter_node,
					 struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node, *tmp;
	int err;

	/* Enable TC QoS for each vport in the node. */
	list_for_each_entry_safe(vport_node, tmp, &node->children, entry) {
		err = esw_qos_vport_tc_enable(vport_node->vport, tc_arbiter_node, extack);
		if  (err)
			goto err_out;
	}

	/* Destroy the current vports node TSAR. */
	err = mlx5_destroy_scheduling_element_cmd(node->esw->dev, SCHEDULING_HIERARCHY_E_SWITCH,
						  node->ix);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Destroy current vports node TSAR failed when enabling vports TC QoS");
		goto err_out;
	}

	return err;

err_out:
	/* Restore vports in TC arbiter node if an error occurs. */
	esw_qos_restore_vports_in_tc_arbiter_node(tc_arbiter_node, node, extack);

	return err;
}

static struct mlx5_esw_sched_node *
esw_qos_copy_tc_arbiter_node(struct mlx5_esw_sched_node *curr_node)
{
	struct mlx5_esw_sched_node *vports_tc_node, *tmp;
	struct mlx5_esw_sched_node *new_node;

	new_node = __esw_qos_alloc_node(curr_node->esw, curr_node->ix, curr_node->type, NULL);
	if (!IS_ERR(new_node)) {
		list_for_each_entry_safe(vports_tc_node, tmp, &curr_node->children, entry) {
			esw_qos_node_set_parent(vports_tc_node, new_node);
		}
	}

	return new_node;
}

static void esw_qos_restore_vports_to_node(struct mlx5_esw_sched_node *curr_node,
					   struct mlx5_esw_sched_node *new_node)
{
	struct mlx5_esw_sched_node *vport_node, *tmp;

	list_for_each_entry_safe(vport_node, tmp, &curr_node->children, entry) {
		esw_qos_node_set_parent(vport_node, new_node);
	}

	list_del_init(&curr_node->entry);
	kfree(curr_node);
}

static struct mlx5_esw_sched_node *
esw_qos_copy_vports_node(struct mlx5_esw_sched_node *curr_node)
{
	struct mlx5_esw_sched_node *new_node, *vport_node, *tmp;

	new_node = __esw_qos_alloc_node(curr_node->esw, curr_node->ix, curr_node->type, NULL);
	if (!IS_ERR(new_node)) {
		list_for_each_entry_safe(vport_node, tmp, &curr_node->children, entry) {
			esw_qos_node_set_parent(vport_node, new_node);
		}
	}

	return new_node;
}

static int esw_qos_node_disable_tc_arbitration(struct mlx5_esw_sched_node *node,
					       struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *curr_node, *vport_node, *tmp;
	int err;

	if (node->type != SCHED_NODE_TYPE_TC_ARBITER_TSAR)
		return 0;

	/* Allocate a new rate node to hold the current state, which will allow
	 * for restoring the vports back to this node after disabling TC arbitration.
	 */
	curr_node = esw_qos_copy_tc_arbiter_node(node);
	if (IS_ERR(curr_node)) {
		NL_SET_ERR_MSG_MOD(extack, "Failed setting up vports node");

		return PTR_ERR(curr_node);
	}

	node->type = SCHED_NODE_TYPE_VPORTS_TSAR;
	/* Disable TC QoS for all vports, and assign them back to the node. */
	err = esw_qos_tc_arbiter_node_disable_tc_qos(curr_node, node, extack);
	if (err)
		goto err_disable_vports_tc;

	/* Clean up the TC arbiter node after disabling TC QoS for vports. */
	err = esw_qos_tc_arbiter_scheduling_teardown(curr_node, false, extack);
	if (err)
		goto err_tc_arbiter_node_cleanup;

	list_del_init(&curr_node->entry);
	kfree(curr_node);

	return err;

err_tc_arbiter_node_cleanup:
	/* Attempt to restore vports to the original node if cleanup fails. */
	list_for_each_entry_safe(vport_node, tmp, &node->children, entry) {
		if (esw_qos_vport_tc_enable(vport_node->vport, curr_node, extack))
			esw_warn(vport_node->vport->dev, "TC Arbiter node restore failed\n");
	}

 err_disable_vports_tc:
	/* Restore original node type if disabling TC QoS failed. */
	node->type = curr_node->type;
	node->ix = curr_node->ix;
	list_del_init(&curr_node->entry);
	kfree(curr_node);

	return err;
}

static int esw_qos_node_enable_tc_arbitration(struct mlx5_esw_sched_node *node,
					      struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *curr_node;
	int err;

	if (node->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR)
		return 0;

	/* Check if any vport within the node has TC QoS already enabled.
	 * TC QoS cannot be enabled for the entire node if any member vport
	 * already has individual TC QoS enabled.
	 */
	if (node->type == SCHED_NODE_TYPE_VPORTS_AND_TC_ARBITERS_TSAR) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cannot enable node TC QoS: assigned vport has TC QoS enabled");

		return -EOPNOTSUPP;
	}

	/* Allocate a new node that will store the information of the current node.
	 * This will be used later to restore the node if necessary.
	 */
	curr_node = esw_qos_copy_vports_node(node);
	if (IS_ERR(curr_node)) {
		NL_SET_ERR_MSG_MOD(extack, "Failed setting up node TC QoS");

		return PTR_ERR(curr_node);
	}

	/* Initialize the TC arbiter node for QoS management.
	 * This step prepares the node for handling Traffic Class arbitration.
	 */
	node->type = SCHED_NODE_TYPE_TC_ARBITER_TSAR;
	err = esw_qos_tc_arbiter_scheduling_setup(node, node->parent, extack);
	if (err)
		goto err_tc_arbiter_init;

	/* Enable TC QoS for each vport within the current node. */
	err = esw_qos_tc_qos_enable_for_vports_in_node(curr_node, node, extack);
	if (err)
		goto err_node_enable_vports_tc;

	list_del_init(&curr_node->entry);
	kfree(curr_node);

	return err;

err_node_enable_vports_tc:
	/* Teardown the TC arbiter node if enabling TC for vports failed. */
	esw_qos_tc_arbiter_scheduling_teardown(node, true, NULL);

err_tc_arbiter_init:
	/* Restore the original node. */
	node->type = curr_node->type;
	node->ix = curr_node->ix;
	esw_qos_restore_vports_to_node(curr_node, node);

	return err;
}

bool esw_qos_tc_arbitration_enabled_on_vport(struct mlx5_vport *vport)
{
	struct mlx5_esw_sched_node *parent;

	if (!vport->qos.tc.arbiter_node)
		return false;

	parent = vport->qos.tc.arbiter_node->parent;
	if (!parent)
		return false;

	return (parent->type == SCHED_NODE_TYPE_VPORTS_AND_TC_ARBITERS_TSAR);
}

static int esw_qos_destroy_tc_arbiter_node(struct mlx5_vport *vport, bool force,
					   struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *parent, *tc_arbiter_node;
	int err, ret = 0;

	tc_arbiter_node = vport->qos.tc.arbiter_node;
	parent = tc_arbiter_node->parent;
	list_del(&tc_arbiter_node->entry);
	err = esw_qos_vport_tc_disable(vport, parent, extack);
	if (err) {
		ret = err;
		if (!force) {
			list_add_tail(&tc_arbiter_node->entry, &parent->children);
			return ret;
		}
	}

	err = esw_qos_tc_arbiter_scheduling_teardown(tc_arbiter_node, false, extack);
	if (err) {
		ret = err;
		if (!force) {
			esw_qos_vport_tc_enable(vport, tc_arbiter_node, extack);
			return ret;
		}
	}

	kfree(tc_arbiter_node);
	if (!esw_sched_node_has_tc_arbiter(parent))
		parent->type = SCHED_NODE_TYPE_VPORTS_TSAR;

	return ret;
}

int esw_qos_vport_disable_tc_arbitration(struct mlx5_vport *vport,
					 struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;

	esw_assert_qos_lock_held(esw);

	if (!vport->qos.tc.arbiter_node)
		return 0;

	if (!esw_qos_tc_arbitration_enabled_on_vport(vport)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cannot disable TC arbitration on vport assigned to a node with TC arbitration enabled");
		return -EOPNOTSUPP;
	}

	return esw_qos_destroy_tc_arbiter_node(vport, false, extack);
}

static int esw_qos_vport_enable_tc_arbitration(struct mlx5_vport *vport,
					       struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	struct mlx5_esw_sched_node *tc_arbiter_node;
	int err;

	esw_assert_qos_lock_held(esw);
	/* Check if TC arbitration is already enabled on this vport,
	 * or if it's part of a node with TC arbitration enabled.
	 */
	if (vport->qos.tc.arbiter_node) {
		if (!esw_qos_tc_arbitration_enabled_on_vport(vport)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Cannot enable TC arbitration on vport assigned to a node with TC arbitration enabled");
			return -EOPNOTSUPP;
		}

		return 0;
	}

	if (MLX5_CAP_QOS(esw->dev, log_esw_max_sched_depth) < 2) {
		NL_SET_ERR_MSG_MOD(extack, "Setting up TC Arbiter for a vport is not supported.");
		return -EOPNOTSUPP;
	}

	tc_arbiter_node = esw_qos_create_tc_arbiter_node(vport, extack);
	if (IS_ERR(tc_arbiter_node))
		return PTR_ERR(tc_arbiter_node);

	vport_node->parent->type = SCHED_NODE_TYPE_VPORTS_AND_TC_ARBITERS_TSAR;

	err =  esw_qos_vport_tc_enable(vport, tc_arbiter_node, extack);
	if (err) {
		esw_qos_destroy_tc_arbiter_node(vport, true, NULL);
	}

	return err;
}

int esw_qos_vport_enable(struct mlx5_vport *vport, u32 max_rate, u32 bw_share,
			 struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	u32 sched_elem_ix;
	int err;

	esw_assert_qos_lock_held(esw);
	if (vport->qos.sched_node)
		return 0;

	err = esw_qos_get(esw, extack);
	if (err)
		return err;

	err = esw_qos_vport_create_sched_element(vport, esw->qos.node0, max_rate, bw_share,
						 &sched_elem_ix);
	if (err)
		goto err_out;

	vport->qos.sched_node = __esw_qos_alloc_node(esw, sched_elem_ix, SCHED_NODE_TYPE_VPORT,
						     esw->qos.node0);
	if (!vport->qos.sched_node) {
		err = -ENOMEM;
		goto err_alloc;
	}

	vport->qos.sched_node->vport = vport;
	esw->qos.node0->num_vports++;

	trace_mlx5_esw_vport_qos_create(vport->dev, vport, bw_share, max_rate);

	return 0;

err_alloc:
	if (mlx5_destroy_scheduling_element_cmd(esw->dev,
						SCHEDULING_HIERARCHY_E_SWITCH, sched_elem_ix))
		esw_warn(esw->dev, "E-Switch destroy vport scheduling element failed.\n");
err_out:
	esw_qos_put(esw);

	return err;
}

void mlx5_esw_qos_vport_disable(struct mlx5_vport *vport)
{
	struct mlx5_esw_sched_node *vport_node, *tc_arbiter_node;
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	struct mlx5_core_dev *dev;
	int err;

	lockdep_assert_held(&esw->state_lock);
	esw_qos_lock(esw);
	vport_node = vport->qos.sched_node;
	if (!vport_node)
		goto unlock;
	WARN(vport_node->parent != esw->qos.node0,
	     "Disabling QoS on port before detaching it from node");

	tc_arbiter_node = vport->qos.tc.arbiter_node;
	dev = tc_arbiter_node ? tc_arbiter_node->esw->dev : vport_node->esw->dev;
	trace_mlx5_esw_vport_qos_destroy(dev, vport);

	if (tc_arbiter_node) {
		struct mlx5_esw_sched_node *parent = tc_arbiter_node->parent;

		esw_qos_cleanup_vport_tcs(vport, true, NULL);
		/* Destroy the TC arbiter if the tc arbitration is on the
		 * vport.
		 */
		if (parent) {
			esw_qos_tc_arbiter_scheduling_teardown(tc_arbiter_node, true,
							       NULL);
			kfree(tc_arbiter_node);
			if (!esw_sched_node_has_tc_arbiter(parent))
				parent->type = SCHED_NODE_TYPE_VPORTS_TSAR;
		} else {
			esw_qos_destroy_sysfs_rate_group(esw, vport, tc_arbiter_node);
		}
	} else {
		err = mlx5_destroy_scheduling_element_cmd(dev,
							  SCHEDULING_HIERARCHY_E_SWITCH,
							  vport_node->ix);
		if (err)
			esw_warn(dev,
				 "E-Switch destroy vport scheduling element failed (vport=%d,err=%d)\n",
				 vport->vport, err);
		esw_qos_destroy_sysfs_rate_group(esw, vport, vport_node->parent);
	}

	__esw_qos_free_node(vport_node);
	memset(&vport->qos, 0, sizeof(vport->qos));

	esw_qos_put(esw);
unlock:
	esw_qos_unlock(esw);
}

static int esw_qos_set_vport_tc_min_rate(struct mlx5_vport *vport,
					 u64 tx_share, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *tc_arbiter_node;
	int err = 0, i, num_tcs;
	u32 *tcs_min_rate;

	esw_assert_qos_lock_held(vport->dev->priv.eswitch);

	tc_arbiter_node = vport->qos.tc.arbiter_node;
	num_tcs = esw_qos_num_tcs(tc_arbiter_node->esw->dev);

	/* Allocate memory for storing the current min rate for rollback in case of failure. */
	tcs_min_rate = kcalloc(num_tcs, sizeof(u32), GFP_KERNEL);
	if (!tcs_min_rate) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to setup TX share for vport");
		return -ENOMEM;
	}

	/* Iterate over each traffic class (TC) and update the min rate. */
	for (i = 0; i < num_tcs; i++) {
		tcs_min_rate[i] = vport->qos.tc.sched_nodes[i]->min_rate;
		vport->qos.tc.sched_nodes[i]->min_rate = tx_share;
	}

	err = esw_qos_normalize_vports_tcs(tc_arbiter_node, false, extack);
	if (err)
		goto err_out;

	kfree(tcs_min_rate);

	return 0;

err_out:
	for (i = 0; i < num_tcs; i++)
		vport->qos.tc.sched_nodes[i]->min_rate = tcs_min_rate[i];

	if (esw_qos_normalize_vports_tcs(tc_arbiter_node, true, extack))
		esw_warn(vport->dev, "Failed to restore TC arbiter");

	kfree(tcs_min_rate);
	return err;
}

int mlx5_esw_qos_set_vport_tc_min_rate(struct mlx5_eswitch *esw, struct mlx5_vport *vport,
				       u64 tx_share, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *tc_arbiter_node, *parent_node;
	u32 act_min_rate;
	int err;

	/* If the tc arbitration is not on the vport, update the vports tc. */
	if (!esw_qos_tc_arbitration_enabled_on_vport(vport))
		return esw_qos_set_vport_tc_min_rate(vport, tx_share, extack);

	tc_arbiter_node = vport->qos.tc.arbiter_node;
	parent_node = tc_arbiter_node->parent;
	act_min_rate =  tc_arbiter_node->min_rate;
	if (act_min_rate == tx_share)
		return 0;

	tc_arbiter_node->min_rate = tx_share;
	err = esw_qos_normalize_min_rate(parent_node->esw, parent_node, extack);
	if (err)
		tc_arbiter_node->min_rate = act_min_rate;

	return err;
}

static int esw_qos_vport_tc_set_max_rate(struct mlx5_vport *vport, u32 max_rate)
{
	struct mlx5_esw_sched_node *tc_arbiter_node = vport->qos.tc.arbiter_node;
	int err;

	esw_assert_qos_lock_held(vport->dev->priv.eswitch);
	if (vport->qos.sched_node->max_rate == max_rate)
		return 0;

	err = esw_qos_rate_limit_config(tc_arbiter_node->esw->dev,
					vport->qos.tc.esw_rate_limit_elem_ix,
					max_rate);
	if (err)
		return err;

	if (tc_arbiter_node->parent) {
		err = esw_qos_rate_limit_config(tc_arbiter_node->esw->dev,
						tc_arbiter_node->ix,
						max_rate);
		if (err) {
			esw_qos_rate_limit_config(tc_arbiter_node->esw->dev,
						  vport->qos.tc.esw_rate_limit_elem_ix,
						  vport->qos.sched_node->max_rate);
			return err;
		}

		tc_arbiter_node->max_rate = max_rate;
	}

	vport->qos.sched_node->max_rate = max_rate;
	return 0;
}

int mlx5_esw_qos_set_vport_rate(struct mlx5_vport *vport, u32 max_rate, u32 min_rate)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	int err;

	esw_qos_lock(esw);

	if (vport->qos.tc.arbiter_node) {
		err = mlx5_esw_qos_set_vport_tc_min_rate(esw, vport, min_rate, NULL);
		if (err)
			goto unlock;

		vport->qos.sched_node->min_rate = min_rate;
		err = esw_qos_vport_tc_set_max_rate(vport, max_rate);
		goto unlock;
	}

	err = esw_qos_vport_enable(vport, 0, 0, NULL);
	if (err)
		goto unlock;

	err = esw_qos_set_vport_min_rate(vport, min_rate, NULL);
	if (!err)
		err = esw_qos_set_vport_max_rate(vport, max_rate, NULL);
unlock:
	esw_qos_unlock(esw);
	return err;
}

bool mlx5_esw_qos_get_vport_rate(struct mlx5_vport *vport, u32 *max_rate, u32 *min_rate)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	bool enabled;

	/* Opportunistic check to avoid locking below if unnecessary. */
	if (!vport->qos.sched_node)
		return false;

	esw_qos_lock(esw);
	enabled = !!vport->qos.sched_node;
	if (enabled) {
		*max_rate = vport->qos.sched_node->max_rate;
		*min_rate = vport->qos.sched_node->min_rate;
	}
	esw_qos_unlock(esw);
	return enabled;
}

static u32 mlx5_esw_qos_lag_link_speed_get_locked(struct mlx5_core_dev *mdev)
{
	struct ethtool_link_ksettings lksettings;
	struct net_device *slave, *master;
	u32 speed = SPEED_UNKNOWN;

	/* Lock ensures a stable reference to master and slave netdevice
	 * while port speed of master is queried.
	 */
	ASSERT_RTNL();

	slave = mlx5_uplink_netdev_get(mdev);
	if (!slave)
		goto out;

	master = netdev_master_upper_dev_get(slave);
	if (master && !__ethtool_get_link_ksettings(master, &lksettings))
		speed = lksettings.base.speed;

out:
	return speed;
}

static int mlx5_esw_qos_max_link_speed_get(struct mlx5_core_dev *mdev, u32 *link_speed_max,
					   bool hold_rtnl_lock, struct netlink_ext_ack *extack)
{
	int err;

	if (!mlx5_lag_is_active(mdev))
		goto skip_lag;

	if (hold_rtnl_lock)
		rtnl_lock();

	*link_speed_max = mlx5_esw_qos_lag_link_speed_get_locked(mdev);

	if (hold_rtnl_lock)
		rtnl_unlock();

	if (*link_speed_max != (u32)SPEED_UNKNOWN)
		return 0;

skip_lag:
	err = mlx5_port_max_linkspeed(mdev, link_speed_max);
	if (err)
		NL_SET_ERR_MSG_MOD(extack, "Failed to get link maximum speed");

	return err;
}

static int mlx5_esw_qos_link_speed_verify(struct mlx5_core_dev *mdev,
					  const char *name, u32 link_speed_max,
					  u64 value, struct netlink_ext_ack *extack)
{
	if (value > link_speed_max) {
		pr_err("%s rate value %lluMbps exceed link maximum speed %u.\n",
		       name, value, link_speed_max);
		NL_SET_ERR_MSG_MOD(extack, "TX rate value exceed link maximum speed");
		return -EINVAL;
	}

	return 0;
}

int mlx5_esw_qos_modify_vport_rate(struct mlx5_eswitch *esw, u16 vport_num, u32 rate_mbps)
{
	u32 ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	struct mlx5_vport *vport;
	u32 link_speed_max;
	u32 bitmask;
	int err;

	vport = mlx5_eswitch_get_vport(esw, vport_num);
	if (IS_ERR(vport))
		return PTR_ERR(vport);

	if (rate_mbps) {
		err = mlx5_esw_qos_max_link_speed_get(esw->dev, &link_speed_max, false, NULL);
		if (err)
			return err;

		err = mlx5_esw_qos_link_speed_verify(esw->dev, "Police",
						     link_speed_max, rate_mbps, NULL);
		if (err)
			return err;
	}

	esw_qos_lock(esw);
	if (!vport->qos.sched_node) {
		/* Eswitch QoS wasn't enabled yet. Enable it and vport QoS. */
		err = esw_qos_vport_enable(vport, rate_mbps, 0, NULL);
	} else {
		struct mlx5_core_dev *dev = vport->qos.sched_node->parent->esw->dev;

		MLX5_SET(scheduling_context, ctx, max_average_bw, rate_mbps);
		bitmask = MODIFY_SCHEDULING_ELEMENT_IN_MODIFY_BITMASK_MAX_AVERAGE_BW;
		err = mlx5_modify_scheduling_element_cmd(dev,
							 SCHEDULING_HIERARCHY_E_SWITCH,
							 ctx,
							 vport->qos.sched_node->ix,
							 bitmask);
	}
	esw_qos_unlock(esw);

	return err;
}

#define MLX5_LINKSPEED_UNIT 125000 /* 1Mbps in Bps */

/* Converts bytes per second value passed in a pointer into megabits per
 * second, rewriting last. If converted rate exceed link speed or is not a
 * fraction of Mbps - returns error.
 */
static int esw_qos_devlink_rate_to_mbps(struct mlx5_core_dev *mdev, const char *name,
					u64 *rate, struct netlink_ext_ack *extack)
{
	u32 link_speed_max, remainder;
	u64 value;
	int err;

	value = div_u64_rem(*rate, MLX5_LINKSPEED_UNIT, &remainder);
	if (remainder) {
		pr_err("%s rate value %lluBps not in link speed units of 1Mbps.\n",
		       name, *rate);
		NL_SET_ERR_MSG_MOD(extack, "TX rate value not in link speed units of 1Mbps");
		return -EINVAL;
	}

	err = mlx5_esw_qos_max_link_speed_get(mdev, &link_speed_max, true, extack);
	if (err)
		return err;

	err = mlx5_esw_qos_link_speed_verify(mdev, name, link_speed_max, value, extack);
	if (err)
		return err;

	*rate = value;
	return 0;
}

static bool esw_qos_groups_are_supported(struct mlx5_core_dev *dev)
{
	return MLX5_CAP_GEN(dev, qos) &&
	       MLX5_CAP_QOS(dev, log_esw_max_sched_depth) &&
	       MLX5_CAP_QOS(dev, esw_scheduling);
}

static struct mlx5_esw_sched_node *
esw_qos_find_sysfs_group(struct mlx5_eswitch *esw, u32 group_id)
{
	struct mlx5_esw_sched_node *tmp;

	esw_assert_qos_lock_held(esw);
	list_for_each_entry(tmp, &esw->qos.domain->nodes, entry) {
		if (tmp->esw != esw)
			continue;
		if (tmp->group_id == MLX5_ESW_QOS_NON_SYSFS_GROUP)
			continue;
		if (tmp->group_id == group_id)
			return tmp;
	}

	return NULL;
}

int mlx5_esw_qos_vport_update_sysfs_group(struct mlx5_eswitch *group_esw, u32 group_id,
					  struct mlx5_vport *vport)
{
	struct mlx5_esw_sched_node *tc_arbiter_node = vport->qos.tc.arbiter_node;
	struct mlx5_eswitch *vport_esw = vport->dev->priv.eswitch;
	struct mlx5_esw_sched_node *curr_group, *new_group;
	int err = 0;

	if (!esw_qos_groups_are_supported(group_esw->dev))
		return -EOPNOTSUPP;

	esw_qos_lock(group_esw);

	err = esw_qos_vport_enable(vport, 0, 0, NULL);
	if (err)
		goto out;

	curr_group = mlx5_esw_qos_vport_get_parent(vport);
	if (curr_group->esw == group_esw && curr_group->group_id == group_id)
		goto out;

	if (group_id) {
		new_group = esw_qos_find_sysfs_group(group_esw, group_id);
		if (!new_group) {
			new_group = esw_qos_create_vports_sched_node(group_esw, group_id, NULL);
			if (IS_ERR(new_group)) {
				err = PTR_ERR(new_group);
				esw_warn(group_esw->dev,
					 "E-Switch couldn't create new sysfs group %d (%d)\n",
					 group_id, err);
				esw_qos_unlock(group_esw);
				return err;
			}
		}
	} else {
		new_group = vport_esw->qos.node0;
	}

	if (new_group->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR) {
		if (esw_qos_tc_arbitration_enabled_on_vport(vport)) {
			esw_warn(vport_esw->dev, "TC arbitration already enabled for vport");
				err = -EOPNOTSUPP;
				esw_qos_unlock(group_esw);
				return err;
			}
		err = esw_qos_vport_tc_update_node(vport, new_group, NULL);
		goto update_out;
	}

	if (esw_qos_tc_arbitration_enabled_on_vport(vport)) {
		err = mlx5_esw_qos_vport_tc_update_tc_arbitration_node(vport, new_group, NULL);
		goto update_out;
	}

	if (tc_arbiter_node)
		err = esw_qos_vport_tc_disable(vport, new_group, NULL);
	else
		err = esw_qos_update_node_scheduling_element(vport, curr_group, new_group, NULL);
update_out:
	if (err) {
		curr_group = new_group;
		goto curr_group_cleanup;
	}

	new_group->num_vports++;
	curr_group->num_vports--;

curr_group_cleanup:
	if (curr_group->group_id != 0 && !curr_group->num_vports) {
		if (curr_group->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR) {
			esw_qos_destroy_vports_tc_nodes(curr_group, true, NULL);
		}

		esw_qos_destroy_node(curr_group, NULL);
	}

out:
	esw_qos_unlock(group_esw);
	return err;
}

int mlx5_esw_qos_set_sysfs_group_max_rate(struct mlx5_eswitch *esw,
					  struct mlx5_esw_sched_node *group,
					  u32 max_rate)
{
	int err;

	if (!esw_qos_groups_are_supported(esw->dev) ||
	    !MLX5_CAP_QOS(esw->dev, esw_rate_limit))
		return -EOPNOTSUPP;

	if (!mutex_trylock(&esw->qos.domain->lock))
		return -EBUSY;

	if (!esw_qos_find_sysfs_group(esw, group->group_id)) {
		err = -EINVAL;
		goto unlock;
	}

	err = esw_qos_set_node_max_rate(group, max_rate, NULL);
unlock:
	mutex_unlock(&esw->qos.domain->lock);
	return err;
}

int mlx5_esw_qos_set_sysfs_group_min_rate(struct mlx5_eswitch *esw,
					  struct mlx5_esw_sched_node *group,
					  u32 min_rate)
{
	int err = 0;

	if (!MLX5_CAP_GEN(esw->dev, qos) ||
	    !MLX5_CAP_QOS(esw->dev, log_esw_max_sched_depth))
		return -EOPNOTSUPP;

	if (!mutex_trylock(&esw->qos.domain->lock))
		return -EBUSY;

	if (!esw_qos_find_sysfs_group(esw, group->group_id)) {
		err = -EINVAL;
		goto unlock;
	}

	err = esw_qos_set_node_min_rate(group, min_rate, NULL);
unlock:
	mutex_unlock(&esw->qos.domain->lock);

	return err;
}

static bool esw_qos_validate_unsupported_tc_bw(struct mlx5_eswitch *esw, u32 *tc_bw)
{
	int i, num_tcs = esw_qos_num_tcs(esw->dev);

	for (i = num_tcs; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (tc_bw[i])
			return false;
	}

	return true;
}

static bool esw_qos_vport_validate_unsupported_tc_bw(struct mlx5_vport *vport, u32 *tc_bw)
{
	struct mlx5_esw_sched_node *parent = mlx5_esw_qos_vport_get_parent(vport);
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;

	if (parent)
		esw = parent->esw;

	return esw_qos_validate_unsupported_tc_bw(esw, tc_bw);
}

int mlx5_esw_qos_init(struct mlx5_eswitch *esw)
{
	bool use_shared_domain = esw->mode == MLX5_ESWITCH_OFFLOADS &&
		MLX5_CAP_QOS(esw->dev, esw_cross_esw_sched);

	if (esw->qos.domain) {
		if (esw->qos.domain->shared == use_shared_domain)
			return 0;  /* Nothing to change. */
		esw_qos_domain_release(esw);
	}

	return esw_qos_domain_init(esw, use_shared_domain);
}

void mlx5_esw_qos_cleanup(struct mlx5_eswitch *esw)
{
	if (esw->qos.domain)
		esw_qos_domain_release(esw);
}

int mlx5_esw_rate_leaf_tx_max_set(struct mlx5_eswitch *esw, struct mlx5_vport *vport,
				  u64 tx_max, struct netlink_ext_ack *extack)
{
	int err;

	if (!mlx5_esw_allowed(esw))
		return -EPERM;

	esw_qos_lock(esw);
	if (!vport->qos.sched_node && !tx_max)
		goto unlock;

	if (vport->qos.tc.arbiter_node) {
		err = esw_qos_vport_tc_set_max_rate(vport, tx_max);
		goto unlock;
	}

	err = esw_qos_vport_enable(vport, 0, 0, extack);
	if (err)
		goto unlock;

	err = esw_qos_set_vport_max_rate(vport, tx_max, extack);
unlock:
	esw_qos_unlock(esw);
	return err;
}

/* Eswitch devlink rate API */
#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
int mlx5_esw_devlink_rate_leaf_tx_share_set(struct devlink_rate *rate_leaf, void *priv,
					    u64 tx_share, struct netlink_ext_ack *extack)
{
	struct mlx5_vport *vport = priv;
	struct mlx5_eswitch *esw;
	int err;

	esw = vport->dev->priv.eswitch;
	if (!mlx5_esw_allowed(esw))
		return -EPERM;

	err = esw_qos_devlink_rate_to_mbps(vport->dev, "tx_share", &tx_share, extack);
	if (err)
		return err;

	esw_qos_lock(esw);
	if (vport->qos.tc.arbiter_node) {
		err = mlx5_esw_qos_set_vport_tc_min_rate(esw, vport, tx_share, extack);
		if (!err)
			vport->qos.sched_node->min_rate = tx_share;
		goto unlock;
	}

	err = esw_qos_vport_enable(vport, 0, 0, extack);
	if (err)
		goto unlock;

	err = esw_qos_set_vport_min_rate(vport, tx_share, extack);
unlock:
	esw_qos_unlock(esw);
	return err;
}

int mlx5_esw_devlink_rate_leaf_tx_max_set(struct devlink_rate *rate_leaf, void *priv,
					  u64 tx_max, struct netlink_ext_ack *extack)
{
	struct mlx5_vport *vport = priv;
	struct mlx5_eswitch *esw;
	int err;

	esw = vport->dev->priv.eswitch;
	if (!mlx5_esw_allowed(esw))
		return -EPERM;

	err = esw_qos_devlink_rate_to_mbps(vport->dev, "tx_max", &tx_max, extack);
	if (err)
		return err;

	esw_qos_lock(esw);

	if (vport->qos.tc.arbiter_node) {
		err = esw_qos_vport_tc_set_max_rate(vport, tx_max);
		goto unlock;
	}

	err = esw_qos_vport_enable(vport, 0, 0, extack);
	if (err)
		goto unlock;

	err = esw_qos_set_vport_max_rate(vport, tx_max, extack);
unlock:
	esw_qos_unlock(esw);
	return err;
}
#endif

static int
mlx5_esw_qos_update_tc_arbiter_node(struct mlx5_esw_sched_node *tc_arbiter_node, u32 *new_tc_bw,
				    struct netlink_ext_ack *extack)
{
	int num_tcs = esw_qos_num_tcs(tc_arbiter_node->esw->dev);
	struct mlx5_esw_sched_node *vports_tc_node;
	u32 *orig_tc_bw;
	int err = 0;
	u8 tc;

	orig_tc_bw = kcalloc(num_tcs, sizeof(u32), GFP_KERNEL);
	if (!orig_tc_bw)
		return -ENOMEM;

	list_for_each_entry(vports_tc_node, &tc_arbiter_node->children, entry) {
		u32 bw_share;

		tc = vports_tc_node->tc;
		orig_tc_bw[tc] = vports_tc_node->bw_share;
		if (orig_tc_bw[tc] == new_tc_bw[tc] && new_tc_bw[tc])
			continue;

		bw_share = new_tc_bw[tc] ?: MLX5_MIN_BW_SHARE;
		err = esw_qos_sched_elem_config(vports_tc_node, 0, bw_share, extack);
		if (err)
			goto err_update_vports_tc_node;

		vports_tc_node->bw_share = bw_share;
	}

	kfree(orig_tc_bw);
	list_for_each_entry(vports_tc_node, &tc_arbiter_node->children, entry) {
		tc = vports_tc_node->tc;
		vports_tc_node->user_bw_share = new_tc_bw[tc];
	}

	return err;

err_update_vports_tc_node:
	list_for_each_entry(vports_tc_node, &tc_arbiter_node->children, entry) {
		tc = vports_tc_node->tc;
		if (orig_tc_bw[tc] == vports_tc_node->bw_share)
			continue;

		if (esw_qos_sched_elem_config(vports_tc_node, 0, orig_tc_bw[tc], extack)) {
			esw_warn(tc_arbiter_node->esw->dev, "E-Switch Restore Traffic Class node failed\n");
			break;
		}

		vports_tc_node->bw_share = orig_tc_bw[tc];
	}

	kfree(orig_tc_bw);

	return err;
}

static bool esw_qos_tc_bw_disabled(u32 *tc_bw)
{
	int i;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (tc_bw[i])
			return false;
	}

	return true;
}

static int rate_leaf_tc_bw_set(void *priv, u32 *tc_bw, struct netlink_ext_ack *extack)
{
	struct mlx5_vport *vport = priv;
	struct mlx5_eswitch *esw;
	bool disable;
	int err;

	esw = vport->dev->priv.eswitch;
	if (!mlx5_esw_allowed(esw))
		return -EPERM;

	esw_qos_lock(esw);

	if (!esw_qos_vport_validate_unsupported_tc_bw(vport, tc_bw)) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch traffic classes number is not supported");
		err = -EOPNOTSUPP;
		goto unlock;
	}

	disable = esw_qos_tc_bw_disabled(tc_bw);
	if (disable) {
		err = esw_qos_vport_disable_tc_arbitration(vport, extack);
		goto unlock;
	}

	err = esw_qos_vport_enable(vport, 0, 0, extack);
	if (err)
		goto unlock;

	err = esw_qos_vport_enable_tc_arbitration(vport, extack);
	if (err)
		goto unlock;

	err = mlx5_esw_qos_update_tc_arbiter_node(vport->qos.tc.arbiter_node, tc_bw, extack);
unlock:
	esw_qos_unlock(esw);

	return err;
}

#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
int mlx5_esw_devlink_rate_leaf_tc_bw_set(struct devlink_rate *rate_leaf, void *priv,
					 u32 *tc_bw, struct netlink_ext_ack *extack)
{
	return rate_leaf_tc_bw_set(priv, tc_bw, extack);
}
#endif

int mlx5_esw_sysfs_rate_leaf_tc_bw_set(void *priv, u32 *tc_bw, struct netlink_ext_ack *extack)
{
	return rate_leaf_tc_bw_set(priv, tc_bw, extack);
}

int mlx5_esw_devm_rate_leaf_tc_bw_set(void *priv, u32 *tc_bw, struct netlink_ext_ack *extack)
{
	return rate_leaf_tc_bw_set(priv, tc_bw, extack);
}

static int rate_node_tc_bw_set(void *priv, u32 *tc_bw, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node = priv;
	struct mlx5_eswitch *esw = node->esw;
	bool disable = true;
	int num_tcs, err, i;

	num_tcs = esw_qos_num_tcs(esw->dev);
	if (!esw_qos_validate_unsupported_tc_bw(esw, tc_bw)) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch traffic classes number is not supported");
		return -EOPNOTSUPP;
	}

	for (i = 0; i < num_tcs; i++) {
		if (tc_bw[i]) {
			disable = false;
			break;
		}
	}

	esw_qos_lock(esw);

	if (disable) {
		err = esw_qos_node_disable_tc_arbitration(node, extack);
		goto out;
	}

	err = esw_qos_node_enable_tc_arbitration(node, extack);
	if (err)
		goto out;

	err = mlx5_esw_qos_update_tc_arbiter_node(node, tc_bw, extack);
	if (err) {
		if (esw_qos_node_disable_tc_arbitration(node, extack))
			NL_SET_ERR_MSG_MOD(extack, "E-Switch restore TC BW for node failed");
	}

out:
	esw_qos_unlock(esw);

	return err;
}

#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
int mlx5_esw_devlink_rate_node_tc_bw_set(struct devlink_rate *rate_node, void *priv,
					 u32 *tc_bw, struct netlink_ext_ack *extack)
{
	return rate_node_tc_bw_set(priv, tc_bw, extack);
}
#endif

int mlx5_esw_sysfs_rate_node_tc_bw_set(void *priv, u32 *tc_bw,
				       struct netlink_ext_ack *extack)
{
	return rate_node_tc_bw_set(priv, tc_bw, extack);
}

int mlx5_esw_devm_rate_node_tc_bw_set(struct mlx5_eswitch *esw,
				      struct mlx5_esw_sched_node *node,
				      u32 *tc_bw, struct netlink_ext_ack *extack)
{
	bool disable;
	int err;

	if (!refcount_read(&esw->qos.refcnt))
		return 0;

	esw_qos_lock(esw);
	if (!esw_qos_validate_unsupported_tc_bw(node->esw, tc_bw)) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch traffic classes number is not supported");
		err = -EOPNOTSUPP;
		goto out;
	}

	disable = esw_qos_tc_bw_disabled(tc_bw);
	if (disable) {
		err = esw_qos_node_disable_tc_arbitration(node, extack);
		goto out;
	}

	err = esw_qos_node_enable_tc_arbitration(node, extack);
	if (err)
		goto out;

	err = mlx5_esw_qos_update_tc_arbiter_node(node, tc_bw, extack);
	if (err) {
		if (esw_qos_node_disable_tc_arbitration(node, extack))
			NL_SET_ERR_MSG_MOD(extack, "E-Switch restore TC BW for node failed");
		goto out;
	}

out:
	if (!err)
		memcpy(node->devm.tc_bw, tc_bw, sizeof(node->devm.tc_bw));
	esw_qos_unlock(esw);

	return err;
}

#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
int mlx5_esw_devlink_rate_node_tx_share_set(struct devlink_rate *rate_node, void *priv,
					    u64 tx_share, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node = priv;
	struct mlx5_eswitch *esw = node->esw;
	int err;

	err = esw_qos_devlink_rate_to_mbps(esw->dev, "tx_share", &tx_share, extack);
	if (err)
		return err;

	esw_qos_lock(esw);
	err = esw_qos_set_node_min_rate(node, tx_share, extack);
	esw_qos_unlock(esw);
	return err;
}

int mlx5_esw_devlink_rate_node_tx_max_set(struct devlink_rate *rate_node, void *priv,
					  u64 tx_max, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node = priv;
	struct mlx5_eswitch *esw = node->esw;
	int err;

	err = esw_qos_devlink_rate_to_mbps(esw->dev, "tx_max", &tx_max, extack);
	if (err)
		return err;

	esw_qos_lock(esw);
	err = esw_qos_set_node_max_rate(node, tx_max, extack);
	esw_qos_unlock(esw);
	return err;
}

int mlx5_esw_devlink_rate_node_new(struct devlink_rate *rate_node, void **priv,
				   struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node;
	struct mlx5_eswitch *esw;
	int err = 0;

	esw = mlx5_devlink_eswitch_get(rate_node->devlink);
	if (IS_ERR(esw))
		return PTR_ERR(esw);

	esw_qos_lock(esw);
	if (esw->mode != MLX5_ESWITCH_OFFLOADS) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Rate node creation supported only in switchdev mode");
		err = -EOPNOTSUPP;
		goto unlock;
	}

	node = esw_qos_create_vports_sched_node(esw, MLX5_ESW_QOS_NON_SYSFS_GROUP, extack);
	if (IS_ERR(node)) {
		err = PTR_ERR(node);
		goto unlock;
	}

	*priv = node;
unlock:
	esw_qos_unlock(esw);
	return err;
}

int mlx5_esw_devlink_rate_node_del(struct devlink_rate *rate_node, void *priv,
				   struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node = priv;
	struct mlx5_eswitch *esw = node->esw;
	int err, ret = 0;

	esw_qos_lock(esw);
	if (node->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR) {
		err = esw_qos_destroy_vports_tc_nodes(node, true, NULL);
		if (err)
			ret = err;
	}

	err = __esw_qos_destroy_node(node, extack);
	if (err)
		ret = err;
	esw_qos_put(esw);

	esw_qos_unlock(esw);
	return ret;
}
#endif

int esw_qos_vport_tc_update_node(struct mlx5_vport *vport,
				 struct mlx5_esw_sched_node *new_tc_arbiter_node,
				 struct netlink_ext_ack *extack)
{
	/* If TC QoS is already enabled, disable it and re-enable with the new node. */
	if (vport->qos.tc.arbiter_node) {
		struct mlx5_esw_sched_node *curr_tc_arbiter_node;
		int err;

		curr_tc_arbiter_node = vport->qos.tc.arbiter_node;
		err = esw_qos_cleanup_vport_tcs(vport, false, extack);
		if (err)
			return err;

		err = esw_qos_init_vport_tcs(vport, new_tc_arbiter_node, extack);
		if (err) {
			if (esw_qos_init_vport_tcs(vport, curr_tc_arbiter_node, extack))
				esw_warn(curr_tc_arbiter_node->esw->dev,
					 "Restore vport tc failed.\n");
		}

		return err;
	}

	/* If TC QoS is not enabled, handle full TC QoS enablement. */
	return esw_qos_vport_tc_enable(vport, new_tc_arbiter_node, extack);
}

#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
int mlx5_esw_devlink_rate_parent_set(struct devlink_rate *devlink_rate,
				     struct devlink_rate *parent,
				     void *priv, void *parent_priv,
				     struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node;
	struct mlx5_vport *vport = priv;

	if (!parent)
		return mlx5_esw_qos_vport_update_node(vport, NULL, extack);

	node = parent_priv;
	return mlx5_esw_qos_vport_update_node(vport, node, extack);
}
#endif

static void
esw_qos_tc_arbiter_get_bw_shares(struct mlx5_esw_sched_node *tc_arbiter_node, u32 *tc_bw)
{
	struct mlx5_esw_sched_node *vports_tc_node;

	list_for_each_entry(vports_tc_node, &tc_arbiter_node->children, entry)
		tc_bw[vports_tc_node->tc] = vports_tc_node->user_bw_share;
}

int mlx5_esw_qos_vport_tc_update_tc_arbitration_node(struct mlx5_vport *vport,
						     struct mlx5_esw_sched_node *node,
						     struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	struct mlx5_esw_sched_node *parent, *arbiter_node;
	struct mlx5_eswitch *esw;
	u32 *curr_tc_bw = NULL;
	int err;

	arbiter_node = vport->qos.tc.arbiter_node;
	if (arbiter_node) {
		int num_tcs = esw_qos_num_tcs(arbiter_node->parent->esw->dev);

		curr_tc_bw = kcalloc(num_tcs, sizeof(u32), GFP_KERNEL);
		if (!curr_tc_bw) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Failed to allocate memory for vports tc TSARs bandwidth share.");
			return -ENOMEM;
		}

		esw_qos_tc_arbiter_get_bw_shares(vport->qos.tc.arbiter_node, curr_tc_bw);
	}

	esw = node ? node->esw : vport->dev->priv.eswitch;
	if (!esw_qos_validate_unsupported_tc_bw(esw, curr_tc_bw)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Unsupported traffic classes on the new device");
		return -EOPNOTSUPP;
	}

	err = esw_qos_vport_disable_tc_arbitration(vport, extack);
	if (err)
		goto out;

	parent = vport_node->parent;
	err = esw_qos_vport_update_node(vport, node, extack);
	if (err) {
		if (esw_qos_vport_enable_tc_arbitration(vport, extack))
			goto err_restore;
		goto out_update_tc;
	}

	err = esw_qos_vport_enable_tc_arbitration(vport, extack);
	if (err) {
		vport_node->parent = parent;
		if (esw_qos_vport_enable_tc_arbitration(vport, extack))
			goto err_restore;
	}

out_update_tc:
	if (curr_tc_bw)
		mlx5_esw_qos_update_tc_arbiter_node(vport->qos.tc.arbiter_node, curr_tc_bw, extack);

	goto out;
err_restore:
	esw_warn(vport_node->parent->esw->dev, "Restore vport tc failed.\n");
out:
	kfree(curr_tc_bw);
	return err;
}

static bool mlx5_esw_validate_cross_esw_scheduling(struct mlx5_eswitch *esw,
						   struct mlx5_esw_sched_node *node,
						   struct netlink_ext_ack *extack)
{
	if (!node || esw == node->esw)
		return 0;

	if (!MLX5_CAP_QOS(esw->dev, esw_cross_esw_sched)) {
		NL_SET_ERR_MSG_MOD(extack, "Cross E-Switch scheduling is not supported");
		return -EOPNOTSUPP;
	}
	if (esw->qos.domain != node->esw->qos.domain) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cannot add vport to a node belonging to a different qos domain");
		return -EOPNOTSUPP;
	}
	if (!mlx5_lag_is_active(esw->dev)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cross E-Switch scheduling requires LAG to be activated");
		return -EOPNOTSUPP;
	}

	return 0;
}

int mlx5_esw_qos_vport_update_node(struct mlx5_vport *vport,
				   struct mlx5_esw_sched_node *node,
				   struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	int err;

	err = mlx5_esw_validate_cross_esw_scheduling(esw, node, extack);
	if (err)
		return err;

	esw_qos_lock(esw);
	if (!vport->qos.sched_node && !node)
		goto unlock;

	err = esw_qos_vport_enable(vport, 0, 0, extack);
	if (err)
		goto unlock;

	if (node) {
		if (node->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR) {
			if (esw_qos_tc_arbitration_enabled_on_vport(vport)) {
				NL_SET_ERR_MSG_MOD(extack,
						   "TC arbitration already enabled for vport");
				err = -EOPNOTSUPP;
				goto unlock;
			}

			err = esw_qos_vport_tc_update_node(vport, node, extack);
			goto unlock;
		}
	}

	if (esw_qos_tc_arbitration_enabled_on_vport(vport)) {
		err = mlx5_esw_qos_vport_tc_update_tc_arbitration_node(vport, node, extack);
		goto unlock;
	}

	if (vport->qos.tc.arbiter_node)
		err = esw_qos_vport_tc_disable(vport, node, extack);
	else
		err = esw_qos_vport_update_node(vport, node, extack);
unlock:
	esw_qos_unlock(esw);
	return err;
}

/* If the qos group has vf from other esw, we can't delete the group
 * because it still has child. So move all vfs in qos group to it's
 * own esw. And delete the empty groups.
 */
void
mlx5_esw_qos_pre_cleanup(struct mlx5_core_dev *dev, int num_vfs)
{
	struct mlx5_esw_sched_node *group, *tmp1, *tmp2, *node0, *vport_group;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5_vport *vport;
	unsigned long i;
	int err;

	if (!is_mdev_switchdev_mode(dev))
		return;

	mlx5_devm_rate_nodes_destroy(dev);

	if (!num_vfs)
		return;

	esw_qos_lock(esw);
	list_for_each_entry_safe(group, tmp1, &esw->qos.domain->nodes, entry) {
		if (group->group_id == MLX5_ESW_QOS_NON_SYSFS_GROUP)
			continue;
		if (!group->group_id)
			continue;
		if (group->type != SCHED_NODE_TYPE_TC_ARBITER_TSAR)
			continue;

		esw_qos_node_disable_tc_arbitration(group, NULL);
	}

	/* If the vport tc arbitration is enabled and this vport is
	 * in a rate node, disable vport tc arbitration first.
	 */
	mlx5_esw_for_each_vf_vport(esw, i, vport, num_vfs) {
		esw_qos_vport_disable_tc_arbitration(vport, NULL);
	}

	list_for_each_entry_safe(group, tmp1, &esw->qos.domain->nodes, entry) {
		if (group->group_id == MLX5_ESW_QOS_NON_SYSFS_GROUP)
			continue;
		if (!group->group_id)
			continue;

		if (group->type != SCHED_NODE_TYPE_VPORTS_TSAR)
			continue;

		list_for_each_entry_safe(vport_group, tmp2, &group->children, entry) {
			vport = vport_group->vport;
			if (vport->dev != dev && group->esw->dev != dev)
				continue;

			node0 = vport->dev->priv.eswitch->qos.node0;
			err = esw_qos_update_node_scheduling_element(vport, group, node0, NULL);
			if (err)
				esw_warn(vport->dev,
					 "failed to move vport %d to node0\n", vport->vport);
			group->num_vports--;
			node0->num_vports++;
		}
		if (!group->num_vports) {
			esw = group->esw;
			__esw_qos_destroy_node(group, NULL);
			esw_qos_put(esw);
		}
	}
	esw_qos_unlock(esw);
}
