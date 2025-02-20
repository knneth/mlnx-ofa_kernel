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
	[SCHED_NODE_TYPE_TC_ARBITER_TSAR] = "TC Arbiter TSAR",
	[SCHED_NODE_TYPE_RATE_LIMITER] = "Rate Limiter",
	[SCHED_NODE_TYPE_VPORT_TC] = "vport TC",
	[SCHED_NODE_TYPE_VPORTS_TC_TSAR] = "vports TC TSAR",
};

static void
esw_qos_node_set_parent(struct mlx5_esw_sched_node *node, struct mlx5_esw_sched_node *parent)
{
	list_del_init(&node->entry);
	if (node->type != SCHED_NODE_TYPE_VPORTS_TC_TSAR) {
		if (node->parent)
			node->parent->num_vports--;
		parent->num_vports++;
	}
	node->parent = parent;
	list_add_tail(&node->entry, &parent->children);
	node->esw = parent->esw;
}

static void
esw_qos_nodes_set_parent(struct list_head *nodes, struct mlx5_esw_sched_node *parent)
{
	struct mlx5_esw_sched_node *node, *tmp, *child;

	list_for_each_entry_safe(node, tmp, nodes, entry) {
		esw_qos_node_set_parent(node, parent);

		if (list_empty(&node->children) || parent->type != SCHED_NODE_TYPE_TC_ARBITER_TSAR)
			continue;

		list_for_each_entry(child, &node->children, entry) {
			if (child->vport && child->vport->qos.sched_node->parent != parent) {
				if (child->vport->qos.sched_node->parent)
					child->vport->qos.sched_node->parent->num_vports--;
				child->vport->qos.sched_node->parent = parent;
			}
		}
	}
}

static int esw_qos_num_tcs(struct mlx5_core_dev *dev)
{
	int num_tcs = mlx5_max_tc(dev) + 1;

	return num_tcs < IEEE_8021QAZ_MAX_TCS ? num_tcs : IEEE_8021QAZ_MAX_TCS;
}

void mlx5_esw_qos_vport_qos_free(struct mlx5_vport *vport)
{
	if (vport->qos.sched_nodes) {
		int i, num_tcs = esw_qos_num_tcs(vport->qos.sched_node->esw->dev);

		for (i = 0; i < num_tcs; i++)
			kfree(vport->qos.sched_nodes[i]);
		kfree(vport->qos.sched_nodes);
	}

	kfree(vport->qos.sched_node);
	memset(&vport->qos, 0, sizeof(vport->qos));
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
	return vport->qos.sched_node->parent;
}

static void esw_qos_sched_elem_warn(struct mlx5_esw_sched_node *node, int err, const char *op)
{
	switch (node->type) {
	case SCHED_NODE_TYPE_VPORTS_TC_TSAR:
		esw_warn(node->esw->dev,
			 "E-Switch %s %s scheduling element failed (tc=%d,err=%d)\n",
			 op, sched_node_type_str[node->type], node->tc, err);
		break;
	case SCHED_NODE_TYPE_VPORT_TC:
		esw_warn(node->esw->dev,
			 "E-Switch %s %s scheduling element failed (vport=%d,tc=%d,err=%d)\n",
			 op, sched_node_type_str[node->type], node->vport->vport, node->tc, err);
		break;
	case SCHED_NODE_TYPE_VPORT:
		esw_warn(node->esw->dev,
			 "E-Switch %s %s scheduling element failed (vport=%d,err=%d)\n",
			 op, sched_node_type_str[node->type], node->vport->vport, err);
		break;
	case SCHED_NODE_TYPE_RATE_LIMITER:
	case SCHED_NODE_TYPE_TC_ARBITER_TSAR:
	case SCHED_NODE_TYPE_VPORTS_TSAR:
		esw_warn(node->esw->dev,
			 "E-Switch %s %s scheduling element failed (err=%d)\n",
			 op, sched_node_type_str[node->type], err);
		break;
	default:
		esw_warn(node->esw->dev,
			 "E-Switch %s scheduling element failed (err=%d)\n", op, err);
		break;
	}
}

static int esw_qos_node_create_sched_element(struct mlx5_esw_sched_node *node, void *ctx,
					     struct netlink_ext_ack *extack)
{
	int err;

	err = mlx5_create_scheduling_element_cmd(node->esw->dev, SCHEDULING_HIERARCHY_E_SWITCH, ctx,
						 &node->ix);
	if (err) {
		esw_qos_sched_elem_warn(node, err, "create");
		NL_SET_ERR_MSG_MOD(extack, "E-Switch create scheduling element failed");
	}

	return err;
}

static int esw_qos_create_rate_limit_element(struct mlx5_esw_sched_node *node,
					     struct netlink_ext_ack *extack)
{
	u32 sched_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};

	if (!mlx5_qos_element_type_supported(node->esw->dev,
					     SCHEDULING_CONTEXT_ELEMENT_TYPE_RATE_LIMIT,
					     SCHEDULING_HIERARCHY_E_SWITCH))
		return -EOPNOTSUPP;

	MLX5_SET(scheduling_context, sched_ctx, max_average_bw, node->max_rate);
	MLX5_SET(scheduling_context, sched_ctx, element_type,
		 SCHEDULING_CONTEXT_ELEMENT_TYPE_RATE_LIMIT);

	return esw_qos_node_create_sched_element(node, sched_ctx, extack);
}

static int esw_qos_node_destroy_sched_element(struct mlx5_esw_sched_node *node,
					      struct netlink_ext_ack *extack)
{
	int err;

	err = mlx5_destroy_scheduling_element_cmd(node->esw->dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  node->ix);
	if (err) {
		esw_qos_sched_elem_warn(node, err, "destroy");
		NL_SET_ERR_MSG_MOD(extack, "E-Switch destroying scheduling element failed.");
	}

	return err;
}

int esw_qos_sched_elem_config(struct mlx5_esw_sched_node *node, u32 max_rate, u32 bw_share,
			      struct netlink_ext_ack *extack)
{
	u32 sched_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	struct mlx5_core_dev *dev = node->esw->dev;
	u32 bitmask = 0;
	int err;

	if (!MLX5_CAP_GEN(dev, qos) || !MLX5_CAP_QOS(dev, esw_scheduling))
		return -EOPNOTSUPP;

	if (bw_share && (!MLX5_CAP_QOS(dev, esw_bw_share) ||
			 MLX5_CAP_QOS(dev, max_tsar_bw_share) < MLX5_MIN_BW_SHARE))
		return -EOPNOTSUPP;

	if (node->max_rate == max_rate && node->bw_share == bw_share)
		return 0;

	if (node->max_rate != max_rate) {
		MLX5_SET(scheduling_context, sched_ctx, max_average_bw, max_rate);
		bitmask |= MODIFY_SCHEDULING_ELEMENT_IN_MODIFY_BITMASK_MAX_AVERAGE_BW;
	}
	if (node->bw_share != bw_share) {
		MLX5_SET(scheduling_context, sched_ctx, bw_share, bw_share);
		bitmask |= MODIFY_SCHEDULING_ELEMENT_IN_MODIFY_BITMASK_BW_SHARE;
	}

	err = mlx5_modify_scheduling_element_cmd(dev,
						 SCHEDULING_HIERARCHY_E_SWITCH,
						 sched_ctx,
						 node->ix,
						 bitmask);
	if (err) {
		esw_qos_sched_elem_warn(node, err, "modify");
		NL_SET_ERR_MSG_MOD(extack, "E-Switch modify scheduling element failed");

		return err;
	}

	node->max_rate = max_rate;
	node->bw_share = bw_share;
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

static void esw_qos_update_sched_node_bw_share(struct mlx5_esw_sched_node *node,
					       u32 divider,
					       struct netlink_ext_ack *extack)
{
	u32 fw_max_bw_share = MLX5_CAP_QOS(node->esw->dev, max_tsar_bw_share);
	u32 bw_share;

	bw_share = esw_qos_calc_bw_share(node->min_rate, divider, fw_max_bw_share);

	esw_qos_sched_elem_config(node, node->max_rate, bw_share, extack);
}

static void esw_qos_normalize_min_rate(struct mlx5_eswitch *esw,
				      struct mlx5_esw_sched_node *parent,
				      struct netlink_ext_ack *extack)
{
	struct list_head *nodes = parent ? &parent->children : &esw->qos.domain->nodes;
	u32 divider = esw_qos_calculate_min_rate_divider(esw, parent);
	struct mlx5_esw_sched_node *node;

	list_for_each_entry(node, nodes, entry) {
		if (node->esw != esw || node->ix == esw->qos.root_tsar_ix)
			continue;

		/* Vports TC TSARs don't have a minimum rate configured,
		 * so there's no need to update the bw_share on them.
		 */
		if (node->type != SCHED_NODE_TYPE_VPORTS_TC_TSAR)
			esw_qos_update_sched_node_bw_share(node, divider, extack);

		if (list_empty(&node->children))
			continue;

		esw_qos_normalize_min_rate(node->esw, node, extack);
	}
}

int esw_qos_set_node_min_rate(struct mlx5_esw_sched_node *node,
			      u32 min_rate, struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = node->esw;

	if (min_rate == node->min_rate)
		return 0;

	node->min_rate = min_rate;
	esw_qos_normalize_min_rate(esw, node->parent, extack);

	return 0;
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
	MLX5_SET(scheduling_context, tsar_ctx, parent_element_id,
		 parent_element_id);
	MLX5_SET(scheduling_context, tsar_ctx, max_average_bw, max_rate);
	MLX5_SET(scheduling_context, tsar_ctx, bw_share, bw_share);
	attr = MLX5_ADDR_OF(scheduling_context, tsar_ctx, element_attributes);
	MLX5_SET(tsar_element, attr, tsar_type, TSAR_ELEMENT_TSAR_TYPE_DWRR);

	return mlx5_create_scheduling_element_cmd(dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  tsar_ctx,
						  tsar_ix);
}

static int esw_qos_vport_create_sched_element(struct mlx5_esw_sched_node *vport_node,
					      struct netlink_ext_ack *extack)
{
	u32 sched_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	struct mlx5_core_dev *dev = vport_node->esw->dev;
	struct mlx5_vport *vport = vport_node->vport;
	void *attr;

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
	MLX5_SET(scheduling_context, sched_ctx, parent_element_id, vport_node->parent->ix);
	MLX5_SET(scheduling_context, sched_ctx, max_average_bw, vport_node->max_rate);

	return esw_qos_node_create_sched_element(vport_node, sched_ctx, extack);
}

void esw_qos_destroy_vports_tc_nodes(struct mlx5_esw_sched_node *tc_arbiter_node,
				     struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vports_tc_node, *tmp;

	list_for_each_entry_safe(vports_tc_node, tmp, &tc_arbiter_node->children, entry)
		esw_qos_destroy_node(vports_tc_node, extack);
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
			esw_qos_destroy_vports_tc_nodes(group, NULL);
		sysfs_esw_qos_destroy_node(group, NULL);
	}
}

static int esw_qos_vport_tc_create_sched_element(struct mlx5_esw_sched_node *vport_tc_node,
						 u32 rate_limit_elem_ix,
						 struct netlink_ext_ack *extack)
{
	u32 sched_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	struct mlx5_core_dev *dev = vport_tc_node->esw->dev;
	struct mlx5_vport *vport = vport_tc_node->vport;
	void *attr;

	if (!mlx5_qos_element_type_supported(dev,
					     SCHEDULING_CONTEXT_ELEMENT_TYPE_VPORT_TC,
					     SCHEDULING_HIERARCHY_E_SWITCH))
		return -EOPNOTSUPP;

	MLX5_SET(scheduling_context, sched_ctx, element_type,
		 SCHEDULING_CONTEXT_ELEMENT_TYPE_VPORT_TC);
	attr = MLX5_ADDR_OF(scheduling_context, sched_ctx, element_attributes);
	MLX5_SET(vport_tc_element, attr, vport_number, vport->vport);
	MLX5_SET(vport_tc_element, attr, traffic_class, vport_tc_node->tc);
	MLX5_SET(scheduling_context, sched_ctx, max_bw_obj_id, rate_limit_elem_ix);
	if (vport->dev != dev) {
		/* The port is assigned to a node on another eswitch. */
		MLX5_SET(vport_tc_element, attr, eswitch_owner_vhca_id_valid, true);
		MLX5_SET(vport_tc_element, attr, eswitch_owner_vhca_id,
			 MLX5_CAP_GEN(vport->dev, vhca_id));
	}
	MLX5_SET(scheduling_context, sched_ctx, parent_element_id, vport_tc_node->parent->ix);
	MLX5_SET(scheduling_context, sched_ctx, bw_share, vport_tc_node->bw_share);

	return esw_qos_node_create_sched_element(vport_tc_node, sched_ctx, extack);
}

static struct mlx5_esw_sched_node *
__esw_qos_alloc_node(struct mlx5_eswitch *esw, u32 tsar_ix, enum sched_node_type type,
		     struct mlx5_esw_sched_node *parent)
{
	struct mlx5_esw_sched_node *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return NULL;

	node->esw = esw;
	node->ix = tsar_ix;
	node->type = type;
	node->parent = parent;
	INIT_LIST_HEAD(&node->children);
	if (parent)
		list_add_tail(&node->entry, &parent->children);
	else
		INIT_LIST_HEAD(&node->entry);

	return node;
}

static void __esw_qos_free_node(struct mlx5_esw_sched_node *node)
{
	list_del(&node->entry);
	kfree(node);
}

static int esw_qos_create_vports_tc_node(struct mlx5_esw_sched_node *parent, u8 tc,
					 struct netlink_ext_ack *extack)
{
	u32 tsar_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	struct mlx5_core_dev *dev = parent->esw->dev;
	struct mlx5_esw_sched_node *vports_tc_node;
	void *attr;
	int err;

	if (!mlx5_qos_element_type_supported(dev,
					     SCHEDULING_CONTEXT_ELEMENT_TYPE_TSAR,
					     SCHEDULING_HIERARCHY_E_SWITCH) ||
	    !mlx5_qos_tsar_type_supported(dev,
					  TSAR_ELEMENT_TSAR_TYPE_DWRR,
					  SCHEDULING_HIERARCHY_E_SWITCH))
		return -EOPNOTSUPP;

	vports_tc_node = __esw_qos_alloc_node(parent->esw, 0, SCHED_NODE_TYPE_VPORTS_TC_TSAR,
					      parent);
	if (!vports_tc_node) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch alloc node failed");
		esw_warn(dev, "Failed to alloc vports TC node (tc=%d)\n", tc);
		return -ENOMEM;
	}

	attr = MLX5_ADDR_OF(scheduling_context, tsar_ctx, element_attributes);
	MLX5_SET(tsar_element, attr, tsar_type, TSAR_ELEMENT_TSAR_TYPE_DWRR);
	MLX5_SET(tsar_element, attr, traffic_class, tc);
	MLX5_SET(scheduling_context, tsar_ctx, parent_element_id, parent->ix);
	MLX5_SET(scheduling_context, tsar_ctx, element_type, SCHEDULING_CONTEXT_ELEMENT_TYPE_TSAR);

	err = esw_qos_node_create_sched_element(vports_tc_node, tsar_ctx, extack);
	if (err)
		goto err_create_sched_element;

	vports_tc_node->tc = tc;

	return 0;

err_create_sched_element:
	__esw_qos_free_node(vports_tc_node);
	return err;
}

static int esw_qos_create_vports_tc_nodes(struct mlx5_esw_sched_node *tc_arbiter_node,
					  struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = tc_arbiter_node->esw;
	int err, i, num_tcs = esw_qos_num_tcs(esw->dev);

	for (i = 0; i < num_tcs; i++) {
		err = esw_qos_create_vports_tc_node(tc_arbiter_node, i, extack);
		if (err)
			goto err_tc_node_create;
	}

	return 0;

err_tc_node_create:
	esw_qos_destroy_vports_tc_nodes(tc_arbiter_node, NULL);
	return err;
}

static int esw_qos_create_tc_arbiter_sched_elem(struct mlx5_esw_sched_node *tc_arbiter_node,
						struct netlink_ext_ack *extack)
{
	u32 tsar_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	u32 tsar_parent_ix;
	void *attr;

	if (!mlx5_qos_tsar_type_supported(tc_arbiter_node->esw->dev,
					  TSAR_ELEMENT_TSAR_TYPE_TC_ARB,
					  SCHEDULING_HIERARCHY_E_SWITCH)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "E-Switch TC Arbiter scheduling element is not supported");
		return -EOPNOTSUPP;
	}

	attr = MLX5_ADDR_OF(scheduling_context, tsar_ctx, element_attributes);
	MLX5_SET(tsar_element, attr, tsar_type, TSAR_ELEMENT_TSAR_TYPE_TC_ARB);
	tsar_parent_ix = tc_arbiter_node->parent ? tc_arbiter_node->parent->ix :
			 tc_arbiter_node->esw->qos.root_tsar_ix;
	MLX5_SET(scheduling_context, tsar_ctx, parent_element_id, tsar_parent_ix);
	MLX5_SET(scheduling_context, tsar_ctx, element_type, SCHEDULING_CONTEXT_ELEMENT_TYPE_TSAR);
	MLX5_SET(scheduling_context, tsar_ctx, max_average_bw, tc_arbiter_node->max_rate);
	MLX5_SET(scheduling_context, tsar_ctx, bw_share, tc_arbiter_node->bw_share);

	return esw_qos_node_create_sched_element(tc_arbiter_node, tsar_ctx, extack);
}

void esw_qos_destroy_node(struct mlx5_esw_sched_node *node, struct netlink_ext_ack *extack)
{
	esw_qos_node_destroy_sched_element(node, extack);
	__esw_qos_free_node(node);
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
	if (group_id != MLX5_ESW_QOS_NON_SYSFS_GROUP) {
		err = mlx5_create_vf_group_sysfs(esw->dev, group_id, &node->kobj);
		if (err)
			goto err_group_sysfs;
	}

	list_add_tail(&node->entry, &esw->qos.domain->nodes);
	esw_qos_normalize_min_rate(esw, NULL, extack);
	trace_mlx5_esw_node_qos_create(esw->dev, node, node->ix);
	init_completion(&node->free_group_comp);

	return node;

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

static void __esw_qos_destroy_node(struct mlx5_esw_sched_node *node, struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = node->esw;

	if (node->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR)
		esw_qos_destroy_vports_tc_nodes(node, extack);

	/* Only rate group has sysfs dir. Check if the node is a rate group. */
	if (node->type == SCHED_NODE_TYPE_VPORTS_TSAR ||
	    node->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR) {
		if (node->group_id != MLX5_ESW_QOS_NON_SYSFS_GROUP)
			mlx5_destroy_vf_group_sysfs(node);
		else
			complete_all(&node->free_group_comp);

		wait_for_completion(&node->free_group_comp);
	}

	trace_mlx5_esw_node_qos_destroy(esw->dev, node, node->ix);
	esw_qos_destroy_node(node, extack);
	esw_qos_normalize_min_rate(esw, NULL, extack);
}

void sysfs_esw_qos_destroy_node(struct mlx5_esw_sched_node *node,
				struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = node->esw;

	__esw_qos_destroy_node(node, extack);
	esw_qos_put(esw);
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

	if (esw->qos.node0->ix != esw->qos.root_tsar_ix)
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

static void esw_qos_tc_arbiter_scheduling_teardown(struct mlx5_esw_sched_node *node,
						   struct netlink_ext_ack *extack)
{
	/* Clean up all Vports TC nodes within the TC arbiter node. */
	esw_qos_destroy_vports_tc_nodes(node, extack);
	/* Destroy the scheduling element for the TC arbiter node itself. */
	esw_qos_node_destroy_sched_element(node, extack);
}

static int esw_qos_tc_arbiter_scheduling_setup(struct mlx5_esw_sched_node *node,
					       struct netlink_ext_ack *extack)
{
	u32 curr_ix = node->ix;
	int err;

	err = esw_qos_create_tc_arbiter_sched_elem(node, extack);
	if (err)
		return err;
	/* Initialize the vports TC nodes within created TC arbiter TSAR. */
	err = esw_qos_create_vports_tc_nodes(node, extack);
	if (err)
		goto err_vports_tc_nodes;

	node->type = SCHED_NODE_TYPE_TC_ARBITER_TSAR;

	return 0;

err_vports_tc_nodes:
	/* If initialization fails, clean up the scheduling element
	 * for the TC arbiter node.
	 */
	esw_qos_node_destroy_sched_element(node, NULL);
	node->ix = curr_ix;
	return err;
}

static void esw_qos_destroy_vport_tc_sched_elements(struct mlx5_vport *vport,
						    struct netlink_ext_ack *extack)
{
	int i, num_tcs = esw_qos_num_tcs(vport->qos.sched_node->esw->dev);

	for (i = 0; i < num_tcs; i++) {
		if (vport->qos.sched_nodes[i])
			__esw_qos_destroy_node(vport->qos.sched_nodes[i], extack);
	}

	kfree(vport->qos.sched_nodes);
	vport->qos.sched_nodes = NULL;
}

void esw_qos_vport_tc_disable(struct mlx5_vport *vport, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	enum sched_node_type curr_type = vport_node->type;

	esw_qos_destroy_vport_tc_sched_elements(vport, extack);

	if (curr_type == SCHED_NODE_TYPE_RATE_LIMITER)
		esw_qos_node_destroy_sched_element(vport_node, extack);
	else
		esw_qos_tc_arbiter_scheduling_teardown(vport_node, extack);
}

static int esw_qos_create_vport_tc_sched_node(struct mlx5_vport *vport,
					      u32 rate_limit_elem_ix,
					      struct mlx5_esw_sched_node *vports_tc_node,
					      struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	struct mlx5_esw_sched_node *vport_tc_node;
	u8 tc = vports_tc_node->tc;
	int err;

	vport_tc_node = __esw_qos_alloc_node(vport_node->esw, 0, SCHED_NODE_TYPE_VPORT_TC,
					     vports_tc_node);
	if (!vport_tc_node)
		return -ENOMEM;

	vport_tc_node->min_rate = vport_node->min_rate;
	vport_tc_node->tc = tc;
	vport_tc_node->vport = vport;
	err = esw_qos_vport_tc_create_sched_element(vport_tc_node, rate_limit_elem_ix, extack);
	if (err)
		goto err_out;

	vport->qos.sched_nodes[tc] = vport_tc_node;

	return 0;
err_out:
	__esw_qos_free_node(vport_tc_node);
	return err;
}

static int esw_qos_create_vport_tc_sched_elements(struct mlx5_vport *vport,
						  enum sched_node_type type,
						  struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	struct mlx5_esw_sched_node *tc_arbiter_node, *vports_tc_node;
	int err, num_tcs = esw_qos_num_tcs(vport_node->esw->dev);
	u32 rate_limit_elem_ix;

	vport->qos.sched_nodes = kcalloc(num_tcs, sizeof(struct mlx5_esw_sched_node *), GFP_KERNEL);
	if (!vport->qos.sched_nodes) {
		NL_SET_ERR_MSG_MOD(extack, "Allocating the vport TC scheduling elements failed.");
		return -ENOMEM;
	}

	rate_limit_elem_ix = type == SCHED_NODE_TYPE_RATE_LIMITER ? vport_node->ix : 0;
	tc_arbiter_node = type == SCHED_NODE_TYPE_RATE_LIMITER ? vport_node->parent : vport_node;
	list_for_each_entry(vports_tc_node, &tc_arbiter_node->children, entry) {
		err = esw_qos_create_vport_tc_sched_node(vport, rate_limit_elem_ix, vports_tc_node,
							 extack);
		if (err)
			goto err_create_vport_tc;
	}

	return 0;

err_create_vport_tc:
	esw_qos_destroy_vport_tc_sched_elements(vport, NULL);

	return err;
}

static int esw_qos_vport_tc_enable(struct mlx5_vport *vport, enum sched_node_type type,
				   struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	int err;

	if (type == SCHED_NODE_TYPE_TC_ARBITER_TSAR &&
	    MLX5_CAP_QOS(vport_node->esw->dev, log_esw_max_sched_depth) < 2) {
		NL_SET_ERR_MSG_MOD(extack, "Setting up TC Arbiter for a vport is not supported.");
		return -EOPNOTSUPP;
	}

	esw_assert_qos_lock_held(vport->dev->priv.eswitch);

	if (type == SCHED_NODE_TYPE_RATE_LIMITER)
		err = esw_qos_create_rate_limit_element(vport_node, extack);
	else
		err = esw_qos_tc_arbiter_scheduling_setup(vport_node, extack);
	if (err)
		return err;

	/* Rate limiters impact multiple nodes not directly connected to them
	 * and are not direct members of the QoS hierarchy.
	 * Unlink it from the parent to reflect that.
	 */
	if (type == SCHED_NODE_TYPE_RATE_LIMITER)
		list_del_init(&vport_node->entry);

	err  = esw_qos_create_vport_tc_sched_elements(vport, type, extack);
	if (err)
		goto err_sched_nodes;

	return 0;

err_sched_nodes:
	if (type == SCHED_NODE_TYPE_RATE_LIMITER) {
		esw_qos_node_destroy_sched_element(vport_node, NULL);
		list_add_tail(&vport_node->entry, &vport_node->parent->children);
	} else {
		esw_qos_tc_arbiter_scheduling_teardown(vport_node, NULL);
	}
	return err;
}

static struct mlx5_esw_sched_node *esw_qos_move_node(struct mlx5_esw_sched_node *curr_node)
{
	struct mlx5_esw_sched_node *new_node;

	new_node = __esw_qos_alloc_node(curr_node->esw, curr_node->ix, curr_node->type, NULL);
	if (!IS_ERR(new_node))
		esw_qos_nodes_set_parent(&curr_node->children, new_node);

	return new_node;
}

static void esw_qos_switch_vport_tcs_to_vport(struct mlx5_esw_sched_node *tc_arbiter_node,
					      struct mlx5_esw_sched_node *node,
					      struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vports_tc_node, *vport_tc_node, *tmp;

	vports_tc_node = list_first_entry(&tc_arbiter_node->children, struct mlx5_esw_sched_node,
					  entry);

	list_for_each_entry_safe(vport_tc_node, tmp, &vports_tc_node->children, entry)
		esw_qos_vport_update_parent(vport_tc_node->vport, node, extack);
}

static int esw_qos_switch_tc_arbiter_node_to_vports(struct mlx5_esw_sched_node *tc_arbiter_node,
						    struct mlx5_esw_sched_node *node,
						    struct netlink_ext_ack *extack)
{
	u32 parent_tsar_ix = node->parent ? node->parent->ix : node->esw->qos.root_tsar_ix;
	int err;

	err = esw_qos_create_node_sched_elem(node->esw->dev, parent_tsar_ix, node->max_rate,
					     node->bw_share, &node->ix);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Failed to create scheduling element for vports node when disabliing vports TC QoS");
		return err;
	}

	node->type = SCHED_NODE_TYPE_VPORTS_TSAR;

	/* Disable TC QoS for vports in the arbiter node. */
	esw_qos_switch_vport_tcs_to_vport(tc_arbiter_node, node, extack);

	return 0;
}

static int esw_qos_node_disable_tc_arbitration(struct mlx5_esw_sched_node *node,
					       struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *curr_node;
	int err;

	if (node->type != SCHED_NODE_TYPE_TC_ARBITER_TSAR)
		return 0;

	/* Allocate a new rate node to hold the current state, which will allow
	 * for restoring the vports back to this node after disabling TC arbitration.
	 */
	curr_node = esw_qos_move_node(node);
	if (IS_ERR(curr_node)) {
		NL_SET_ERR_MSG_MOD(extack, "Failed setting up vports node");

		return PTR_ERR(curr_node);
	}

	/* Disable TC QoS for all vports, and assign them back to the node. */
	err = esw_qos_switch_tc_arbiter_node_to_vports(curr_node, node, extack);
	if (err)
		goto err_out;

	/* Clean up the TC arbiter node after disabling TC QoS for vports. */
	esw_qos_tc_arbiter_scheduling_teardown(curr_node, extack);
	goto out;
err_out:
	esw_qos_nodes_set_parent(&curr_node->children, node);
out:
	__esw_qos_free_node(curr_node);
	return err;
}

static int esw_qos_switch_vports_node_to_tc_arbiter(struct mlx5_esw_sched_node *node,
						    struct mlx5_esw_sched_node *tc_arbiter_node,
						    struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node, *tmp;
	struct mlx5_vport *vport;
	int err;

	/* Enable TC QoS for each vport in the node. */
	list_for_each_entry_safe(vport_node, tmp, &node->children, entry) {
		vport = vport_node->vport;
		err = esw_qos_vport_update_parent(vport, tc_arbiter_node, extack);
		if  (err)
			goto err_out;
	}

	/* Destroy the current vports node TSAR. */
	err = mlx5_destroy_scheduling_element_cmd(node->esw->dev, SCHEDULING_HIERARCHY_E_SWITCH,
						  node->ix);
	if (err)
		goto err_out;

	return 0;
err_out:
	/* Restore vports back into the node if an error occurs. */
	esw_qos_switch_vport_tcs_to_vport(tc_arbiter_node, node, NULL);

	return err;
}

static int esw_qos_node_enable_tc_arbitration(struct mlx5_esw_sched_node *node,
					      struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *curr_node;
	int err;

	if (node->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR)
		return 0;

	/* Allocate a new node that will store the information of the current node.
	 * This will be used later to restore the node if necessary.
	 */
	curr_node = esw_qos_move_node(node);
	if (IS_ERR(curr_node)) {
		NL_SET_ERR_MSG_MOD(extack, "Failed setting up node TC QoS");

		return PTR_ERR(curr_node);
	}

	/* Initialize the TC arbiter node for QoS management.
	 * This step prepares the node for handling Traffic Class arbitration.
	 */
	err = esw_qos_tc_arbiter_scheduling_setup(node, extack);
	if (err)
		goto err_setup;

	/* Enable TC QoS for each vport within the current node. */
	err = esw_qos_switch_vports_node_to_tc_arbiter(curr_node, node, extack);
	if (err)
		goto err_switch_vports;
	goto out;

err_switch_vports:
	esw_qos_tc_arbiter_scheduling_teardown(node, NULL);
	node->ix = curr_node->ix;
	node->type = curr_node->type;
err_setup:
	esw_qos_nodes_set_parent(&curr_node->children, node);
out:
	__esw_qos_free_node(curr_node);
	return err;
}

static void esw_qos_vport_disable(struct mlx5_vport *vport, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	struct mlx5_esw_sched_node *parent = vport_node->parent;
	enum sched_node_type curr_type = vport_node->type;

	if (curr_type == SCHED_NODE_TYPE_VPORT)
		esw_qos_node_destroy_sched_element(vport_node, extack);
	else
		esw_qos_vport_tc_disable(vport, extack);

	vport_node->bw_share = 0;
	list_del_init(&vport_node->entry);
	esw_qos_normalize_min_rate(parent->esw, parent, extack);

	trace_mlx5_esw_vport_qos_destroy(vport_node->esw->dev, vport);
}

static int esw_qos_vport_enable(struct mlx5_vport *vport, enum sched_node_type type,
				struct mlx5_esw_sched_node *parent,
				struct netlink_ext_ack *extack)
{
	int err;

	esw_assert_qos_lock_held(vport->dev->priv.eswitch);

	esw_qos_node_set_parent(vport->qos.sched_node, parent);
	if (type == SCHED_NODE_TYPE_VPORT)
		err = esw_qos_vport_create_sched_element(vport->qos.sched_node, extack);
	else
		err = esw_qos_vport_tc_enable(vport, type, extack);
	if (err)
	       return err;

	vport->qos.sched_node->type = type;
	esw_qos_normalize_min_rate(parent->esw, parent, extack);

	return 0;
}

int mlx5_esw_qos_vport_enable(struct mlx5_vport *vport, enum sched_node_type type,
			      struct mlx5_esw_sched_node *parent, u32 max_rate,
			      u32 min_rate, struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	struct mlx5_esw_sched_node *sched_node;
	int err;

	esw_assert_qos_lock_held(esw);
	if (vport->qos.sched_node)
		return 0;

	err = esw_qos_get(esw, extack);
	if (err)
		return err;

	parent = parent ?: esw->qos.node0;
	sched_node = __esw_qos_alloc_node(parent->esw, 0, type, parent);
	if (!sched_node)
		return -ENOMEM;

	sched_node->max_rate = max_rate;
	sched_node->min_rate = min_rate;
	sched_node->vport = vport;
	vport->qos.sched_node = sched_node;
	parent->num_vports++;

	err = esw_qos_vport_enable(vport, type, parent, extack);
	if (err) {
		parent->num_vports--;
		__esw_qos_free_node(sched_node);
		esw_qos_put(esw);
	}

	return err;
}

int mlx5_esw_qos_set_vport_max_rate(struct mlx5_vport *vport, u32 max_rate,
				    struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;

	esw_assert_qos_lock_held(vport->dev->priv.eswitch);

	if (!vport_node)
		return mlx5_esw_qos_vport_enable(vport, SCHED_NODE_TYPE_VPORT, NULL, max_rate, 0,
						 extack);
	else
		return esw_qos_sched_elem_config(vport_node, max_rate, vport_node->bw_share,
						 extack);
}

int mlx5_esw_qos_set_vport_min_rate(struct mlx5_vport *vport, u32 min_rate,
				    struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;

	esw_assert_qos_lock_held(vport->dev->priv.eswitch);

	if (!vport_node)
		return mlx5_esw_qos_vport_enable(vport, SCHED_NODE_TYPE_VPORT, NULL, 0, min_rate,
						 extack);
	else
		return esw_qos_set_node_min_rate(vport_node, min_rate, extack);
}

void mlx5_esw_qos_vport_disable(struct mlx5_vport *vport)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	struct mlx5_esw_sched_node *parent;

	lockdep_assert_held(&esw->state_lock);
	esw_qos_lock(esw);
	if (!vport->qos.sched_node)
		goto unlock;

	parent = vport->qos.sched_node->parent;
	WARN(parent != esw->qos.node0, "Disabling QoS on port before detaching it from node");

	esw_qos_vport_disable(vport, NULL);
	mlx5_esw_qos_vport_qos_free(vport);
	esw_qos_destroy_sysfs_rate_group(esw, vport, parent);
	esw_qos_put(esw);
unlock:
	esw_qos_unlock(esw);
}

int mlx5_esw_qos_set_vport_rate(struct mlx5_vport *vport, u32 max_rate, u32 min_rate)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	int err;

	esw_qos_lock(esw);
	err = mlx5_esw_qos_set_vport_min_rate(vport, min_rate, NULL);
	if (!err)
		err = mlx5_esw_qos_set_vport_max_rate(vport, max_rate, NULL);
	esw_qos_unlock(esw);
	return err;
}

bool mlx5_esw_qos_get_vport_rate(struct mlx5_vport *vport, u32 *max_rate, u32 *min_rate)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	bool enabled;

	esw_qos_lock(esw);
	enabled = !!vport->qos.sched_node;
	if (enabled) {
		*max_rate = vport->qos.sched_node->max_rate;
		*min_rate = vport->qos.sched_node->min_rate;
	}
	esw_qos_unlock(esw);
	return enabled;
}

static int esw_qos_vport_tc_check_type(enum sched_node_type curr_type,
				       enum sched_node_type new_type,
				       struct netlink_ext_ack *extack)
{
	if (curr_type == SCHED_NODE_TYPE_TC_ARBITER_TSAR &&
	    new_type == SCHED_NODE_TYPE_RATE_LIMITER) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cannot switch from vport-level TC arbitration to node-level TC arbitration");
		return -EOPNOTSUPP;
	}

	if (curr_type == SCHED_NODE_TYPE_RATE_LIMITER &&
	    new_type == SCHED_NODE_TYPE_TC_ARBITER_TSAR) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cannot switch from node-level TC arbitration to vport-level TC arbitration");
		return -EOPNOTSUPP;
	}

	return 0;
}

static void esw_qos_set_tc_arbiter_bw_shares(struct mlx5_esw_sched_node *tc_arbiter_node,
					     u32 *tc_bw, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vports_tc_node;

	list_for_each_entry(vports_tc_node, &tc_arbiter_node->children, entry) {
		u32 bw_share;
		u8 tc;

		tc = vports_tc_node->tc;
		bw_share = tc_bw[tc] ?: MLX5_MIN_BW_SHARE;
		vports_tc_node->user_bw_share = tc_bw[tc];
		esw_qos_sched_elem_config(vports_tc_node, 0, bw_share, extack);
	}
}

static void
esw_qos_tc_arbiter_get_bw_shares(struct mlx5_esw_sched_node *tc_arbiter_node, u32 *tc_bw)
{
	struct mlx5_esw_sched_node *vports_tc_node;

	list_for_each_entry(vports_tc_node, &tc_arbiter_node->children, entry)
		tc_bw[vports_tc_node->tc] = vports_tc_node->user_bw_share;
}

static bool esw_qos_validate_unsupported_tc_bw(struct mlx5_eswitch *esw, u32 *tc_bw)
{
	int i, num_tcs = esw_qos_num_tcs(esw->dev);

	for (i = num_tcs; i < IEEE_8021QAZ_MAX_TCS; i++)
		if (tc_bw[i])
			return false;

	return true;
}

static bool esw_qos_vport_validate_unsupported_tc_bw(struct mlx5_vport *vport, u32 *tc_bw)
{
	struct mlx5_eswitch *esw = vport->qos.sched_node ?
				   vport->qos.sched_node->parent->esw : vport->dev->priv.eswitch;

	return esw_qos_validate_unsupported_tc_bw(esw, tc_bw);
}

static int esw_qos_vport_update(struct mlx5_vport *vport, enum sched_node_type type,
				struct mlx5_esw_sched_node *parent,
				struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *curr_parent = vport->qos.sched_node->parent;
	enum sched_node_type curr_type = vport->qos.sched_node->type;
	u32 curr_tc_bw[IEEE_8021QAZ_MAX_TCS] = {0};
	int err;

	esw_assert_qos_lock_held(vport->dev->priv.eswitch);
	parent = parent ?: curr_parent;
	if (curr_type == type && curr_parent == parent)
		return 0;

	err = esw_qos_vport_tc_check_type(curr_type, type, extack);
	if (err)
		return err;

	if (curr_type == SCHED_NODE_TYPE_TC_ARBITER_TSAR && curr_type == type) {
		esw_qos_tc_arbiter_get_bw_shares(vport->qos.sched_node, curr_tc_bw);
		if (!esw_qos_validate_unsupported_tc_bw(parent->esw, curr_tc_bw)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Unsupported traffic classes on the new device");
			return -EOPNOTSUPP;
		}
	}

	esw_qos_vport_disable(vport, extack);

	err = esw_qos_vport_enable(vport, type, parent, extack);
	if (err) {
		esw_qos_vport_enable(vport, curr_type, curr_parent, NULL);
		extack = NULL;
	}

	if (curr_type == SCHED_NODE_TYPE_TC_ARBITER_TSAR && curr_type == type)
		esw_qos_set_tc_arbiter_bw_shares(vport->qos.sched_node, curr_tc_bw, extack);

	return err;
}

int esw_qos_vport_update_parent(struct mlx5_vport *vport, struct mlx5_esw_sched_node *parent,
				struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	struct mlx5_esw_sched_node *curr_parent;
	enum sched_node_type type;

	esw_assert_qos_lock_held(esw);
	curr_parent = vport->qos.sched_node->parent;
	parent = parent ?: esw->qos.node0;
	if (curr_parent == parent)
		return 0;

	/* Set vport QoS type based on parent node type if different from default QoS;
	 * otherwise, use the vport's current QoS type.
	 */
	if (parent->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR)
		type = SCHED_NODE_TYPE_RATE_LIMITER;
	else if (curr_parent->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR)
		type = SCHED_NODE_TYPE_VPORT;
	else
		type = vport->qos.sched_node->type;

	return esw_qos_vport_update(vport, type, parent, extack);
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
	struct mlx5_vport *vport;
	u32 link_speed_max;
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
	err = mlx5_esw_qos_set_vport_max_rate(vport, rate_mbps, NULL);
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
	struct mlx5_esw_sched_node *cur_group, *new_group;
	int err = 0;

	if (!esw_qos_groups_are_supported(group_esw->dev))
		return -EOPNOTSUPP;

	if (!vport->qos.sched_node && !group_id)
		return 0;

	if (!group_id) {
		cur_group = mlx5_esw_qos_vport_get_parent(vport);
		err = mlx5_esw_qos_vport_update_parent(vport, NULL, NULL);
		goto destroy_empty_node;
	}

	esw_qos_lock(group_esw);
	new_group = esw_qos_find_sysfs_group(group_esw, group_id);
	if (!new_group) {
		new_group = esw_qos_create_vports_sched_node(group_esw, group_id, NULL);
		if (IS_ERR(new_group)) {
			esw_warn(group_esw->dev,
				 "E-Switch couldn't create new sysfs group %d (%d)\n",
				 group_id, err);
			err = PTR_ERR(new_group);
		}
	}
	esw_qos_unlock(group_esw);

	if (err)
		return err;

	cur_group = mlx5_esw_qos_vport_get_parent(vport);
	err = mlx5_esw_qos_vport_update_parent(vport, new_group, NULL);

destroy_empty_node:
	esw_qos_lock(group_esw);
	if (!err && cur_group && cur_group->group_id && !cur_group->num_vports)
		sysfs_esw_qos_destroy_node(cur_group, NULL);
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

	err = esw_qos_sched_elem_config(group, max_rate, group->bw_share, NULL);
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
	err = mlx5_esw_qos_set_vport_min_rate(vport, tx_share, extack);
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
	err = mlx5_esw_qos_set_vport_max_rate(vport, tx_max, extack);
	esw_qos_unlock(esw);
	return err;
}
#endif

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
	struct mlx5_esw_sched_node *vport_node;
	struct mlx5_vport *vport = priv;
	struct mlx5_eswitch *esw;
	bool disable;
	int err = 0;

	esw = vport->dev->priv.eswitch;
	if (!mlx5_esw_allowed(esw))
		return -EPERM;

	disable = esw_qos_tc_bw_disabled(tc_bw);
	esw_qos_lock(esw);

	if (!esw_qos_vport_validate_unsupported_tc_bw(vport, tc_bw)) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch traffic classes number is not supported");
		err = -EOPNOTSUPP;
		goto unlock;
	}

	vport_node = vport->qos.sched_node;
	if (disable && !vport_node)
		goto unlock;

	if (disable) {
		if (vport_node->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR)
			err = esw_qos_vport_update(vport, SCHED_NODE_TYPE_VPORT, NULL, extack);
		goto unlock;
	}

	if (!vport_node) {
		err = mlx5_esw_qos_vport_enable(vport, SCHED_NODE_TYPE_TC_ARBITER_TSAR, NULL, 0, 0,
						extack);
		vport_node = vport->qos.sched_node;
	} else {
		err = esw_qos_vport_update(vport, SCHED_NODE_TYPE_TC_ARBITER_TSAR, NULL, extack);
	}
	if (!err)
		esw_qos_set_tc_arbiter_bw_shares(vport_node, tc_bw, extack);
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
	bool disable;
	int err;

	if (!esw_qos_validate_unsupported_tc_bw(esw, tc_bw)) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch traffic classes number is not supported");
		return -EOPNOTSUPP;
	}

	disable = esw_qos_tc_bw_disabled(tc_bw);
	esw_qos_lock(esw);
	if (disable) {
		err = esw_qos_node_disable_tc_arbitration(node, extack);
		goto unlock;
	}

	err = esw_qos_node_enable_tc_arbitration(node, extack);
	if (!err)
		esw_qos_set_tc_arbiter_bw_shares(node, tc_bw, extack);
unlock:
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
	if (!err)
		esw_qos_set_tc_arbiter_bw_shares(node, tc_bw, extack);

out:
	/* If disable is true and err is 0, clear tc_bw. Then mlxdevm will
	 * show the correct tc bw values.
	 */
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
	err = esw_qos_sched_elem_config(node, tx_max, node->bw_share, extack);
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

	esw_qos_lock(esw);
	if (node->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR)
		esw_qos_destroy_vports_tc_nodes(node, NULL);

	__esw_qos_destroy_node(node, extack);
	esw_qos_put(esw);

	esw_qos_unlock(esw);
	return 0;
}
#endif


#ifdef HAVE_DEVLINK_HAS_RATE_FUNCTIONS
int mlx5_esw_devlink_rate_parent_set(struct devlink_rate *devlink_rate,
				     struct devlink_rate *parent,
				     void *priv, void *parent_priv,
				     struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node;
	struct mlx5_vport *vport = priv;

	if (!parent)
		return mlx5_esw_qos_vport_update_parent(vport, NULL, extack);

	node = parent_priv;
	return mlx5_esw_qos_vport_update_parent(vport, node, extack);
}
#endif

static bool mlx5_esw_validate_cross_esw_scheduling(struct mlx5_eswitch *esw,
						   struct mlx5_esw_sched_node *parent,
						   struct netlink_ext_ack *extack)
{
	if (!parent || esw == parent->esw)
		return 0;

	if (!MLX5_CAP_QOS(esw->dev, esw_cross_esw_sched)) {
		NL_SET_ERR_MSG_MOD(extack, "Cross E-Switch scheduling is not supported");
		return -EOPNOTSUPP;
	}
	if (esw->qos.domain != parent->esw->qos.domain) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cannot add vport to a parent belonging to a different qos domain");
		return -EOPNOTSUPP;
	}
	if (!mlx5_lag_is_active(esw->dev)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cross E-Switch scheduling requires LAG to be activated");
		return -EOPNOTSUPP;
	}

	return 0;
}

int mlx5_esw_qos_vport_update_parent(struct mlx5_vport *vport, struct mlx5_esw_sched_node *parent,
				     struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	int err = 0;

	err = mlx5_esw_validate_cross_esw_scheduling(esw, parent, extack);
	if (err)
		return err;

	esw_qos_lock(esw);
	if (!vport->qos.sched_node && parent) {
		enum sched_node_type type = parent->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR ?
					    SCHED_NODE_TYPE_RATE_LIMITER : SCHED_NODE_TYPE_VPORT;

		err = mlx5_esw_qos_vport_enable(vport, type, parent, 0, 0, extack);
	} else if (vport->qos.sched_node) {
		err = esw_qos_vport_update_parent(vport, parent, extack);
	}
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
			err = esw_qos_vport_update_parent(vport, node0, NULL);
			if (err)
				esw_warn(vport->dev,
					 "failed to move vport %d to node0\n", vport->vport);
		}
		if (!group->num_vports) {
			esw = group->esw;
			__esw_qos_destroy_node(group, NULL);
			esw_qos_put(esw);
		}
	}
	esw_qos_unlock(esw);
}
