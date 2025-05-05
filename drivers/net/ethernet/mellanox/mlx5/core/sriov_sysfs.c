/*
 * Copyright (c) 2014, Mellanox Technologies inc.  All rights reserved.
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

#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/etherdevice.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/vport.h>
#include <linux/mlx5/port.h>
#include "mlx5_core.h"
#include "eswitch.h"
#ifdef CONFIG_MLX5_ESWITCH
#include "esw/vf_meter.h"
#include "esw/qos.h"
#endif
#include "esw/legacy.h"

struct group_sysfs_opts {
	char *bus_name;
	char *dev_name;
	char *group_id;
};

struct vf_attributes {
	struct attribute attr;
	ssize_t (*show)(struct mlx5_sriov_vf *, struct vf_attributes *,
			char *buf);
	ssize_t (*store)(struct mlx5_sriov_vf *, struct vf_attributes *,
			 const char *buf, size_t count);
};

static ssize_t vf_attr_show(struct kobject *kobj,
			    struct attribute *attr, char *buf)
{
	struct vf_attributes *ga =
		container_of(attr, struct vf_attributes, attr);
	struct mlx5_sriov_vf *g = container_of(kobj, struct mlx5_sriov_vf, kobj);

	if (!ga->show)
		return -EIO;

	return ga->show(g, ga, buf);
}

static ssize_t vf_attr_store(struct kobject *kobj,
			     struct attribute *attr,
			     const char *buf, size_t size)
{
	struct vf_attributes *ga =
		container_of(attr, struct vf_attributes, attr);
	struct mlx5_sriov_vf *g = container_of(kobj, struct mlx5_sriov_vf, kobj);

	if (!ga->store)
		return -EIO;

	return ga->store(g, ga, buf, size);
}

static ssize_t vf_paging_attr_show(struct kobject *kobj,
				   struct attribute *attr, char *buf)
{
	struct vf_attributes *ga =
		container_of(attr, struct vf_attributes, attr);
	struct mlx5_sriov_vf *g = container_of(kobj, struct mlx5_sriov_vf, page_kobj);

	if (!ga->show)
		return -EIO;

	return ga->show(g, ga, buf);
}

static ssize_t vf_paging_attr_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buf, size_t size)
{
	struct vf_attributes *ga =
		container_of(attr, struct vf_attributes, attr);
	struct mlx5_sriov_vf *g = container_of(kobj, struct mlx5_sriov_vf, page_kobj);

	if (!ga->store)
		return -EIO;

	return ga->store(g, ga, buf, size);
}

struct vf_group_attributes {
	struct attribute attr;
	ssize_t (*show)(struct mlx5_esw_sched_node *, struct vf_group_attributes *,
			char *buf);
	ssize_t (*store)(struct mlx5_esw_sched_node *, struct vf_group_attributes *,
			 const char *buf, size_t count);
};

static ssize_t vf_group_attr_show(struct kobject *kobj,
				  struct attribute *attr, char *buf)
{
	struct vf_group_attributes *ga =
		container_of(attr, struct vf_group_attributes, attr);
	struct mlx5_esw_sched_node *g = container_of(kobj, struct mlx5_esw_sched_node, kobj);

	if (!ga->show)
		return -EIO;

	return ga->show(g, ga, buf);
}

static ssize_t vf_group_attr_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buf, size_t size)
{
	struct vf_group_attributes *ga =
		container_of(attr, struct vf_group_attributes, attr);
	struct mlx5_esw_sched_node *g = container_of(kobj, struct mlx5_esw_sched_node, kobj);

	if (!ga->store)
		return -EIO;

	return ga->store(g, ga, buf, size);
}

static ssize_t tc_bw_group_show(struct mlx5_esw_sched_node *g,
				struct vf_group_attributes *oa,
				char *buf)
{
	struct mlx5_esw_sched_node *vports_tc_node;
	u32 tc_bw[MLX5_MAX_NUM_TC] = {};

	if (g->type != SCHED_NODE_TYPE_TC_ARBITER_TSAR)
		return sprintf(buf, "TC BW is not yet configured\n");

	list_for_each_entry(vports_tc_node, &g->children, entry)
		tc_bw[vports_tc_node->tc] = vports_tc_node->user_bw_share;

	return sprintf(buf, "TC_BW 0:%d 1:%d 2:%d 3:%d 4:%d 5:%d 6:%d 7:%d \n",
		       tc_bw[0], tc_bw[1], tc_bw[2], tc_bw[3],
		       tc_bw[4], tc_bw[5], tc_bw[6], tc_bw[7]);
}

static int atoi(const char *s)
{
	unsigned int ret = 0;
	unsigned int d;

	while (1) {
		d = (*s++) - '0';
		if (d > 9)
			break;
		ret *= 10;
		ret += d;
	}
	return ret;
}

static int get_validate_tc_bw(const char *buf, u32*tc_bw)
{
	char tc_bw_str[MLX5_MAX_NUM_TC][7] = {};
	int i, err, sum = 0;
	char *p;

	err = sscanf(buf, "%s %s %s %s %s %s %s %s",
		     tc_bw_str[0], tc_bw_str[1], tc_bw_str[2], tc_bw_str[3],
		     tc_bw_str[4], tc_bw_str[5], tc_bw_str[6], tc_bw_str[7]);

	if (err != MLX5_MAX_NUM_TC)
		return -EINVAL;

	for (i = 0; i < MLX5_MAX_NUM_TC; i++) {
		p = strchr(tc_bw_str[i], ':');
		if (!p)
			return -EINVAL;

		tc_bw[i] = atoi(++p);
		sum += tc_bw[i];
	}
	if (sum && sum != 100)
		return -EINVAL;

	return 0;
}

static ssize_t tc_bw_group_store(struct mlx5_esw_sched_node *g,
				 struct vf_group_attributes *oa,
				 const char *buf, size_t count)
{
	u32 tc_bw[MLX5_MAX_NUM_TC] = {};
	int err;

	err = get_validate_tc_bw(buf, tc_bw);
	if (err)
		return err;

	err = mlx5_esw_sysfs_rate_node_tc_bw_set(g, tc_bw, NULL);

	return err ? err : count;
}

static ssize_t max_tx_rate_group_show(struct mlx5_esw_sched_node *g,
				      struct vf_group_attributes *oa,
				      char *buf)
{
	return sprintf(buf,
		       "usage: write <Rate (Mbit/s)> to set VF group max rate\n");
}

static ssize_t max_tx_rate_group_store(struct mlx5_esw_sched_node *g,
				       struct vf_group_attributes *oa,
				       const char *buf, size_t count)
{
	struct mlx5_eswitch *esw = g->esw;
	u32 max_rate;
	int err;

	err = kstrtou32(buf, 10, &max_rate);
	if(err)
		return err;

	if (max_rate && max_rate < g->min_rate)
		return -EINVAL;

	err = mlx5_esw_qos_set_sysfs_group_max_rate(esw, g, max_rate);

	return err ? err : count;
}

static ssize_t min_tx_rate_group_show(struct mlx5_esw_sched_node *g,
				      struct vf_group_attributes *oa,
				      char *buf)
{
	return sprintf(buf,
		       "usage: write <Rate (Mbit/s)> to set VF group min rate\n");
}

static ssize_t min_tx_rate_group_store(struct mlx5_esw_sched_node *g,
				       struct vf_group_attributes *oa,
				       const char *buf, size_t count)
{
	struct mlx5_eswitch *esw = g->esw;
	u32 min_rate;
	int err;

	err = kstrtou32(buf, 10, &min_rate);
	if(err)
		return err;

	if (g->max_rate && min_rate > g->max_rate)
		return -EINVAL;

	err = mlx5_esw_qos_set_sysfs_group_min_rate(esw, g, min_rate);

	return err ? err : count;
}

static ssize_t port_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			 char *buf)
{
	struct mlx5_core_dev *dev = g->dev;
	union ib_gid gid;
	int err;
	u8 *p;

	err = mlx5_core_query_gids(dev, 1, 1, g->vf, 0 , &gid);
	if (err) {
		mlx5_core_warn(dev, "failed to query gid at index 0 for vf %d\n", g->vf);
		return err;
	}

	p = &gid.raw[8];
	err = sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		      p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
	return err;
}

static ssize_t port_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			  const char *buf, size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
	struct mlx5_vf_context *vfs_ctx = dev->priv.sriov.vfs_ctx;
	struct mlx5_hca_vport_context *in;
	u64 guid = 0;
	int err;
	int tmp[8];
	int i;

	err = sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		     &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5], &tmp[6], &tmp[7]);
	if (err != 8)
		return -EINVAL;

	for (i = 0; i < 8; i++)
		guid += ((u64)tmp[i] << ((7 - i) * 8));

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->field_select = MLX5_HCA_VPORT_SEL_PORT_GUID;
	in->port_guid = guid;
	err = mlx5_core_modify_hca_vport_context(dev, 1, 1, g->vf + 1, in);
	kfree(in);
	if (err)
		return err;

	vfs_ctx[g->vf].port_guid = guid;

	return count;
}

static int show_hca_node_guid(struct mlx5_core_dev *dev, u16 vf,
			      __be64 *node_guid)
{
	struct mlx5_hca_vport_context *rep;
	int err = 0;

	rep = kzalloc(sizeof(*rep), GFP_KERNEL);
	if (!rep)
		return -ENOMEM;

	err = mlx5_core_query_hca_vport_context(dev, 1, 1,  vf, rep);
	if (err)
		goto free;

	*node_guid = cpu_to_be64(rep->node_guid);

free:
	kfree(rep);
	return err;
}

static int show_nic_node_guid(struct mlx5_core_dev *dev, u16 vf,
			      __be64 *node_guid)
{
	int err;

	err = mlx5_query_nic_vport_node_guid(dev, vf + 1, node_guid);
	if (!err)
		*node_guid = cpu_to_be64(*node_guid);

	return err;
}

static ssize_t node_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			 char *buf)
{
	struct mlx5_core_dev *dev = g->dev;
	__be64 guid;

	int err;
	u8 *p;

	if (MLX5_CAP_GEN(dev, port_type) == MLX5_CAP_PORT_TYPE_IB)
		err = show_hca_node_guid(dev, g->vf, &guid);
	else if (MLX5_CAP_GEN(dev, port_type) == MLX5_CAP_PORT_TYPE_ETH)
		err = show_nic_node_guid(dev, g->vf, &guid);
	else
		return -ENOTSUPP;

	if (err) {
		mlx5_core_warn(dev, "failed to query node guid for vf %d (%d)\n",
			       g->vf, err);
		return err;
	}

	p = (u8 *)&guid;
	err = sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		      p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

	return err;
}

static int modify_hca_node_guid(struct mlx5_core_dev *dev, u16 vf,
				u64 node_guid)
{
	struct mlx5_vf_context *vfs_ctx = dev->priv.sriov.vfs_ctx;
	struct mlx5_hca_vport_context *in;
	int err;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->field_select = MLX5_HCA_VPORT_SEL_NODE_GUID;
	in->node_guid = node_guid;
	err = mlx5_core_modify_hca_vport_context(dev, 1, 1, vf + 1, in);
	if (!err)
		vfs_ctx[vf].node_guid = node_guid;
	kfree(in);

	return err;
}

static int modify_nic_node_guid(struct mlx5_core_dev *dev, u16 vf,
				u64 node_guid)
{
	return mlx5_modify_nic_vport_node_guid(dev, vf + 1, node_guid);
}

static ssize_t node_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			  const char *buf, size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
	u64 guid = 0;
	int err;
	int tmp[8];
	int i;

	err = sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		     &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5], &tmp[6], &tmp[7]);
	if (err != 8)
		return -EINVAL;

	for (i = 0; i < 8; i++)
		guid += ((u64)tmp[i] << ((7 - i) * 8));

	if (MLX5_CAP_GEN(dev, port_type) == MLX5_CAP_PORT_TYPE_IB)
		err = modify_hca_node_guid(dev, g->vf, guid);
	else if (MLX5_CAP_GEN(dev, port_type) == MLX5_CAP_PORT_TYPE_ETH)
		err = modify_nic_node_guid(dev, g->vf, guid);
	else
		return -ENOTSUPP;

	if (err) {
		mlx5_core_warn(dev, "failed to modify node guid for vf %d (%d)\n",
			       g->vf, err);
		return err;
	}

	return count;
}

static const char *policy_str(enum port_state_policy policy)
{
	switch (policy) {
	case MLX5_POLICY_DOWN:		return "Down\n";
	case MLX5_POLICY_UP:		return "Up\n";
	case MLX5_POLICY_FOLLOW:	return "Follow\n";
	default:			return "Invalid policy\n";
	}
}

static ssize_t policy_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			   char *buf)
{
	struct mlx5_core_dev *dev = g->dev;
	struct mlx5_hca_vport_context *rep;
	const char *p = NULL;
	int err;

	rep = kzalloc(sizeof(*rep), GFP_KERNEL);
	if (!rep)
		return -ENOMEM;

	err = mlx5_core_query_hca_vport_context(dev, 1, 1,  g->vf, rep);
	if (err) {
		mlx5_core_warn(dev, "failed to query port policy for vf %d (%d)\n",
			       g->vf, err);
		goto free;
	}
	p = policy_str(rep->policy);
	strcpy(buf, p);

free:
	kfree(rep);
	return p ? strlen(p) : err;
}

static int strpolicy(const char *buf, enum port_state_policy *policy)
{
	if (sysfs_streq(buf, "Down")) {
		*policy = MLX5_POLICY_DOWN;
		return 0;
	}

	if (sysfs_streq(buf, "Up")) {
		*policy = MLX5_POLICY_UP;
		return 0;
	}

	if (sysfs_streq(buf, "Follow")) {
		*policy = MLX5_POLICY_FOLLOW;
		return 0;
	}
	return -EINVAL;
}

static ssize_t policy_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			    const char *buf, size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
	struct mlx5_vf_context *vfs_ctx = dev->priv.sriov.vfs_ctx;
	struct mlx5_hca_vport_context *in;
	enum port_state_policy policy;
	int err;

	err = strpolicy(buf, &policy);
	if (err)
		return err;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->policy = policy;
	in->field_select = MLX5_HCA_VPORT_SEL_STATE_POLICY;
	err = mlx5_core_modify_hca_vport_context(dev, 1, 1, g->vf + 1, in);
	kfree(in);
	if (err)
		return err;

	vfs_ctx[g->vf].policy = policy;

	return count;
}

#ifdef CONFIG_MLX5_ESWITCH
/* ETH SRIOV SYSFS */
static ssize_t mac_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			char *buf)
{
	return sprintf(buf,
		       "usage: write <LLADDR|Random> to set VF Mac Address\n");
}

static ssize_t mac_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			 const char *buf, size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
	u8 mac[ETH_ALEN];
	int err;

	err = sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		     &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	if (err == 6)
		goto set_mac;

	if (sysfs_streq(buf, "Random"))
		eth_random_addr(mac);
	else
		return -EINVAL;

set_mac:
	err = mlx5_eswitch_set_vport_mac(dev->priv.eswitch, g->vf + 1, mac);
	return err ? err : count;
}

static ssize_t vlan_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			 char *buf)
{
	return sprintf(buf,
		       "usage: write <Vlan:Qos[:Proto]> to set VF Vlan,"
		       " Qos, and optionally Vlan Protocol (default 802.1Q)\n");
}

static ssize_t vlan_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
		const char *buf, size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
	char vproto_ext[5] = {'\0'};
	__be16 vlan_proto;
	u16 vlan_id;
	u8 qos;
	int err;

	err = sscanf(buf, "%hu:%hhu:802.%4s", &vlan_id, &qos, vproto_ext);
	if (err == 3) {
		if ((strcmp(vproto_ext, "1AD") == 0) ||
				(strcmp(vproto_ext, "1ad") == 0))
			vlan_proto = htons(ETH_P_8021AD);
		else if ((strcmp(vproto_ext, "1Q") == 0) ||
				(strcmp(vproto_ext, "1q") == 0))
			vlan_proto = htons(ETH_P_8021Q);
		else
			return -EINVAL;
	} else {
		err = sscanf(buf, "%hu:%hhu", &vlan_id, &qos);
		if (err != 2)
			return -EINVAL;
		vlan_proto = htons(ETH_P_8021Q);
	}

	err = mlx5_eswitch_set_vport_vlan(dev->priv.eswitch, g->vf + 1,
			vlan_id, qos, vlan_proto);
	return err ? err : count;
}

static const char *vlan_proto_str(u16 vlan, u8 qos, __be16 vlan_proto)
{
	if (!vlan && !qos)
		return "N/A";

	switch (vlan_proto) {
	case htons(ETH_P_8021AD):	return "802.1ad";
	case htons(ETH_P_8021Q):	return "802.1Q";
	default:			return "Invalid vlan protocol";
	}
}

static ssize_t spoofcheck_show(struct mlx5_sriov_vf *g,
			       struct vf_attributes *oa,
			       char *buf)
{
	return sprintf(buf,
		       "usage: write <ON|OFF> to enable|disable VF SpoofCheck\n"
		       );
}

static ssize_t spoofcheck_store(struct mlx5_sriov_vf *g,
				struct vf_attributes *oa,
				const char *buf,
				size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
	bool settings;
	int err;

	if (sysfs_streq(buf, "ON"))
		settings = true;
	else if (sysfs_streq(buf, "OFF"))
		settings = false;
	else
		return -EINVAL;

	err = mlx5_eswitch_set_vport_spoofchk(dev->priv.eswitch, g->vf + 1, settings);
	return err ? err : count;
}

static ssize_t trust_show(struct mlx5_sriov_vf *g,
			  struct vf_attributes *oa,
			  char *buf)
{
	return sprintf(buf,
		       "usage: write <ON|OFF> to trust|untrust VF\n"
		       );
}

static ssize_t trust_store(struct mlx5_sriov_vf *g,
			   struct vf_attributes *oa,
			   const char *buf,
			   size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
	bool settings;
	int err;

	if (sysfs_streq(buf, "ON"))
		settings = true;
	else if (sysfs_streq(buf, "OFF"))
		settings = false;
	else
		return -EINVAL;

	err = mlx5_eswitch_set_vport_trust(dev->priv.eswitch, g->vf + 1, settings);
	return err ? err : count;
}

static ssize_t link_state_show(struct mlx5_sriov_vf *g,
			       struct vf_attributes *oa,
			       char *buf)
{
	return sprintf(buf, "usage: write <Up|Down|Follow> to set VF State\n");
}

static ssize_t link_state_store(struct mlx5_sriov_vf *g,
				struct vf_attributes *oa,
				const char *buf,
				size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
	enum port_state_policy policy;
	int err;

	err = strpolicy(buf, &policy);
	if (err)
		return err;

	err = mlx5_eswitch_set_vport_state(dev->priv.eswitch, g->vf + 1, policy);
	return err ? err : count;
}

static ssize_t max_tx_rate_show(struct mlx5_sriov_vf *g,
				struct vf_attributes *oa,
				char *buf)
{
	return sprintf(buf,
		       "usage: write <Rate (Mbit/s)> to set VF max rate\n");
}

static ssize_t max_tx_rate_store(struct mlx5_sriov_vf *g,
				 struct vf_attributes *oa,
				 const char *buf, size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5_vport *vport = mlx5_eswitch_get_vport(esw, g->vf + 1);
	u32 max_tx_rate;
	int err;

	err = kstrtou32(buf, 10, &max_tx_rate);
	if (err)
		return err;

	esw_qos_lock(esw);
	err = mlx5_esw_qos_set_vport_max_rate(vport, max_tx_rate, NULL);
	esw_qos_unlock(esw);
	return err ? err : count;
}

static ssize_t group_show(struct mlx5_sriov_vf *g,
			  struct vf_attributes *oa,
			  char *buf)
{
	return sprintf(buf,
		       "usage: write <Group 0-%d> to set VF vport group\n",
		       MLX5_ESW_QOS_SYSFS_GROUP_MAX_ID);
}

static unsigned int get_str_char_count(char *str, int match)
{
	unsigned int count = 0;
	const char *pos = str;

	while ((pos = strchr(pos, match))) {
		count++;
		pos++;
	}
	return count;
}

static int ident_str_validate(char *str, unsigned int expected)
{
	if (!str)
		return -ENOENT;

	if (get_str_char_count(str, '/') != expected) {
		pr_info("Wrong identification string format.\n");
		return -EINVAL;
	}

	return 0;
}

static int str_split_by_char(char *str, char **before, char **after, int match)
{
	char *slash;

	slash = strrchr(str, match);
	if (!slash)
		return -EINVAL;
	*slash = '\0';
	*before = str;
	*after = slash + 1;
	return 0;
}

static int parse_name(char *str, char **bus_name, char **dev_name, char **group_id)
{
	char *handlestr;
	int err;

	err = str_split_by_char(str, &handlestr, group_id, '/');
	if (err)
		return err;

	return str_split_by_char(handlestr, bus_name, dev_name, '/');
}

static int parse_long_group_id(char *str, char **bus_name, char **dev_name, char **group_id)
{
	int err;

	err = ident_str_validate(str, 2);
	if (err) {
		pr_err("Expected \"bus_name/dev_name/group_id\" identification.\n");
		return err;
	}

	err = parse_name(str, bus_name, dev_name, group_id);
	if (err) {
		pr_err("Node identification \"%s\" is invalid\n", str);
		return err;
	}

	if (!**group_id) {
		err = -EINVAL;
		pr_err("group id can't be empty.\n");
	}

        return err;
}


static struct group_sysfs_opts *get_long_group_id(struct group_sysfs_opts *opts,
						  u32 *group_id,
						  const char *buf)
{
	int err;

	/* If the input is only a number, use local esw to create group. */
	if (strspn(buf, "0123456789") == strlen(buf) - 1) {
		err = kstrtou32(buf, 10, group_id);
		if(err){
			pr_err("failed to get group id\n");
			return ERR_PTR(-EINVAL);
		}
		return NULL;
	}

	err = parse_long_group_id((char *)buf, &opts->bus_name, &opts->dev_name,
				  &opts->group_id);
	if (err != 0) {
		pr_err("failed to parse pci/dev/group_id\n");
		return ERR_PTR(-EINVAL);
	}
	err = kstrtou32(opts->group_id, 10, group_id);
	if(err){
		pr_err("failed to get long group id\n");
		return ERR_PTR(-EINVAL);
	}

	return opts;
}

static bool esw_equal(const struct mlx5_eswitch *esw, const struct group_sysfs_opts *opts)
{
	return !strcmp(esw->dev->device->bus->name, opts->bus_name) &&
	       !strcmp(dev_name(esw->dev->device), opts->dev_name);
}

static ssize_t group_store(struct mlx5_sriov_vf *g,
			   struct vf_attributes *oa,
			   const char *buf, size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
	struct mlx5_eswitch *esw = dev->priv.eswitch, *peer_esw;
	struct mlx5_devcom_comp_dev *devcom = esw->devcom, *pos;
	struct group_sysfs_opts opts, *opts_p;
	struct mlx5_vport *vport;
	bool found = false;
	u32 group_id;
	int err;

	opts_p = get_long_group_id(&opts, &group_id, buf);
	if (IS_ERR(opts_p))
		return PTR_ERR(opts_p);

	if (group_id > MLX5_ESW_QOS_SYSFS_GROUP_MAX_ID) {
		pr_err("group id should be smaller than %d\n",
		       MLX5_ESW_QOS_SYSFS_GROUP_MAX_ID + 1);
		return -EINVAL;
	}

	/* If the input is pci/dev/group_id, eg. "pci/0000:08:00.0/1",
	 * but the device is local, no need to use devcom to find peer esw.
	 */
	if (opts_p && esw_equal(esw, opts_p))
		opts_p = NULL;

	/* Currently, we support to add a vf to a group of other esw, pass a
	 * vf number is not enough, get the vport.
	 */
	vport = mlx5_eswitch_get_vport(esw, g->vf + 1);
	if (IS_ERR(vport))
		return PTR_ERR(vport);

	/* vport and group are in the same esw. */
	if (!opts_p) {
		err = mlx5_esw_qos_vport_update_sysfs_group(esw, group_id, vport);
		return err ? err : count;
	}

	if (!MLX5_CAP_QOS(esw->dev, esw_cross_esw_sched)) {
		pr_err("Cross E-Switch scheduling is not supported\n");
		return -EOPNOTSUPP;
	}

	if (!mlx5_lag_is_active(esw->dev)) {
		pr_err("Cross E-Switch scheduling is only supported when LAG is active\n");
		return -EOPNOTSUPP;
	}

	if (!mlx5_devcom_for_each_peer_begin(devcom)) {
		pr_err("devcom is not ready\n");
		return -ENODEV;
	}

	mlx5_devcom_for_each_peer_entry(devcom, peer_esw, pos) {
		if (!esw_equal(peer_esw, opts_p))
			continue;

		err = mlx5_esw_qos_vport_update_sysfs_group(peer_esw, group_id, vport);
		if (err) {
			esw_warn(peer_esw->dev,
				 "failed to add vport %d to peer esw, err: %d\n",
				 vport->vport, err);
			mlx5_devcom_for_each_peer_end(devcom);
			return err;
		}
		found = true;
		break;
	}

	mlx5_devcom_for_each_peer_end(devcom);

	if (!found) {
		pr_err("pci dev %s not found\n", opts_p->dev_name);
		return -ENODEV;
	}

	return count;
}

static ssize_t min_tx_rate_show(struct mlx5_sriov_vf *g,
				struct vf_attributes *oa,
				char *buf)
{
	return sprintf(buf,
		       "usage: write <Rate (Mbit/s)> to set VF min rate\n");
}

static ssize_t min_tx_rate_store(struct mlx5_sriov_vf *g,
				 struct vf_attributes *oa,
				 const char *buf, size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5_vport *vport = mlx5_eswitch_get_vport(esw, g->vf + 1);
	u32 min_tx_rate;
	int err;

	err = kstrtou32(buf, 10, &min_tx_rate);
	if (err)
		return err;

	esw_qos_lock(esw);
	err = mlx5_esw_qos_set_vport_min_rate(vport, min_tx_rate, NULL);
	esw_qos_unlock(esw);
	return err ? err : count;
}

static ssize_t tc_bw_show(struct mlx5_sriov_vf *g,
			  struct vf_attributes *oa,
			  char *buf)
{
	struct mlx5_core_dev *dev = g->dev;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5_vport *evport = mlx5_eswitch_get_vport(esw, g->vf + 1);
	struct mlx5_esw_sched_node *vports_tc_node;
	u32 tc_bw[MLX5_MAX_NUM_TC] = {};

	if (!evport->qos.sched_nodes)
		return sprintf(buf, "TC BW is not yet configured\n");

	list_for_each_entry(vports_tc_node, &evport->qos.sched_node->children, entry)
		tc_bw[vports_tc_node->tc] = vports_tc_node->user_bw_share;

	return sprintf(buf, "TC BW 0:%d 1:%d 2:%d 3:%d 4:%d 5:%d 6:%d 7:%d \n",
		       tc_bw[0], tc_bw[1], tc_bw[2], tc_bw[3],
		       tc_bw[4], tc_bw[5], tc_bw[6], tc_bw[7]);
}

static ssize_t tc_bw_store(struct mlx5_sriov_vf *g,
			   struct vf_attributes *oa,
			   const char *buf, size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5_vport *evport = mlx5_eswitch_get_vport(esw, g->vf + 1);
	u32 tc_bw[MLX5_MAX_NUM_TC] = {};
	int err;

	err = get_validate_tc_bw(buf, tc_bw);
	if (err)
		return err;

	err =  mlx5_esw_sysfs_rate_leaf_tc_bw_set(evport, tc_bw, NULL);

	return err ? err : count;
}
#define _sprintf(p, buf, format, arg...)				\
	((PAGE_SIZE - (int)(p - buf)) <= 0 ? 0 :			\
	scnprintf(p, PAGE_SIZE - (int)(p - buf), format, ## arg))

static ssize_t trunk_show(struct mlx5_sriov_vf *g,
			  struct vf_attributes *oa,
			  char *buf)
{
	struct mlx5_core_dev *dev = g->dev;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5_vport *evport = mlx5_eswitch_get_vport(esw, g->vf + 1);
	u16 vlan_id = 0;
	char *ret = buf;

	mutex_lock(&esw->state_lock);
	if (!!bitmap_weight(evport->info.vlan_trunk_8021q_bitmap, VLAN_N_VID)) {
		ret += _sprintf(ret, buf, "Allowed 802.1Q VLANs:");
		for_each_set_bit(vlan_id, evport->info.vlan_trunk_8021q_bitmap,
				VLAN_N_VID)
			ret += _sprintf(ret, buf, " %d", vlan_id);
		ret += _sprintf(ret, buf, "\n");
	}
	mutex_unlock(&esw->state_lock);

	return (ssize_t)(ret - buf);
}

static ssize_t trunk_store(struct mlx5_sriov_vf *g,
			   struct vf_attributes *oa,
			   const char *buf,
			   size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
	u16 start_vid, end_vid;
	char op[5];
	int err;

	err = sscanf(buf, "%4s %hu %hu", op, &start_vid, &end_vid);
	if (err != 3)
		return -EINVAL;

	if (!strcmp(op, "add"))
		err = mlx5_eswitch_add_vport_trunk_range(dev->priv.eswitch,
							 g->vf + 1,
							 start_vid, end_vid);
	else if (!strcmp(op, "rem"))
		err = mlx5_eswitch_del_vport_trunk_range(dev->priv.eswitch,
							 g->vf + 1,
							 start_vid, end_vid);
	else
		return -EINVAL;

	return err ? err : count;
}

static ssize_t config_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			   char *buf)
{
	struct mlx5_core_dev *dev = g->dev;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5_vport *evport = mlx5_eswitch_get_vport(esw, g->vf + 1);
	struct mlx5_vport_info *ivi;
	char *p = buf;

	if (!esw && MLX5_CAP_GEN(esw->dev, vport_group_manager) && mlx5_core_is_pf(esw->dev))
		return -EPERM;

	if (IS_ERR(evport))
		return PTR_ERR(evport);

	mutex_lock(&esw->state_lock);
	ivi = &evport->info;
	p += _sprintf(p, buf, "VF         : %d\n", g->vf);
	p += _sprintf(p, buf, "MAC        : %pM\n", ivi->mac);
	p += _sprintf(p, buf, "VLAN       : %d\n", ivi->vlan);
	p += _sprintf(p, buf, "QoS        : %d\n", ivi->qos);
	p += _sprintf(p, buf, "VLAN Proto : %s\n",
		      vlan_proto_str(ivi->vlan, ivi->qos, ivi->vlan_proto));
	p += _sprintf(p, buf, "SpoofCheck : %s\n", ivi->spoofchk ? "ON" : "OFF");
	p += _sprintf(p, buf, "Trust      : %s\n", ivi->trusted ? "ON" : "OFF");
	p += _sprintf(p, buf, "LinkState  : %s",   policy_str(ivi->link_state));
	if (evport->qos.sched_node) {
		struct mlx5_esw_sched_node *parent = mlx5_esw_qos_vport_get_parent(evport);

		p += _sprintf(p, buf, "MinTxRate  : %d\n", evport->qos.sched_node->min_rate);
		p += _sprintf(p, buf, "MaxTxRate  : %d\n", evport->qos.sched_node->max_rate);
		if (parent)
			p += _sprintf(p, buf, "RateGroup  : %d\n", parent->group_id);
		else
			p += _sprintf(p, buf, "RateGroup  : 0\n");
	} else {
		p += _sprintf(p, buf, "MinTxRate  : 0\nMaxTxRate  : 0\nRateGroup  : 0\n");
	}
	p += _sprintf(p, buf, "VGT+       : %s\n",
		      !!bitmap_weight(ivi->vlan_trunk_8021q_bitmap,
				      VLAN_N_VID) ? "ON" : "OFF");

	p += _sprintf(p, buf, "RateGroup  : %d\n", ivi->group);

	if (evport->qos.sched_nodes) {
		struct mlx5_esw_sched_node *vports_tc_node;
		u32 tc_bw[MLX5_MAX_NUM_TC] = {0};

		list_for_each_entry(vports_tc_node, &evport->qos.sched_node->children, entry)
			tc_bw[vports_tc_node->tc] = vports_tc_node->user_bw_share;
		p += _sprintf(p, buf, "TC BW      : 0:%d 1:%d 2:%d 3:%d 4:%d 5:%d 6:%d 7:%d\n",
			       tc_bw[0], tc_bw[1], tc_bw[2], tc_bw[3],
			       tc_bw[4], tc_bw[5], tc_bw[6], tc_bw[7]);
	}

	mutex_unlock(&esw->state_lock);

	return (ssize_t)(p - buf);
}

static ssize_t config_store(struct mlx5_sriov_vf *g,
			    struct vf_attributes *oa,
			    const char *buf, size_t count)
{
	return -ENOTSUPP;
}

static ssize_t config_group_show(struct mlx5_esw_sched_node *g,
				 struct vf_group_attributes *oa,
				 char *buf)
{
	struct mlx5_eswitch *esw = g->esw;
	char *p = buf;

	if (!esw && MLX5_CAP_GEN(esw->dev, vport_group_manager) &&
	    mlx5_core_is_pf(esw->dev))
		return -EPERM;

	if (!mutex_trylock(&esw->qos.domain->lock))
		return -EBUSY;

	p += _sprintf(p, buf, "Num VFs    : %d\n", g->num_vports);
	p += _sprintf(p, buf, "MaxRate    : %d\n", g->max_rate);
	p += _sprintf(p, buf, "MinRate    : %d\n", g->min_rate);
	p += _sprintf(p, buf, "BWShare(Indirect cfg)    : %d\n", g->bw_share);

	if (g->type == SCHED_NODE_TYPE_TC_ARBITER_TSAR) {
		struct mlx5_esw_sched_node *vports_tc_node;
		u32 tc_bw[MLX5_MAX_NUM_TC] = {0};

                list_for_each_entry(vports_tc_node, &g->children, entry)
			tc_bw[vports_tc_node->tc] = vports_tc_node->user_bw_share;

		p += _sprintf(p, buf, "TC BW      : 0:%d 1:%d 2:%d 3:%d 4:%d 5:%d 6:%d 7:%d\n",
			      tc_bw[0], tc_bw[1], tc_bw[2], tc_bw[3],
			      tc_bw[4], tc_bw[5], tc_bw[6], tc_bw[7]);
	}

	mutex_unlock(&esw->qos.domain->lock);

	return (ssize_t)(p - buf);
}

static ssize_t config_group_store(struct mlx5_esw_sched_node *g,
				  struct vf_group_attributes *oa,
				  const char *buf, size_t count)
{
	return -ENOTSUPP;
}

static ssize_t stats_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			  char *buf)
{
	struct ifla_vf_stats_backport ifi_backport;
	struct mlx5_core_dev *dev = g->dev;
	struct mlx5_vport *vport = mlx5_eswitch_get_vport(dev->priv.eswitch, g->vf + 1);
	struct ifla_vf_stats ifi;
	struct mlx5_vport_drop_stats stats = {};
	int err;
	char *p = buf;

	err = mlx5_eswitch_get_vport_stats(dev->priv.eswitch, g->vf + 1, &ifi);
	if (err)
		return -EINVAL;

	err = mlx5_eswitch_get_vport_stats_backport(dev->priv.eswitch, g->vf + 1, &ifi_backport);
	if (err)
		return -EINVAL;

	err = mlx5_esw_query_vport_drop_stats(dev, vport, &stats);
	if (err)
		return -EINVAL;

	p += _sprintf(p, buf, "tx_packets    : %llu\n", ifi.tx_packets);
	p += _sprintf(p, buf, "tx_bytes      : %llu\n", ifi.tx_bytes);
	p += _sprintf(p, buf, "tx_dropped    : %llu\n", stats.tx_dropped);
	p += _sprintf(p, buf, "rx_packets    : %llu\n", ifi.rx_packets);
	p += _sprintf(p, buf, "rx_bytes      : %llu\n", ifi.rx_bytes);
	p += _sprintf(p, buf, "rx_broadcast  : %llu\n", ifi.broadcast);
	p += _sprintf(p, buf, "rx_multicast  : %llu\n", ifi.multicast);
	p += _sprintf(p, buf, "tx_broadcast  : %llu\n", ifi_backport.tx_broadcast);
	p += _sprintf(p, buf, "tx_multicast  : %llu\n", ifi_backport.tx_multicast);
	p += _sprintf(p, buf, "rx_dropped    : %llu\n", stats.rx_dropped);

	return (ssize_t)(p - buf);
}

static ssize_t stats_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			   const char *buf, size_t count)
{
	return -ENOTSUPP;
}

static ssize_t vf_meter_common_show(struct mlx5_sriov_vf *g,
				    struct vf_attributes *oa, char *buf,
				    int data_type)
{
	struct mlx5_core_dev *dev = g->dev;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	u64 data;
	int err;

	err = mlx5_eswitch_get_vf_meter_data(esw, g->vf + 1, data_type,
					     g->meter_type.rx_tx,
					     g->meter_type.xps, &data);
	if (err)
		return err;

	return sprintf(buf, "%lld\n", data);
}

static ssize_t vf_meter_common_store(struct mlx5_sriov_vf *g,
				     struct vf_attributes *oa,
				     const char *buf, size_t count,
				     int data_type)
{
	struct mlx5_core_dev *dev = g->dev;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	s64 data;
	int err;

	err = kstrtos64(buf, 10, &data);
	if (err)
		return err;

	if (data < 0)
		return -EINVAL;

	err = mlx5_eswitch_set_vf_meter_data(esw, g->vf + 1, data_type,
					     g->meter_type.rx_tx,
					     g->meter_type.xps, data);

	return err ? err : count;
}

static ssize_t rate_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			 char *buf)
{
	return vf_meter_common_show(g, oa, buf, MLX5_RATE_LIMIT_DATA_RATE);
}

static ssize_t rate_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			  const char *buf, size_t count)
{
	return vf_meter_common_store(g, oa, buf, count, MLX5_RATE_LIMIT_DATA_RATE);
}

static ssize_t burst_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			  char *buf)
{
	return vf_meter_common_show(g, oa, buf, MLX5_RATE_LIMIT_DATA_BURST);
}

static ssize_t burst_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			   const char *buf, size_t count)
{
	return vf_meter_common_store(g, oa, buf, count, MLX5_RATE_LIMIT_DATA_BURST);
}

static ssize_t bytes_dropped_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
				  char *buf)
{
	return vf_meter_common_show(g, oa, buf, MLX5_RATE_LIMIT_DATA_BYTES_DROPPED);
}

static ssize_t bytes_dropped_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
				   const char *buf, size_t count)
{
	return -EOPNOTSUPP;
}

static ssize_t packets_dropped_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
				    char *buf)
{
	return vf_meter_common_show(g, oa, buf, MLX5_RATE_LIMIT_DATA_PACKETS_DROPPED);
}

static ssize_t packets_dropped_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
				     const char *buf, size_t count)
{
	return -EOPNOTSUPP;
}

static ssize_t page_limit_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			       char *buf)
{
	struct mlx5_eswitch *esw = g->dev->priv.eswitch;
	struct mlx5_vport *evport;
	u16 vhca_id;
	u32 page_limit;
	int err;

	if (mlx5_vhca_icm_ctrl_supported(esw->dev)) {
		err = mlx5_esw_query_vport_vhca_id(esw, g->vf + 1, &vhca_id);
		if (err)
			return err;

		err = mlx5_get_max_alloc_icm_th(g->dev, vhca_id, &page_limit);
		if (err)
			return err;
		goto out;
	    }

	evport = mlx5_eswitch_get_vport(esw, g->vf + 1);
	spin_lock(&evport->pg_counters_lock);
	page_limit = evport->page_limit;
	spin_unlock(&evport->pg_counters_lock);
out:
	return sprintf(buf, "%u\n", page_limit);
}

#define PAGE_LIMIT_UNLIMITED UINT_MAX
static ssize_t page_limit_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
				const char *buf, size_t count)
{
	struct mlx5_eswitch *esw = g->dev->priv.eswitch;
	struct mlx5_vport *evport;
	u16 vhca_id;
	u32 limit;
	int err;

	err = sscanf(buf, "%u", &limit);
	if (err != 1)
		return -EINVAL;

	if (mlx5_vhca_icm_ctrl_supported(esw->dev)) {
		err = mlx5_esw_query_vport_vhca_id(esw, g->vf + 1, &vhca_id);
		if (err)
			return err;

		if (!limit)
			limit = PAGE_LIMIT_UNLIMITED;

		err = mlx5_set_max_alloc_icm_th(g->dev, vhca_id, limit);
		if (err)
			return err;
		goto out;
	    }

	evport = mlx5_eswitch_get_vport(esw, g->vf + 1);
	spin_lock(&evport->pg_counters_lock);
	evport->page_limit = limit;
	spin_unlock(&evport->pg_counters_lock);
out:
	return count;
}

static ssize_t num_pages_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			      char *buf)
{
	struct mlx5_eswitch *esw = g->dev->priv.eswitch;
	struct mlx5_vport *evport;
	u32 fw_pages;

	evport = mlx5_eswitch_get_vport(esw, g->vf + 1);
	spin_lock(&evport->pg_counters_lock);
	fw_pages = evport->fw_pages;
	spin_unlock(&evport->pg_counters_lock);
	return sprintf(buf, "%u\n", fw_pages);
}

static ssize_t num_pages_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			       const char *buf, size_t count)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_MLX5_ESWITCH */

static ssize_t num_vf_store(struct device *device, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct pci_dev *pdev = container_of(device, struct pci_dev, dev);
	int req_vfs;
	int err;

	if (kstrtoint(buf, 0, &req_vfs) || req_vfs < 0 ||
	    req_vfs > pci_sriov_get_totalvfs(pdev))
		return -EINVAL;

	err = mlx5_core_sriov_configure(pdev, req_vfs);
	if (err < 0)
		return err;

	return count;
}

static ssize_t num_vf_show(struct device *device, struct device_attribute *attr,
			   char *buf)
{
	struct pci_dev *pdev = container_of(device, struct pci_dev, dev);
	struct mlx5_core_dev *dev  = pci_get_drvdata(pdev);
	struct mlx5_core_sriov *sriov = &dev->priv.sriov;

	return sprintf(buf, "%d\n", sriov->num_vfs);
}

static DEVICE_ATTR(mlx5_num_vfs, 0600, num_vf_show, num_vf_store);

static const struct sysfs_ops vf_sysfs_ops = {
	.show = vf_attr_show,
	.store = vf_attr_store,
};

static const struct sysfs_ops vf_paging_ops = {
	.show = vf_paging_attr_show,
	.store = vf_paging_attr_store,
};

static const struct sysfs_ops vf_group_sysfs_ops = {
	.show = vf_group_attr_show,
	.store = vf_group_attr_store,
};

#define VF_RATE_GROUP_ATTR(_name) struct vf_group_attributes vf_group_attr_##_name = \
	__ATTR(_name, 0644, _name##_group_show, _name##_group_store)
#define VF_ATTR(_name) struct vf_attributes vf_attr_##_name = \
	__ATTR(_name, 0644, _name##_show, _name##_store)

VF_ATTR(node);
VF_ATTR(port);
VF_ATTR(policy);

#ifdef CONFIG_MLX5_ESWITCH
VF_ATTR(mac);
VF_ATTR(vlan);
VF_ATTR(link_state);
VF_ATTR(spoofcheck);
VF_ATTR(trust);
VF_ATTR(page_limit);
VF_ATTR(num_pages);
VF_ATTR(max_tx_rate);
VF_ATTR(min_tx_rate);
VF_ATTR(tc_bw);
VF_ATTR(config);
VF_ATTR(trunk);
VF_ATTR(stats);
VF_ATTR(group);
VF_RATE_GROUP_ATTR(min_tx_rate);
VF_RATE_GROUP_ATTR(max_tx_rate);
VF_RATE_GROUP_ATTR(config);
VF_RATE_GROUP_ATTR(tc_bw);

static struct attribute *vf_eth_attrs[] = {
	&vf_attr_node.attr,
	&vf_attr_mac.attr,
	&vf_attr_vlan.attr,
	&vf_attr_link_state.attr,
	&vf_attr_spoofcheck.attr,
	&vf_attr_trust.attr,
	&vf_attr_max_tx_rate.attr,
	&vf_attr_min_tx_rate.attr,
	&vf_attr_tc_bw.attr,
	&vf_attr_config.attr,
	&vf_attr_trunk.attr,
	&vf_attr_stats.attr,
	&vf_attr_group.attr,
	NULL
};

static struct attribute *vf_group_attrs[] = {
	&vf_group_attr_max_tx_rate.attr,
	&vf_group_attr_min_tx_rate.attr,
	&vf_group_attr_config.attr,
	&vf_group_attr_tc_bw.attr,
	NULL
};

static struct attribute *vf_paging_attrs[] = {
	&vf_attr_page_limit.attr,
	&vf_attr_num_pages.attr,
	NULL
};

ATTRIBUTE_GROUPS(vf_group);

static struct kobj_type vf_group = {
	.sysfs_ops     = &vf_group_sysfs_ops,
	.default_groups = vf_group_groups
};

ATTRIBUTE_GROUPS(vf_eth);

static struct kobj_type vf_type_eth = {
	.sysfs_ops     = &vf_sysfs_ops,
	.default_groups = vf_eth_groups
};

ATTRIBUTE_GROUPS(vf_paging);

static struct kobj_type vf_paging = {
	.sysfs_ops     = &vf_paging_ops,
	.default_groups = vf_paging_groups
};

VF_ATTR(rate);
VF_ATTR(burst);
VF_ATTR(bytes_dropped);
VF_ATTR(packets_dropped);

static struct attribute *vf_meters_eth_attrs[] = {
	&vf_attr_rate.attr,
	&vf_attr_burst.attr,
	&vf_attr_bytes_dropped.attr,
	&vf_attr_packets_dropped.attr,
	NULL
};

ATTRIBUTE_GROUPS(vf_meters_eth);

static struct kobj_type vf_meters_type_eth = {
	.sysfs_ops     = &vf_sysfs_ops,
	.default_groups = vf_meters_eth_groups
};
#endif /* CONFIG_MLX5_ESWITCH */

static struct attribute *vf_ib_attrs[] = {
	&vf_attr_node.attr,
	&vf_attr_port.attr,
	&vf_attr_policy.attr,
	NULL
};

ATTRIBUTE_GROUPS(vf_ib);

static struct kobj_type vf_type_ib = {
	.sysfs_ops     = &vf_sysfs_ops,
	.default_groups = vf_ib_groups
};

static struct device_attribute *mlx5_class_attributes[] = {
	&dev_attr_mlx5_num_vfs,
};

int mlx5_sriov_sysfs_init(struct mlx5_core_dev *dev)
{
	struct mlx5_core_sriov *sriov = &dev->priv.sriov;
	struct device *device = &dev->pdev->dev;
	int err;
	int i;

	sriov->config = kobject_create_and_add("sriov", &device->kobj);
	if (!sriov->config)
		return -ENOMEM;

#ifdef CONFIG_MLX5_ESWITCH
	if (MLX5_CAP_QOS(dev, log_esw_max_sched_depth)) {
		sriov->groups_config = kobject_create_and_add("groups",
							      sriov->config);
		if (!sriov->groups_config) {
			err = -ENOMEM;
			goto err_groups;
		}
	}
#endif

	for (i = 0; i < ARRAY_SIZE(mlx5_class_attributes); i++) {
		err = device_create_file(device, mlx5_class_attributes[i]);
		if (err)
			goto err_attr;
	}

	return 0;

err_attr:
	if (sriov->groups_config) {
		kobject_put(sriov->groups_config);
		sriov->groups_config = NULL;
	}

err_groups:
	kobject_put(sriov->config);
	sriov->config = NULL;
	return err;
}

void mlx5_sriov_sysfs_cleanup(struct mlx5_core_dev *dev)
{
	struct mlx5_core_sriov *sriov = &dev->priv.sriov;
	struct device *device = &dev->pdev->dev;
	int i;

	for (i = 0; i < ARRAY_SIZE(mlx5_class_attributes); i++)
		device_remove_file(device, mlx5_class_attributes[i]);

	if (MLX5_CAP_QOS(dev, log_esw_max_sched_depth))
		kobject_put(sriov->groups_config);
	kobject_put(sriov->config);
	sriov->config = NULL;
}

int mlx5_create_vf_group_sysfs(struct mlx5_core_dev *dev,
			       u32 group_id, struct kobject *group_kobj)
{
	struct mlx5_core_sriov *sriov = &dev->priv.sriov;
	int err;

#ifdef CONFIG_MLX5_ESWITCH
	err = kobject_init_and_add(group_kobj, &vf_group, sriov->groups_config,
				   "%d", group_id);
	if (err)
		return err;

	kobject_uevent(group_kobj, KOBJ_ADD);
#endif

	return 0;
}

#ifdef CONFIG_MLX5_ESWITCH
struct mlx5_group_kobj {
	struct work_struct work;
	struct mlx5_esw_sched_node *group;
};

static void destroy_vf_group_work(struct work_struct *work)
{
	struct mlx5_group_kobj *obj = container_of(work, struct mlx5_group_kobj, work);
	struct mlx5_esw_sched_node *group = obj->group;

	kobject_put(&group->kobj);
	complete_all(&group->free_group_comp);
	kfree(obj);
}
#endif

void mlx5_destroy_vf_group_sysfs(struct mlx5_esw_sched_node *group)
{
#ifdef CONFIG_MLX5_ESWITCH
	struct mlx5_group_kobj *kobj = kzalloc(sizeof *kobj, GFP_ATOMIC);

	INIT_WORK(&kobj->work, destroy_vf_group_work);
	kobj->group = group;
	queue_work(system_wq, &kobj->work);
#endif
}


#ifdef CONFIG_MLX5_ESWITCH
static void mlx5_destroy_vfs_sysfs_meters(struct mlx5_core_dev *dev, int num_vfs)
{
	struct mlx5_core_sriov *sriov = &dev->priv.sriov;
	struct mlx5_sriov_vf_meters *meters;
	struct mlx5_sriov_vf *vf;
	int i, j;

	for (i = 0; i < num_vfs; i++) {
		vf = &sriov->vfs[i];

		meters = vf->meters;
		if (!meters)
			break;

		for (j = 0; j < 4; j++)
			kobject_put(&meters->meters[j].kobj);

		kobject_put(meters->rx_kobj);
		kobject_put(meters->tx_kobj);
		kobject_put(meters->kobj);

		kfree(meters);
	}
}

static int mlx5_init_vfs_sysfs_init_meter(struct mlx5_sriov_vf *vf,
					  struct mlx5_sriov_vf_meters *meters,
					  struct mlx5_sriov_vf *meter,
					  int rx_tx, int xps)
{
	struct kobject *parent;
	int err;

	if (rx_tx == MLX5_RATE_LIMIT_TX)
		parent = meters->tx_kobj;
	else
		parent = meters->rx_kobj;

	err = kobject_init_and_add(&meter->kobj, &vf_meters_type_eth, parent,
				   (xps == MLX5_RATE_LIMIT_PPS) ? "pps" : "bps");
	if (err)
		return err;

	meter->dev = vf->dev;
	meter->vf = vf->vf;
	meter->meter_type.rx_tx = rx_tx;
	meter->meter_type.xps = xps;

	return 0;
}

static int mlx5_create_vfs_sysfs_meters(struct mlx5_core_dev *dev, int num_vfs)
{
	struct mlx5_core_sriov *sriov = &dev->priv.sriov;
	struct mlx5_sriov_vf_meters *meters;
	struct mlx5_sriov_vf *vf;
	int err, i;

	if (!(MLX5_CAP_GEN_64(dev, general_obj_types) &
	      MLX5_HCA_CAP_GENERAL_OBJECT_TYPES_FLOW_METER_ASO))
		return 0;

	if (!(MLX5_CAP_QOS(dev, flow_meter_reg_id) & 0x20)) {
		mlx5_core_warn(dev, "Metadata reg C5 can't be used for flow meter.\n");
		return 0;
	}

	if (!MLX5_CAP_ESW_EGRESS_ACL(dev, execute_aso))
		return 0;

	for (i = 0; i < num_vfs; i++) {
		vf = &sriov->vfs[i];

		meters = kzalloc(sizeof(*meters), GFP_KERNEL);
		if (!meters) {
			err = -ENOMEM;
			goto err_vf_meters;
		}

		meters->kobj = kobject_create_and_add("meters", &vf->kobj);
		if (!meters->kobj) {
			err = -EINVAL;
			goto err_vf_meters;
		}

		meters->rx_kobj = kobject_create_and_add("rx", meters->kobj);
		if (!meters->rx_kobj) {
			err = -EINVAL;
			goto err_vf_meters;
		}

		meters->tx_kobj = kobject_create_and_add("tx", meters->kobj);
		if (!meters->tx_kobj) {
			err = -EINVAL;
			goto err_vf_meters;
		}

		err = mlx5_init_vfs_sysfs_init_meter(vf, meters,
						     &meters->meters[0],
						     MLX5_RATE_LIMIT_RX,
						     MLX5_RATE_LIMIT_BPS);
		if (err)
			goto err_vf_meters;

		err = mlx5_init_vfs_sysfs_init_meter(vf, meters,
						     &meters->meters[1],
						     MLX5_RATE_LIMIT_RX,
						     MLX5_RATE_LIMIT_PPS);
		if (err)
			goto err_put_meter_0;

		err = mlx5_init_vfs_sysfs_init_meter(vf, meters,
						     &meters->meters[2],
						     MLX5_RATE_LIMIT_TX,
						     MLX5_RATE_LIMIT_BPS);
		if (err)
			goto err_put_meter_1;

		err = mlx5_init_vfs_sysfs_init_meter(vf, meters,
						     &meters->meters[3],
						     MLX5_RATE_LIMIT_TX,
						     MLX5_RATE_LIMIT_PPS);
		if (err)
			goto err_put_meter_2;

		vf->meters = meters;
	}

	return 0;

err_put_meter_2:
	kobject_put(&meters->meters[2].kobj);
err_put_meter_1:
	kobject_put(&meters->meters[1].kobj);
err_put_meter_0:
	kobject_put(&meters->meters[0].kobj);
err_vf_meters:
	kobject_put(meters->rx_kobj);
	kobject_put(meters->tx_kobj);
	kobject_put(meters->kobj);

	kfree(meters);

	mlx5_destroy_vfs_sysfs_meters(dev, num_vfs);

	return err;
}
#endif

int mlx5_create_vfs_sysfs(struct mlx5_core_dev *dev, int num_vfs)
{
	struct mlx5_core_sriov *sriov = &dev->priv.sriov;
	struct mlx5_sriov_vf *tmp;
	static struct kobj_type *sysfs;
	int err;
	int vf;

#ifdef CONFIG_MLX5_ESWITCH
	if (MLX5_CAP_GEN(dev, port_type) == MLX5_CAP_PORT_TYPE_ETH)
		sysfs = &vf_type_eth;
	else
#endif
		sysfs = &vf_type_ib;

	sriov->vfs = kcalloc(num_vfs, sizeof(*sriov->vfs), GFP_KERNEL);
	if (!sriov->vfs)
		return -ENOMEM;

	for (vf = 0; vf < num_vfs; vf++) {
		tmp = &sriov->vfs[vf];
		tmp->dev = dev;
		tmp->vf = vf;
		err = kobject_init_and_add(&tmp->kobj, sysfs, sriov->config,
					   "%d", vf);
		if (err)
			goto err_vf;

		kobject_uevent(&tmp->kobj, KOBJ_ADD);
	}

#ifdef CONFIG_MLX5_ESWITCH
	err = mlx5_create_vfs_sysfs_meters(dev, num_vfs);
	if (err) {
		--vf;
		goto err_vf;
	}
#endif

#ifdef CONFIG_MLX5_ESWITCH
	if (MLX5_CAP_GEN(dev, port_type) != MLX5_CAP_PORT_TYPE_ETH)
		return 0;

	for (vf = 0; vf < num_vfs; vf++) {
		tmp = &sriov->vfs[vf];
		err = kobject_init_and_add(&tmp->page_kobj, &vf_paging, &tmp->kobj,
					   "paging_control");
		if (err)
			goto err_vf;

		kobject_uevent(&tmp->page_kobj, KOBJ_ADD);
	}
#endif

	return 0;

err_vf:
	for (; vf >= 0; vf--) {
		tmp = &sriov->vfs[vf];
		kobject_put(&tmp->kobj);
	}

	kfree(sriov->vfs);
	sriov->vfs = NULL;
	return err;
}

void mlx5_destroy_vfs_sysfs(struct mlx5_core_dev *dev, int num_vfs)
{
	struct mlx5_core_sriov *sriov = &dev->priv.sriov;
	struct mlx5_sriov_vf *tmp;
	int vf;

	if (!num_vfs || !sriov || !sriov->vfs)
		return;

#ifdef CONFIG_MLX5_ESWITCH
	if (MLX5_CAP_GEN(dev, port_type) == MLX5_CAP_PORT_TYPE_ETH) {
		for (vf = 0; vf < num_vfs; vf++) {
			tmp = &sriov->vfs[vf];
			kobject_put(&tmp->page_kobj);
		}
	}
#endif

#ifdef CONFIG_MLX5_ESWITCH
	mlx5_destroy_vfs_sysfs_meters(dev, num_vfs);
#endif
	for (vf = 0; vf < num_vfs; vf++) {
		tmp = &sriov->vfs[vf];
		kobject_put(&tmp->kobj);
	}

	kfree(sriov->vfs);
	sriov->vfs = NULL;
}
