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

	return count;
}

static int show_hca_node_guid(struct mlx5_core_dev *dev, u16 vf,
			      __be64 *node_guid)
{
	struct mlx5_hca_vport_context *rep;
	int err;

	rep = kzalloc(sizeof(*rep), GFP_KERNEL);
	if (!rep)
		return -ENOMEM;

	err = mlx5_core_query_hca_vport_context(dev, 1, 1,  vf, rep);
	if (err)
		goto free;

	*node_guid = cpu_to_be64(rep->node_guid);

	return 0;

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
	struct mlx5_hca_vport_context *in;
	int err;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->field_select = MLX5_HCA_VPORT_SEL_NODE_GUID;
	in->node_guid = node_guid;
	err = mlx5_core_modify_hca_vport_context(dev, 1, 1, vf + 1, in);
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
	case MLX5_POLICY_DOWN:		return "Down";
	case MLX5_POLICY_UP:		return "Up";
	case MLX5_POLICY_FOLLOW:	return "Follow";
	default:			return "Invalid policy";
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
	if (!strcmp(buf, "Down\n")) {
		*policy = MLX5_POLICY_DOWN;
		return 0;
	}

	if (!strcmp(buf, "Up\n")) {
		*policy = MLX5_POLICY_UP;
		return 0;
	}

	if (!strcmp(buf, "Follow\n")) {
		*policy = MLX5_POLICY_FOLLOW;
		return 0;
	}
	return -EINVAL;
}

static ssize_t policy_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			    const char *buf, size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
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

	return count;
}

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

	if (!strncmp(buf, "Random", 6))
		random_ether_addr(mac);
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
		       "usage: write <Vlan:Qos> to set VF Vlan and Qos\n");
}

static ssize_t vlan_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			  const char *buf, size_t count)
{
	struct mlx5_core_dev *dev = g->dev;
	u16 vlan_id;
	u8 qos;
	int err;

	err = sscanf(buf, "%hu:%hhu", &vlan_id, &qos);
	if (err != 2)
		return -EINVAL;

	err = mlx5_eswitch_set_vport_vlan(dev->priv.eswitch, g->vf + 1, vlan_id, qos);
	return err ? err : count;
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

	if (!strncmp(buf, "ON", 2))
		settings = true;
	else if (!strncmp(buf, "OFF", 3))
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

	if (!strncmp(buf, "ON", 2))
		settings = true;
	else if (!strncmp(buf, "OFF", 3))
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
	u32 max_tx_rate;
	u32 min_tx_rate;
	int err;

	mutex_lock(&esw->state_lock);
	min_tx_rate = esw->vports[g->vf + 1].info.min_rate;
	mutex_unlock(&esw->state_lock);

	err = sscanf(buf, "%u", &max_tx_rate);
	if (err != 1)
		return -EINVAL;

	err = mlx5_eswitch_set_vport_rate(dev->priv.eswitch, g->vf + 1,
					  max_tx_rate, min_tx_rate);
	return err ? err : count;
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
	u32 min_tx_rate;
	u32 max_tx_rate;
	int err;

	mutex_lock(&esw->state_lock);
	max_tx_rate = esw->vports[g->vf + 1].info.max_rate;
	mutex_unlock(&esw->state_lock);

	err = sscanf(buf, "%u", &min_tx_rate);
	if (err != 1)
		return -EINVAL;

	err = mlx5_eswitch_set_vport_rate(dev->priv.eswitch, g->vf + 1,
					  max_tx_rate, min_tx_rate);
	return err ? err : count;
}
#define _sprintf(p, buf, format, arg...)				\
	((PAGE_SIZE - (int)(p - buf)) <= 0 ? 0 :			\
	scnprintf(p, PAGE_SIZE - (int)(p - buf), format, ## arg))

static ssize_t config_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			   char *buf)
{
	struct mlx5_core_dev *dev = g->dev;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5_vport_info *ivi;
	int vport = g->vf + 1;
	char *p = buf;

	if (!esw && MLX5_CAP_GEN(esw->dev, vport_group_manager) && mlx5_core_is_pf(esw->dev))
		return -EPERM;
	if (!(vport >= 0 && vport < esw->total_vports))
		return -EINVAL;

	mutex_lock(&esw->state_lock);
	ivi = &esw->vports[vport].info;
	p += _sprintf(p, buf, "VF         : %d\n", g->vf);
	p += _sprintf(p, buf, "MAC        : %pM\n", ivi->mac);
	p += _sprintf(p, buf, "VLAN       : %d\n", ivi->vlan);
	p += _sprintf(p, buf, "QoS        : %d\n", ivi->qos);
	p += _sprintf(p, buf, "SpoofCheck : %s\n", ivi->spoofchk ? "ON" : "OFF");
	p += _sprintf(p, buf, "Trust      : %s\n", ivi->trusted ? "ON" : "OFF");
	p += _sprintf(p, buf, "LinkState  : %s\n", policy_str(ivi->link_state));
	p += _sprintf(p, buf, "MinTxRate  : %d\n", ivi->min_rate);
	p += _sprintf(p, buf, "MaxTxRate  : %d\n", ivi->max_rate);
	mutex_unlock(&esw->state_lock);

	return (ssize_t)(p - buf);
}

static ssize_t config_store(struct mlx5_sriov_vf *g,
			    struct vf_attributes *oa,
			    const char *buf, size_t count)
{
	return -ENOTSUPP;
}

static ssize_t stats_show(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			  char *buf)
{
	struct mlx5_core_dev *dev = g->dev;
	struct ifla_vf_stats ifi;
	int err;
	char *p = buf;

	err = mlx5_eswitch_get_vport_stats(dev->priv.eswitch, g->vf + 1, &ifi);
	if (err)
		return -EINVAL;

	p += _sprintf(p, buf, "tx_packets    : %llu\n", ifi.tx_packets);
	p += _sprintf(p, buf, "tx_bytes      : %llu\n", ifi.tx_bytes);
	p += _sprintf(p, buf, "rx_packets    : %llu\n", ifi.rx_packets);
	p += _sprintf(p, buf, "rx_bytes      : %llu\n", ifi.rx_bytes);
	p += _sprintf(p, buf, "rx_broadcast  : %llu\n", ifi.broadcast);
	p += _sprintf(p, buf, "rx_multicast  : %llu\n", ifi.multicast);
	return (ssize_t)(p - buf);
}

static ssize_t stats_store(struct mlx5_sriov_vf *g, struct vf_attributes *oa,
			   const char *buf, size_t count)
{
	return -ENOTSUPP;
}

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

#define VF_ATTR(_name) struct vf_attributes vf_attr_##_name = \
	__ATTR(_name, 0644, _name##_show, _name##_store)

VF_ATTR(node);
VF_ATTR(port);
VF_ATTR(policy);

VF_ATTR(mac);
VF_ATTR(vlan);
VF_ATTR(link_state);
VF_ATTR(spoofcheck);
VF_ATTR(trust);
VF_ATTR(max_tx_rate);
VF_ATTR(min_tx_rate);
VF_ATTR(config);
VF_ATTR(stats);

static struct attribute *vf_ib_attrs[] = {
	&vf_attr_node.attr,
	&vf_attr_port.attr,
	&vf_attr_policy.attr,
	NULL
};

static struct attribute *vf_eth_attrs[] = {
	&vf_attr_node.attr,
	&vf_attr_mac.attr,
	&vf_attr_vlan.attr,
	&vf_attr_link_state.attr,
	&vf_attr_spoofcheck.attr,
	&vf_attr_trust.attr,
	&vf_attr_max_tx_rate.attr,
	&vf_attr_min_tx_rate.attr,
	&vf_attr_config.attr,
	&vf_attr_stats.attr,
	NULL
};

static struct kobj_type vf_type_ib = {
	.sysfs_ops     = &vf_sysfs_ops,
	.default_attrs = vf_ib_attrs
};

static struct kobj_type vf_type_eth = {
	.sysfs_ops     = &vf_sysfs_ops,
	.default_attrs = vf_eth_attrs
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

	for (i = 0; i < ARRAY_SIZE(mlx5_class_attributes); i++) {
		err = device_create_file(device, mlx5_class_attributes[i]);
		if (err)
			goto err_attr;
	}

	return 0;

err_attr:
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

	kobject_put(sriov->config);
	sriov->config = NULL;
}

int mlx5_create_vfs_sysfs(struct mlx5_core_dev *dev, int num_vfs)
{
	struct mlx5_core_sriov *sriov = &dev->priv.sriov;
	struct mlx5_sriov_vf *tmp;
	static struct kobj_type *sysfs;
	int err;
	int vf;

	if (MLX5_CAP_GEN(dev, port_type) == MLX5_CAP_PORT_TYPE_ETH)
		sysfs = &vf_type_eth;
	else
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

void mlx5_destroy_vfs_sysfs(struct mlx5_core_dev *dev)
{
	struct mlx5_core_sriov *sriov = &dev->priv.sriov;
	struct mlx5_sriov_vf *tmp;
	int vf;

	for (vf = 0; vf < sriov->num_vfs; vf++) {
		tmp = &sriov->vfs[vf];
		kobject_put(&tmp->kobj);
	}

	kfree(sriov->vfs);
	sriov->vfs = NULL;
}



