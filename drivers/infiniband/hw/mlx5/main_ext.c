/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
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

#include <linux/inet.h>
#include <linux/sort.h>
#include <rdma/ib_cache.h>
#include "mlx5_ib.h"
#include  "qp.h"

#include "../../core/restrack.h"

/* mlx5_set_ttl feature infra */
struct ttl_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx5_ttl_data *, struct ttl_attribute *, char *buf);
	ssize_t (*store)(struct mlx5_ttl_data *, struct ttl_attribute *,
			 const char *buf, size_t count);
};

#define TTL_ATTR(_name, _mode, _show, _store) \
struct ttl_attribute ttl_attr_##_name = __ATTR(_name, _mode, _show, _store)

static ssize_t ttl_show(struct mlx5_ttl_data *ttld, struct ttl_attribute *unused, char *buf)
{
	return sprintf(buf, "%d\n", ttld->val);
}

static ssize_t ttl_store(struct mlx5_ttl_data *ttld, struct ttl_attribute *unused,
				   const char *buf, size_t count)
{
	unsigned long var;

	if (kstrtol(buf, 0, &var) || var > 0xff)
		return -EINVAL;

	ttld->val = var;
	return count;
}

static TTL_ATTR(ttl, 0644, ttl_show, ttl_store);

static struct attribute *ttl_attrs[] = {
	&ttl_attr_ttl.attr,
	NULL
};

static ssize_t ttl_attr_show(struct kobject *kobj,
			    struct attribute *attr, char *buf)
{
	struct ttl_attribute *ttl_attr = container_of(attr, struct ttl_attribute, attr);
	struct mlx5_ttl_data *d = container_of(kobj, struct mlx5_ttl_data, kobj);

	return ttl_attr->show(d, ttl_attr, buf);
}

static ssize_t ttl_attr_store(struct kobject *kobj,
			     struct attribute *attr, const char *buf, size_t count)
{
	struct ttl_attribute *ttl_attr = container_of(attr, struct ttl_attribute, attr);
	struct mlx5_ttl_data *d = container_of(kobj, struct mlx5_ttl_data, kobj);

	return ttl_attr->store(d, ttl_attr, buf, count);
}

static const struct sysfs_ops ttl_sysfs_ops = {
	.show = ttl_attr_show,
	.store = ttl_attr_store
};

ATTRIBUTE_GROUPS(ttl);

static struct kobj_type ttl_type = {
	.sysfs_ops     = &ttl_sysfs_ops,
	.default_groups = ttl_groups
};

int init_ttl_sysfs(struct mlx5_ib_dev *dev)
{
	struct device *device = &dev->ib_dev.dev;
	int num_ports;
	int port;
	int err;

	dev->ttl_kobj = kobject_create_and_add("ttl", &device->kobj);
	if (!dev->ttl_kobj)
		return -ENOMEM;
	num_ports = max(MLX5_CAP_GEN(dev->mdev, num_ports),
			MLX5_CAP_GEN(dev->mdev, num_vhca_ports));
	for (port = 1; port <= num_ports; port++) {
		struct mlx5_ttl_data *ttld = &dev->ttld[port - 1];

		err = kobject_init_and_add(&ttld->kobj, &ttl_type, dev->ttl_kobj, "%d", port);
		if (err)
			goto err;
		ttld->val = 0;
	}
	return 0;
err:
	cleanup_ttl_sysfs(dev);
	return err;
}

void cleanup_ttl_sysfs(struct mlx5_ib_dev *dev)
{
	if (dev->ttl_kobj) {
		int num_ports;
		int port;

		kobject_put(dev->ttl_kobj);
		dev->ttl_kobj = NULL;
		num_ports = max(MLX5_CAP_GEN(dev->mdev, num_ports),
				MLX5_CAP_GEN(dev->mdev, num_vhca_ports));
		for (port = 1; port <= num_ports; port++) {
			struct mlx5_ttl_data *ttld = &dev->ttld[port - 1];

			if (ttld->kobj.state_initialized)
				kobject_put(&ttld->kobj);
		}
	}
}

/* mlx5_force_tc feature*/

static int check_string_match(const char *str, const char *str2)
{
	int str2_len;
	int str_len;

	if (!str || !str2)
		return -EINVAL;

	str_len = strlen(str);
	str2_len = strlen(str2);

	if (str_len <= str2_len)
		return -EINVAL;

	return memcmp(str, str2, str2_len);
}

static void tclass_set_mask_32(u32 *mask, int bits)
{
	*mask = 0;
	if (!bits)
		bits = 32;
	while (bits) {
		*mask = (*mask << 1) | 1;
		--bits;
	}
}

static int tclass_parse_src_ip(const char *str, void *store, void *store_mask)
{
	const char *end = NULL;

	return !in4_pton(str, -1, (u8 *)store, -1, &end);
}

static int tclass_parse_dst_ip(const char *str, void *store, void *store_mask)
{
	const char *end = NULL;
	int mask = 0;
	int ret;

	ret = !in4_pton(str, -1, (u8 *)store, -1, &end);

	if (ret)
		return -EINVAL;

	if (strlen(end)) {
		if (*end != '/')
			return -EINVAL;
		ret = kstrtoint(end + 1, 0, &mask);
		if (ret || mask < 0 || mask > 32)
			return -EINVAL;
	}

	tclass_set_mask_32(store_mask, mask);

	return ret;
}

static int tclass_parse_ip6(const char *str, void *store, void *store_mask)
{
	const char *end = NULL;

	return !in6_pton(str, -1, (u8 *)store, -1, &end);
}

static int tclass_parse_tclass(const char *str, void *ptr, void *store_mask)
{
	int *tclass = ptr;
	int ret;

	ret = kstrtoint(str, 0, tclass);

	if (ret || *tclass > 0xff)
		return -EINVAL;

	return 0;
}

static int tclass_compare_src_ips(struct tclass_match *match,
				  struct tclass_match *match2,
				  bool with_mask)
{
	return (*(u32 *)match->s_addr != *(u32 *)match2->s_addr);
}

static int tclass_compare_dst_ips(struct tclass_match *match,
				  struct tclass_match *match2,
				  bool with_mask)
{
	u32 mask = -1;

	if (with_mask)
		mask = *(u32 *)match->d_addr_m;

	return ((*(u32 *)match->d_addr & mask) !=
		((*(u32 *)match2->d_addr) & mask));
}

static int tclass_compare_ip6s(void *ip1, void *ip2, int size)
{
	return memcmp(ip1, ip2, size);
}

static int tclass_compare_src_ip6s(struct tclass_match *match,
				   struct tclass_match *match2,
				   bool with_mask)
{
	return tclass_compare_ip6s(match->s_addr, match2->s_addr,
				   sizeof(match->s_addr));
}

static int tclass_compare_dst_ip6s(struct tclass_match *match,
				   struct tclass_match *match2,
				   bool with_mask)
{
	return tclass_compare_ip6s(match->d_addr, match2->d_addr,
				   sizeof(match->d_addr));
}

static size_t tclass_print_src_ip(struct tclass_match *match,
				  char *buf, size_t size)
{
	return snprintf(buf, size, "src_ip=%pI4,", match->s_addr);
}

static size_t tclass_print_dst_ip(struct tclass_match *match,
				  char *buf, size_t size)
{
	return snprintf(buf, size, "dst_ip=%pI4/%d,",
			match->d_addr,  hweight32(*(int *)match->d_addr_m));
}

static size_t tclass_print_src_ip6(struct tclass_match *match,
				   char *buf, size_t size)
{
	return snprintf(buf, size, "src_ip6=%pI6,", match->s_addr);
}

static size_t tclass_print_dst_ip6(struct tclass_match *match,
				   char *buf, size_t size)
{
	return snprintf(buf, size, "dst_ip6=%pI6,", match->d_addr);
}

static size_t tclass_print_tclass(struct tclass_match *match,
				  char *buf, size_t size)
{
	return snprintf(buf, size, "tclass=%d\n", match->tclass);
}

static const struct tclass_parse_node parse_tree[] = {
	TCLASS_CREATE_PARSE_NODE(TCLASS_MATCH_SRC_ADDR_IP, tclass_parse_src_ip,
				 tclass_compare_src_ips,
				 tclass_print_src_ip, "src_ip=",
				 TCLASS_MATCH_MASK_SRC_ADDR_IP,
				 s_addr, s_addr),
	TCLASS_CREATE_PARSE_NODE(TCLASS_MATCH_DST_ADDR_IP, tclass_parse_dst_ip,
				 tclass_compare_dst_ips,
				 tclass_print_dst_ip, "dst_ip=",
				 TCLASS_MATCH_MASK_DST_ADDR_IP,
				 d_addr, d_addr_m),
	TCLASS_CREATE_PARSE_NODE(TCLASS_MATCH_SRC_ADDR_IP6, tclass_parse_ip6,
				 tclass_compare_src_ip6s,
				 tclass_print_src_ip6, "src_ip6=",
				 TCLASS_MATCH_MASK_SRC_ADDR_IP6,
				 s_addr, s_addr),
	TCLASS_CREATE_PARSE_NODE(TCLASS_MATCH_DST_ADDR_IP6, tclass_parse_ip6,
				 tclass_compare_dst_ip6s,
				 tclass_print_dst_ip6, "dst_ip6=",
				 TCLASS_MATCH_MASK_DST_ADDR_IP6,
				 d_addr, d_addr_m),
	TCLASS_CREATE_PARSE_NODE(TCLASS_MATCH_TCLASS, tclass_parse_tclass,
				 NULL,
				 tclass_print_tclass, "tclass=",
				 TCLASS_MATCH_MASK_TCLASS, tclass, tclass),
	TCLASS_CREATE_PARSE_NODE(TCLASS_MATCH_TCLASS_NO_PREFIX,
				 tclass_parse_tclass,
				 NULL,
				 NULL, "",
				 TCLASS_MATCH_MASK_TCLASS, tclass, tclass),
};

static int tclass_verify_match(struct tclass_match *match)
{
	if (!(match->mask & TCLASS_MATCH_MASK_TCLASS))
		return -EINVAL;

	if ((match->mask & (TCLASS_MATCH_MASK_SRC_ADDR_IP |
			    TCLASS_MATCH_MASK_DST_ADDR_IP)) &&
	    (match->mask & (TCLASS_MATCH_MASK_SRC_ADDR_IP6 |
			    TCLASS_MATCH_MASK_DST_ADDR_IP6)))
		return -EINVAL;

	return 0;
}

static int tclass_parse_input(char *str, struct tclass_match *match)
{
	char *p;
	int ret;
	int i;

	while ((p = strsep(&str, ",")) != NULL) {
		if (!*p)
			continue;

		p = strim(p); /* Removing whitespace */
		for (i = 0; i < ARRAY_SIZE(parse_tree); i++) {
			const struct tclass_parse_node *node;

			node = &parse_tree[i];
			if (!check_string_match(p, node->pattern)) {
				ret = parse_tree[i].parse(p +
							  strlen(node->pattern),
							  (char *)match +
							  node->v_offset,
							  (char *)match +
							  node->m_offset);
				if (ret)
					return -EINVAL;
				match->mask |= node->mask;
				break;
			}
		}
		if (i == ARRAY_SIZE(parse_tree))
			return -EINVAL;
	}

	return tclass_verify_match(match);
}

static struct tclass_match *tclass_find_empty(struct mlx5_tc_data *tcd)
{
	int i;

	for (i = 0; i < TCLASS_MAX_RULES; i++)
		if (!tcd->rule[i].mask)
			return &tcd->rule[i];
	return NULL;
}

static struct tclass_match *tclass_find_match(struct mlx5_tc_data *tcd,
					      struct tclass_match *match,
					      u32 mask,
					      bool with_mask)
{
	int ret;
	int i;
	int j;

	mask |= TCLASS_MATCH_MASK_TCLASS;

	for (i = 0; i < TCLASS_MAX_RULES; i++) {
		if (tcd->rule[i].mask == mask) {
			ret = -1;
			for (j = 0; j < ARRAY_SIZE(parse_tree); j++) {
				const struct tclass_parse_node *node;

				node = &parse_tree[j];
				if (mask & node->mask && node->compare) {
					ret = node->compare(&tcd->rule[i],
							    match,
							    with_mask);
					if (ret)
						break;
				}
			}
			if (!ret)
				return &tcd->rule[i];
		}
	}

	return NULL;
}

void tclass_get_tclass_locked(struct mlx5_ib_dev *dev,
			      struct mlx5_tc_data *tcd,
			      const struct rdma_ah_attr *ah,
			      u8 port,
			      u8 *tclass,
			      bool *global_tc)
{
	struct tclass_match *res_match = NULL;
	struct tclass_match match = {};
	enum ib_gid_type gid_type;
	union ib_gid gid;
	int mask;
	int err;

	if (tcd->val >= 0) {
		*global_tc = true;
		*tclass = tcd->val;
	} else if (ah && ah->type == RDMA_AH_ATTR_TYPE_ROCE) {
		*global_tc = false;
		err = rdma_query_gid(&dev->ib_dev, port, ah->grh.sgid_index,
				   &gid);
		if (err)
			goto out;

		gid_type = ah->grh.sgid_attr->gid_type;
		if (gid_type != IB_GID_TYPE_ROCE_UDP_ENCAP)
			goto out;

		if (ipv6_addr_v4mapped((struct in6_addr *)&gid)) {
			match.mask = TCLASS_MATCH_MASK_SRC_ADDR_IP |
				TCLASS_MATCH_MASK_DST_ADDR_IP;
			memcpy(match.s_addr, gid.raw + 12, 4);
			memcpy(match.d_addr, ah->grh.dgid.raw + 12, 4);
		} else {
			match.mask = TCLASS_MATCH_MASK_SRC_ADDR_IP6 |
				TCLASS_MATCH_MASK_DST_ADDR_IP6;
			memcpy(match.s_addr, gid.raw, sizeof(match.s_addr));
			memcpy(match.d_addr, ah->grh.dgid.raw,
			       sizeof(match.d_addr));
		}

		mask = match.mask;
		res_match = tclass_find_match(tcd, &match, mask, true);
		if (!res_match)
			res_match = tclass_find_match(tcd, &match, mask &
						      ~(TCLASS_MATCH_MASK_SRC_ADDR_IP | TCLASS_MATCH_MASK_SRC_ADDR_IP6),
						      true);
		else
			goto out;
		mask = match.mask;
		if (!res_match)
			res_match = tclass_find_match(tcd, &match, mask &
						      ~(TCLASS_MATCH_MASK_DST_ADDR_IP | TCLASS_MATCH_MASK_DST_ADDR_IP6),
						      true);
	}
out:
	if (res_match)
		*tclass = res_match->tclass;
}

struct tc_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx5_tc_data *, struct tc_attribute *, char *buf);
	ssize_t (*store)(struct mlx5_tc_data *, struct tc_attribute *,
			 const char *buf, size_t count);
};

#define TC_ATTR(_name, _mode, _show, _store) \
	struct tc_attribute tc_attr_##_name = __ATTR(_name, _mode, _show, _store)


static ssize_t traffic_class_show(struct mlx5_tc_data *tcd, struct tc_attribute *unused, char *buf)
{
	size_t count = 0;
	int j;
	int i;

	mutex_lock(&tcd->lock);
	if (tcd->val >= 0)
		count = snprintf(buf, PAGE_SIZE, "Global tclass=%d\n",
				 tcd->val);

	for (i = 0; i < TCLASS_MAX_RULES &&
	     count < (PAGE_SIZE - TCLASS_MAX_CMD); i++) {
		if (!tcd->rule[i].mask)
			continue;
		for (j = 0; j < ARRAY_SIZE(parse_tree); j++) {
			if (tcd->rule[i].mask & parse_tree[j].mask &&
			    parse_tree[j].print)
				count += parse_tree[j].print(&tcd->rule[i],
							     buf + count,
							     PAGE_SIZE - count);
		}
	}
	mutex_unlock(&tcd->lock);

	return count;
}

static int tclass_compare_match(const void *ptr1, const void *ptr2)
{
	const struct tclass_match *m1 = ptr1;
	const struct tclass_match *m2 = ptr2;

	if (m1->mask & TCLASS_MATCH_MASK_DST_ADDR_IP &&
	    m2->mask & TCLASS_MATCH_MASK_DST_ADDR_IP)
		return hweight32(*(u32 *)m2->d_addr_m) -
			hweight32(*(u32 *)m1->d_addr_m);

	if (m1->mask & TCLASS_MATCH_MASK_DST_ADDR_IP)
		return -1;

	if (m2->mask & TCLASS_MATCH_MASK_DST_ADDR_IP)
		return 1;

	return 0;

}
static int tclass_update_qp(struct mlx5_ib_dev *ibdev, struct mlx5_ib_qp *mqp,
			    u8 tclass, void *qpc)
{
	enum mlx5_qp_optpar optpar = MLX5_QP_OPTPAR_PRIMARY_ADDR_PATH_DSCP;
	struct mlx5_ib_qp_base *base = &mqp->trans_qp.base;
	u16 op = MLX5_CMD_OP_RTS2RTS_QP;
	int err;

	MLX5_SET(qpc, qpc, primary_address_path.dscp, tclass >> 2);
	err = mlx5_core_qp_modify(ibdev, op, optpar, qpc, &base->mqp, 0);

	return err;
}

static void tclass_update_qps(struct mlx5_tc_data *tcd)
{
	struct mlx5_ib_dev *ibdev = tcd->ibdev;
	struct rdma_restrack_entry *res;
	struct rdma_restrack_root *rt;
	struct mlx5_ib_qp *mqp;
	unsigned long id = 0;
	struct ib_qp *ibqp;
	bool global_tc;
	u8 tclass;
	int ret;
	void *qpc;

	if (!tcd->ibdev || !MLX5_CAP_GEN(ibdev->mdev, rts2rts_qp_dscp))
		return;

	qpc = kzalloc(MLX5_ST_SZ_BYTES(qpc), GFP_KERNEL);
	if (!qpc)
		return;

	rt = &ibdev->ib_dev.res[RDMA_RESTRACK_QP];
	xa_lock(&rt->xa);
	xa_for_each(&rt->xa, id, res) {
		if (!rdma_restrack_get(res))
			continue;

		xa_unlock(&rt->xa);

		ibqp = container_of(res, struct ib_qp, res);
		mqp = to_mqp(ibqp);

		if (ibqp->qp_type == IB_QPT_GSI ||
				mqp->type == MLX5_IB_QPT_DCT)
			goto cont;

		mutex_lock(&mqp->mutex);

		if (mqp->state == IB_QPS_RTS &&
		    rdma_ah_get_ah_flags(&mqp->ah) & IB_AH_GRH) {

			tclass = mqp->tclass;
			tclass_get_tclass_locked(ibdev, tcd, &mqp->ah,
						 mqp->ah.port_num,
						 &tclass, &global_tc);

			if (tclass != mqp->tclass) {
				ret = tclass_update_qp(ibdev, mqp, tclass,
						       qpc);
				if (!ret)
					mqp->tclass = tclass;
			}
		}
		mutex_unlock(&mqp->mutex);
cont:
		rdma_restrack_put(res);
		xa_lock(&rt->xa);
	}
	xa_unlock(&rt->xa);
}
static ssize_t traffic_class_store(struct mlx5_tc_data *tcd, struct tc_attribute *unused,
				   const char *buf, size_t count)
{
	struct tclass_match *dst_match = NULL;
	char cmd[TCLASS_MAX_CMD + 1] = {};
	struct tclass_match match = {};
	int ret;

	if (count > TCLASS_MAX_CMD)
		return -EINVAL;
	memcpy(cmd, buf, count);

	ret = tclass_parse_input(cmd, &match);

	if (ret)
		return -EINVAL;

	mutex_lock(&tcd->lock);

	if (match.mask == TCLASS_MATCH_MASK_TCLASS) {
		tcd->val = match.tclass;
	} else {
		dst_match = tclass_find_match(tcd, &match, match.mask, false);
		if (!dst_match) {
			dst_match = tclass_find_empty(tcd);
			if (!dst_match) {
				mutex_unlock(&tcd->lock);
				return -ENOMEM;
			}
		}
		if (match.tclass < 0)
			memset(dst_match, 0, sizeof(*dst_match));
		else
			memcpy(dst_match, &match, sizeof(*dst_match));
	}

	/* Sort the list based on subnet mask */
	sort(tcd->rule, TCLASS_MAX_RULES, sizeof(tcd->rule[0]),
	     tclass_compare_match, NULL);
	tclass_update_qps(tcd);
	mutex_unlock(&tcd->lock);

	return count;
}

static TC_ATTR(traffic_class, 0644, traffic_class_show, traffic_class_store);

static struct attribute *tc_attrs[] = {
	&tc_attr_traffic_class.attr,
	NULL
};

static ssize_t tc_attr_show(struct kobject *kobj,
			    struct attribute *attr, char *buf)
{
	struct tc_attribute *tc_attr = container_of(attr, struct tc_attribute, attr);
	struct mlx5_tc_data *d = container_of(kobj, struct mlx5_tc_data, kobj);

	if (!tc_attr->show)
		return -EIO;

	return tc_attr->show(d, tc_attr, buf);
}

static ssize_t tc_attr_store(struct kobject *kobj,
			     struct attribute *attr, const char *buf, size_t count)
{
	struct tc_attribute *tc_attr = container_of(attr, struct tc_attribute, attr);
	struct mlx5_tc_data *d = container_of(kobj, struct mlx5_tc_data, kobj);

	if (!tc_attr->store)
		return -EIO;

	return tc_attr->store(d, tc_attr, buf, count);
}

static const struct sysfs_ops tc_sysfs_ops = {
	.show = tc_attr_show,
	.store = tc_attr_store
};

ATTRIBUTE_GROUPS(tc);

static struct kobj_type tc_type = {
	.sysfs_ops     = &tc_sysfs_ops,
	.default_groups = tc_groups
};

int init_tc_sysfs(struct mlx5_ib_dev *dev)
{
	struct device *device = &dev->ib_dev.dev;
	int num_ports;
	int port;
	int err;

	dev->tc_kobj = kobject_create_and_add("tc", &device->kobj);
	if (!dev->tc_kobj)
		return -ENOMEM;
	num_ports = max(MLX5_CAP_GEN(dev->mdev, num_ports),
			MLX5_CAP_GEN(dev->mdev, num_vhca_ports));
	for (port = 1; port <= num_ports; port++) {
		struct mlx5_tc_data *tcd = &dev->tcd[port - 1];

		err = kobject_init_and_add(&tcd->kobj, &tc_type, dev->tc_kobj, "%d", port);
		if (err)
			goto err;
		tcd->val = -1;
		tcd->ibdev = dev;
		tcd->initialized = true;
		mutex_init(&tcd->lock);
	}
	return 0;
err:
	cleanup_tc_sysfs(dev);
	return err;
}

void cleanup_tc_sysfs(struct mlx5_ib_dev *dev)
{
	if (dev->tc_kobj) {
		int num_ports;
		int port;

		kobject_put(dev->tc_kobj);
		dev->tc_kobj = NULL;
		num_ports = max(MLX5_CAP_GEN(dev->mdev, num_ports),
				MLX5_CAP_GEN(dev->mdev, num_vhca_ports));
		for (port = 1; port <= num_ports; port++) {
			struct mlx5_tc_data *tcd = &dev->tcd[port - 1];

			if (tcd->initialized)
				kobject_put(&tcd->kobj);
		}
	}
}
