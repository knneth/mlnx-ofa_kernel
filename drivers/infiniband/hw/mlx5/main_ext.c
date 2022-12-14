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

#include <linux/highmem.h>
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

static struct kobj_type ttl_type = {
	.sysfs_ops     = &ttl_sysfs_ops,
	.default_attrs = ttl_attrs
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
			      u8 *tclass)
{
	struct tclass_match *res_match = NULL;
	struct tclass_match match = {};
	enum ib_gid_type gid_type;
	union ib_gid gid;
	int mask;
	int err;

	if (tcd->val >= 0) {
		*tclass = tcd->val;
	} else if (ah && ah->type == RDMA_AH_ATTR_TYPE_ROCE) {
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

void tclass_get_tclass(struct mlx5_ib_dev *dev,
		       struct mlx5_tc_data *tcd,
		       const struct rdma_ah_attr *ah,
		       u8 port,
		       u8 *tclass)
{
	mutex_lock(&tcd->lock);
	tclass_get_tclass_locked(dev, tcd, ah, port, tclass);
	mutex_unlock(&tcd->lock);
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
						 &tclass);

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

static struct kobj_type tc_type = {
	.sysfs_ops     = &tc_sysfs_ops,
	.default_attrs = tc_attrs
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

/* DC_cnak feature*/

static unsigned int dc_cnak_qp_depth = MLX5_DC_CONNECT_QP_DEPTH;
module_param_named(dc_cnak_qp_depth, dc_cnak_qp_depth, uint, 0444);
MODULE_PARM_DESC(dc_cnak_qp_depth, "DC CNAK QP depth");

static void mlx5_ib_enable_dc_tracer(struct mlx5_ib_dev *dev)
{
        struct device *device = dev->ib_dev.dma_device;
        struct mlx5_dc_tracer *dct = &dev->dctr;
        int order;
        void *tmp;
        int size;
        int err;

        size = MLX5_CAP_GEN(dev->mdev, num_ports) * 4096;
        if (size <= PAGE_SIZE)
                order = 0;
        else
                order = 1;

        dct->pg = alloc_pages(GFP_KERNEL, order);
        if (!dct->pg) {
                mlx5_ib_err(dev, "failed to allocate %d pages\n", order);
                return;
        }

        tmp = kmap(dct->pg);
        if (!tmp) {
                mlx5_ib_err(dev, "failed to kmap one page\n");
                err = -ENOMEM;
                goto map_err;
        }

        memset(tmp, 0xff, size);
        kunmap(dct->pg);

        dct->size = size;
        dct->order = order;
        dct->dma = dma_map_page(device, dct->pg, 0, size, DMA_FROM_DEVICE);
        if (dma_mapping_error(device, dct->dma)) {
                mlx5_ib_err(dev, "dma mapping error\n");
                goto map_err;
        }

        err = mlx5_core_set_dc_cnak_trace(dev->mdev, 1, dct->dma);
        if (err) {
                mlx5_ib_warn(dev, "failed to enable DC tracer\n");
                goto cmd_err;
        }

        return;

cmd_err:
        dma_unmap_page(device, dct->dma, size, DMA_FROM_DEVICE);
map_err:
        __free_pages(dct->pg, dct->order);
        dct->pg = NULL;
}

static void mlx5_ib_disable_dc_tracer(struct mlx5_ib_dev *dev)
{
        struct device *device = dev->ib_dev.dma_device;
        struct mlx5_dc_tracer *dct = &dev->dctr;
        int err;

        if (!dct->pg)
                return;

        err = mlx5_core_set_dc_cnak_trace(dev->mdev, 0, dct->dma);
        if (err) {
                mlx5_ib_warn(dev, "failed to disable DC tracer\n");
                return;
        }

        dma_unmap_page(device, dct->dma, dct->size, DMA_FROM_DEVICE);
        __free_pages(dct->pg, dct->order);
        dct->pg = NULL;
}

enum {
        MLX5_DC_CNAK_SIZE               = 128,
        MLX5_NUM_BUF_IN_PAGE            = PAGE_SIZE / MLX5_DC_CNAK_SIZE,
        MLX5_CNAK_TX_CQ_SIGNAL_FACTOR   = 128,
        MLX5_DC_CNAK_SL                 = 0,
        MLX5_DC_CNAK_VL                 = 0,
};

int mlx5_ib_mmap_dc_info_page(struct mlx5_ib_dev *dev,
                              struct vm_area_struct *vma)
{
        struct mlx5_dc_tracer *dct;
        phys_addr_t pfn;
        int err;

        if ((MLX5_CAP_GEN(dev->mdev, port_type) !=
             MLX5_CAP_PORT_TYPE_IB) ||
            (!mlx5_core_is_pf(dev->mdev)) ||
            (!MLX5_CAP_GEN(dev->mdev, dc_cnak_trace)))
                return -ENOTSUPP;

        dct = &dev->dctr;
        if (!dct->pg) {
                mlx5_ib_err(dev, "mlx5_ib_mmap DC no page\n");
                return -ENOMEM;
        }

        pfn = page_to_pfn(dct->pg);
        err = remap_pfn_range(vma, vma->vm_start, pfn, dct->size, vma->vm_page_prot);
        if (err) {
                mlx5_ib_err(dev, "mlx5_ib_mmap DC remap_pfn_range failed\n");
                return err;
        }
        return 0;
}

static void dump_buf(void *buf, int size)
{
        __be32 *p = buf;
        int offset;
        int i;

        for (i = 0, offset = 0; i < size; i += 16) {
                pr_info("%03x: %08x %08x %08x %08x\n", offset, be32_to_cpu(p[0]),
                        be32_to_cpu(p[1]), be32_to_cpu(p[2]), be32_to_cpu(p[3]));
                p += 4;
                offset += 16;
        }
        pr_info("\n");
}

enum {
        CNAK_LENGTH_WITHOUT_GRH = 32,
        CNAK_LENGTH_WITH_GRH    = 72,
};

static struct mlx5_dc_desc *get_desc_from_index(struct mlx5_dc_desc *desc, u64 index, unsigned *offset)
{
        struct mlx5_dc_desc *d;

        int i;
        int j;

        i = index / MLX5_NUM_BUF_IN_PAGE;
        j = index % MLX5_NUM_BUF_IN_PAGE;
        d = desc + i;
        *offset = j * MLX5_DC_CNAK_SIZE;
        return d;
}

static void build_cnak_msg(void *rbuf, void *sbuf, u32 *length, u16 *dlid)
{
        void *rdceth, *sdceth;
        void *rlrh, *slrh;
        void *rgrh, *sgrh;
        void *rbth, *sbth;
        int is_global;
        void *saeth;

        memset(sbuf, 0, MLX5_DC_CNAK_SIZE);
        rlrh = rbuf;
        is_global = MLX5_GET(lrh, rlrh, lnh) == 0x3;
        rgrh = is_global ? rlrh + MLX5_ST_SZ_BYTES(lrh) : NULL;
        rbth = rgrh ? rgrh + MLX5_ST_SZ_BYTES(grh) : rlrh + MLX5_ST_SZ_BYTES(lrh);
        rdceth = rbth + MLX5_ST_SZ_BYTES(bth);

        slrh = sbuf;
        sgrh = is_global ? slrh + MLX5_ST_SZ_BYTES(lrh) : NULL;
        sbth = sgrh ? sgrh + MLX5_ST_SZ_BYTES(grh) : slrh + MLX5_ST_SZ_BYTES(lrh);
        sdceth = sbth + MLX5_ST_SZ_BYTES(bth);
        saeth = sdceth + MLX5_ST_SZ_BYTES(dceth);

        *dlid = MLX5_GET(lrh, rlrh, slid);
        MLX5_SET(lrh, slrh, vl, MLX5_DC_CNAK_VL);
        MLX5_SET(lrh, slrh, lver, MLX5_GET(lrh, rlrh, lver));
        MLX5_SET(lrh, slrh, sl, MLX5_DC_CNAK_SL);
        MLX5_SET(lrh, slrh, lnh, MLX5_GET(lrh, rlrh, lnh));
        MLX5_SET(lrh, slrh, dlid, MLX5_GET(lrh, rlrh, slid));
        MLX5_SET(lrh, slrh, pkt_len, 0x9 + ((is_global ? MLX5_ST_SZ_BYTES(grh) : 0) >> 2));
        MLX5_SET(lrh, slrh, slid, MLX5_GET(lrh, rlrh, dlid));

        if (is_global) {
                void *rdgid, *rsgid;
                void *ssgid, *sdgid;

                MLX5_SET(grh, sgrh, ip_version, MLX5_GET(grh, rgrh, ip_version));
                MLX5_SET(grh, sgrh, traffic_class, MLX5_GET(grh, rgrh, traffic_class));
                MLX5_SET(grh, sgrh, flow_label, MLX5_GET(grh, rgrh, flow_label));
                MLX5_SET(grh, sgrh, payload_length, 0x1c);
                MLX5_SET(grh, sgrh, next_header, 0x1b);
                MLX5_SET(grh, sgrh, hop_limit, MLX5_GET(grh, rgrh, hop_limit));

                rdgid = MLX5_ADDR_OF(grh, rgrh, dgid);
                rsgid = MLX5_ADDR_OF(grh, rgrh, sgid);
                ssgid = MLX5_ADDR_OF(grh, sgrh, sgid);
                sdgid = MLX5_ADDR_OF(grh, sgrh, dgid);
                memcpy(ssgid, rdgid, 16);
                memcpy(sdgid, rsgid, 16);
                *length = CNAK_LENGTH_WITH_GRH;
        } else {
                *length = CNAK_LENGTH_WITHOUT_GRH;
        }

        MLX5_SET(bth, sbth, opcode, 0x51);
        MLX5_SET(bth, sbth, migreq, 0x1);
        MLX5_SET(bth, sbth, p_key, MLX5_GET(bth, rbth, p_key));
        MLX5_SET(bth, sbth, dest_qp, MLX5_GET(dceth, rdceth, dci_dct));
        MLX5_SET(bth, sbth, psn, MLX5_GET(bth, rbth, psn));

        MLX5_SET(dceth, sdceth, dci_dct, MLX5_GET(bth, rbth, dest_qp));

        MLX5_SET(aeth, saeth, syndrome, 0x64);

        if (0) {
                pr_info("===dump packet ====\n");
                dump_buf(sbuf, *length);
        }
}

static int reduce_tx_pending(struct mlx5_dc_data *dcd, int num)
{
        struct mlx5_ib_dev *dev = dcd->dev;
        struct ib_cq *cq = dcd->scq;
        unsigned int send_completed;
        unsigned int polled;
        struct ib_wc wc;
        int n;

        while (num > 0) {
                n = ib_poll_cq(cq, 1, &wc);
                if (unlikely(n < 0)) {
                        mlx5_ib_warn(dev, "error polling cnak send cq\n");
                        return n;
                }
                if (unlikely(!n))
                        return -EAGAIN;

                if (unlikely(wc.status != IB_WC_SUCCESS)) {
                        mlx5_ib_warn(dev, "cnak send completed with error, status %d vendor_err %d\n",
                                     wc.status, wc.vendor_err);
                        dcd->last_send_completed++;
                        dcd->tx_pending--;
                        num--;
                } else {
                        send_completed = wc.wr_id;
                        polled = send_completed - dcd->last_send_completed;
                        dcd->tx_pending = (unsigned int)(dcd->cur_send - send_completed);
                        num -= polled;
                        dcd->last_send_completed = send_completed;
                }
        }

        return 0;
}

static bool signal_wr(int wr_count, struct mlx5_dc_data *dcd)
{
	return !(wr_count % dcd->tx_signal_factor);
}

static int send_cnak(struct mlx5_dc_data *dcd, struct mlx5_send_wr *mlx_wr,
                     u64 rcv_buff_id)
{
        struct ib_send_wr *wr = &mlx_wr->wr;
        struct mlx5_ib_dev *dev = dcd->dev;
        const struct ib_send_wr *bad_wr;
        struct mlx5_dc_desc *rxd;
        struct mlx5_dc_desc *txd;
        unsigned int offset;
        unsigned int cur;
        __be32 *sbuf;
        void *rbuf;
        int err;

        if (unlikely(dcd->tx_pending > dcd->max_wqes)) {
                mlx5_ib_warn(dev, "SW error in cnak send: tx_pending(%d) > max_wqes(%d)\n",
                             dcd->tx_pending, dcd->max_wqes);
                return -EFAULT;
        }

        if (unlikely(dcd->tx_pending == dcd->max_wqes)) {
                err = reduce_tx_pending(dcd, 1);
                if (err)
                        return err;
                if (dcd->tx_pending == dcd->max_wqes)
                        return -EAGAIN;
        }

        cur = dcd->cur_send;
        txd = get_desc_from_index(dcd->txdesc, cur % dcd->max_wqes, &offset);
        sbuf = txd->buf + offset;

        wr->sg_list[0].addr = txd->dma + offset;
        wr->sg_list[0].lkey = dcd->mr->lkey;
        wr->opcode = IB_WR_SEND;
        wr->num_sge = 1;
        wr->wr_id = cur;
	if (!signal_wr(cur, dcd))
                wr->send_flags &= ~IB_SEND_SIGNALED;
        else
                wr->send_flags |= IB_SEND_SIGNALED;

        rxd = get_desc_from_index(dcd->rxdesc, rcv_buff_id, &offset);
        rbuf = rxd->buf + offset;
        build_cnak_msg(rbuf, sbuf, &wr->sg_list[0].length, &mlx_wr->sel.mlx.dlid);

        mlx_wr->sel.mlx.sl = MLX5_DC_CNAK_SL;
        mlx_wr->sel.mlx.icrc = 1;

        err = ib_post_send(dcd->dcqp, wr, &bad_wr);
        if (likely(!err)) {
                dcd->tx_pending++;
                dcd->cur_send++;
		atomic64_inc(&dcd->dev->dc_stats[dcd->port - 1].cnaks);
        }

        return err;
}

static int mlx5_post_one_rxdc(struct mlx5_dc_data *dcd, int index)
{
        const struct ib_recv_wr *bad_wr;
        struct ib_recv_wr wr;
        struct ib_sge sge;
        u64 addr;
        int err;
        int i;
        int j;

        i = index / (PAGE_SIZE / MLX5_DC_CNAK_SIZE);
        j = index % (PAGE_SIZE / MLX5_DC_CNAK_SIZE);
        addr = dcd->rxdesc[i].dma + j * MLX5_DC_CNAK_SIZE;

        memset(&wr, 0, sizeof(wr));
        wr.num_sge = 1;
        sge.addr = addr;
        sge.length = MLX5_DC_CNAK_SIZE;
        sge.lkey = dcd->mr->lkey;
        wr.sg_list = &sge;
        wr.num_sge = 1;
        wr.wr_id = index;
        err = ib_post_recv(dcd->dcqp, &wr, &bad_wr);
        if (unlikely(err))
                mlx5_ib_warn(dcd->dev, "failed to post dc rx buf at index %d\n", index);

        return err;
}

static void dc_cnack_rcv_comp_handler(struct ib_cq *cq, void *cq_context)
{
        struct mlx5_dc_data *dcd = cq_context;
        struct mlx5_ib_dev *dev = dcd->dev;
        struct mlx5_send_wr mlx_wr;
        struct ib_send_wr *wr = &mlx_wr.wr;
        struct ib_wc *wc = dcd->wc_tbl;
        struct ib_sge sge;
        int err;
        int n;
        int i;

        memset(&mlx_wr, 0, sizeof(mlx_wr));
        wr->sg_list = &sge;

        n = ib_poll_cq(cq, MLX5_CNAK_RX_POLL_CQ_QUOTA, wc);
        if (unlikely(n < 0)) {
                /* mlx5 never returns negative values but leave a message just in case */
                mlx5_ib_warn(dev, "DC cnak[%d]: failed to poll cq (%d), aborting\n",
			     dcd->index, n);
		return;
        }
        if (likely(n > 0)) {
                for (i = 0; i < n; i++) {
                        if (dev->mdev->state == MLX5_DEVICE_STATE_INTERNAL_ERROR)
                                return;

                        if (unlikely(wc[i].status != IB_WC_SUCCESS)) {
				mlx5_ib_warn(dev, "DC cnak[%d]: completed with error, status = %d vendor_err = %d\n",
					     wc[i].status, wc[i].vendor_err, dcd->index);
                        } else {
				atomic64_inc(&dcd->dev->dc_stats[dcd->port - 1].connects);
				dev->dc_stats[dcd->port - 1].rx_scatter[dcd->index]++;
                                if (unlikely(send_cnak(dcd, &mlx_wr, wc[i].wr_id)))
					mlx5_ib_warn(dev, "DC cnak[%d]: failed to allocate send buf - dropped\n",
						     dcd->index);
                        }

                        if (unlikely(mlx5_post_one_rxdc(dcd, wc[i].wr_id))) {
				atomic64_inc(&dcd->dev->dc_stats[dcd->port - 1].discards);
				mlx5_ib_warn(dev, "DC cnak[%d]: repost rx failed, will leak rx queue\n",
					     dcd->index);
                        }
                }
        }

        err = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
        if (unlikely(err))
		mlx5_ib_warn(dev, "DC cnak[%d]: failed to re-arm receive cq (%d)\n",
			     dcd->index, err);
}

static int alloc_dc_buf(struct mlx5_dc_data *dcd, int rx)
{
        struct mlx5_ib_dev *dev = dcd->dev;
        struct mlx5_dc_desc **desc;
        struct mlx5_dc_desc *d;
        struct device *ddev;
        int max_wqes;
        int err = 0;
        int npages;
        int totsz;
        int i;

        ddev = &dev->mdev->pdev->dev;
        max_wqes = dcd->max_wqes;
        totsz = max_wqes * MLX5_DC_CNAK_SIZE;
        npages = DIV_ROUND_UP(totsz, PAGE_SIZE);
        desc = rx ? &dcd->rxdesc : &dcd->txdesc;
        *desc = kcalloc(npages, sizeof(*dcd->rxdesc), GFP_KERNEL);
        if (!*desc) {
                err = -ENOMEM;
                goto out;
        }

        for (i = 0; i < npages; i++) {
                d = *desc + i;
                d->buf = dma_alloc_coherent(ddev, PAGE_SIZE, &d->dma, GFP_KERNEL);
                if (!d->buf) {
                        mlx5_ib_err(dev, "dma alloc failed at %d\n", i);
                        goto out_free;
                }
        }
        if (rx)
                dcd->rx_npages = npages;
        else
                dcd->tx_npages = npages;

        return 0;

out_free:
        for (i--; i >= 0; i--) {
                d = *desc + i;
                dma_free_coherent(ddev, PAGE_SIZE, d->buf, d->dma);
        }
        kfree(*desc);
out:
        return err;
}

static int alloc_dc_rx_buf(struct mlx5_dc_data *dcd)
{
        return alloc_dc_buf(dcd, 1);
}

static int alloc_dc_tx_buf(struct mlx5_dc_data *dcd)
{
        return alloc_dc_buf(dcd, 0);
}

static void free_dc_buf(struct mlx5_dc_data *dcd, int rx)
{
        struct mlx5_ib_dev *dev = dcd->dev;
        struct mlx5_dc_desc *desc;
        struct mlx5_dc_desc *d;
        struct device *ddev;
        int npages;
        int i;

        ddev = &dev->mdev->pdev->dev;
        npages = rx ? dcd->rx_npages : dcd->tx_npages;
        desc = rx ? dcd->rxdesc : dcd->txdesc;
        for (i = 0; i < npages; i++) {
                d = desc + i;
                dma_free_coherent(ddev, PAGE_SIZE, d->buf, d->dma);
        }
        kfree(desc);
}

static void free_dc_rx_buf(struct mlx5_dc_data *dcd)
{
        free_dc_buf(dcd, 1);
}

static void free_dc_tx_buf(struct mlx5_dc_data *dcd)
{
        free_dc_buf(dcd, 0);
}

struct dc_attribute {
        struct attribute attr;
	ssize_t (*show)(struct mlx5_dc_stats *, struct dc_attribute *, char *buf);
	ssize_t (*store)(struct mlx5_dc_stats *, struct dc_attribute *,
                         const char *buf, size_t count);
};

static ssize_t qp_count_show(struct mlx5_dc_stats *dc_stats,
                             struct dc_attribute *unused,
                             char *buf)
{
        return sprintf(buf, "%u\n", dc_stats->dev->num_dc_cnak_qps);
}

static int init_driver_cnak(struct mlx5_ib_dev *dev, int port, int index);
static ssize_t qp_count_store(struct mlx5_dc_stats *dc_stats,
                              struct dc_attribute *unused,
                              const char *buf, size_t count)
{
        struct mlx5_ib_dev *dev = dc_stats->dev;
        int port = dc_stats->port;
        unsigned long var;
        int i;
        int err = 0;
        int qp_add = 0;

        if (kstrtol(buf, 0, &var)) {
                err = -EINVAL;
                goto err;
        }
        if ((var > dev->max_dc_cnak_qps) ||
            (dev->num_dc_cnak_qps >= var)) {
                err = -EINVAL;
                goto err;
        }

        for (i = dev->num_dc_cnak_qps; i < var; i++) {
                err = init_driver_cnak(dev, port, i);
                if (err) {
                        mlx5_ib_warn(dev, "Fail to set %ld CNAK QPs. Only %d were added\n",
                                     var, qp_add);
                        break;
                }
                dev->num_dc_cnak_qps++;
                qp_add++;
        }
err:

        return err ? err : count;
}

#define DC_ATTR(_name, _mode, _show, _store) \
struct dc_attribute dc_attr_##_name = __ATTR(_name, _mode, _show, _store)

static DC_ATTR(qp_count, 0644, qp_count_show, qp_count_store);

static ssize_t rx_connect_show(struct mlx5_dc_stats *dc_stats,
                               struct dc_attribute *unused,
                               char *buf)
{
        unsigned long num;

	num = atomic64_read(&dc_stats->connects);

        return sprintf(buf, "%lu\n", num);
}

static ssize_t tx_cnak_show(struct mlx5_dc_stats *dc_stats,
                            struct dc_attribute *unused,
                            char *buf)
{
        unsigned long num;

	num = atomic64_read(&dc_stats->cnaks);

        return sprintf(buf, "%lu\n", num);
}

static ssize_t tx_discard_show(struct mlx5_dc_stats *dc_stats,
                               struct dc_attribute *unused,
                               char *buf)
{
        unsigned long num;

	num = atomic64_read(&dc_stats->discards);

        return sprintf(buf, "%lu\n", num);
}

static ssize_t rx_scatter_show(struct mlx5_dc_stats *dc_stats,
                               struct dc_attribute *unused,
                               char *buf)
{
        int i;
        int ret;
        int res = 0;

        buf[0] = 0;

        for (i = 0; i < dc_stats->dev->max_dc_cnak_qps ; i++) {
                unsigned long num = dc_stats->rx_scatter[i];

                if (!dc_stats->dev->dcd[dc_stats->port - 1][i].initialized)
                        continue;
                ret = sprintf(buf + strlen(buf), "%d:%lu\n", i, num);
                if (ret < 0) {
                        res = ret;
                        break;
                }
                res += ret;
        }
        return res;
}

#define DC_ATTR_RO(_name) \
struct dc_attribute dc_attr_##_name = __ATTR_RO(_name)

static DC_ATTR_RO(rx_connect);
static DC_ATTR_RO(tx_cnak);
static DC_ATTR_RO(tx_discard);
static DC_ATTR_RO(rx_scatter);

static struct attribute *dc_attrs[] = {
        &dc_attr_rx_connect.attr,
        &dc_attr_tx_cnak.attr,
        &dc_attr_tx_discard.attr,
	&dc_attr_rx_scatter.attr,
	&dc_attr_qp_count.attr,
        NULL
};

static ssize_t dc_attr_show(struct kobject *kobj,
                            struct attribute *attr, char *buf)
{
        struct dc_attribute *dc_attr = container_of(attr, struct dc_attribute, attr);
	struct mlx5_dc_stats *d = container_of(kobj, struct mlx5_dc_stats, kobj);

        if (!dc_attr->show)
                return -EIO;

        return dc_attr->show(d, dc_attr, buf);
}

static ssize_t dc_attr_store(struct kobject *kobj,
			     struct attribute *attr, const char *buf, size_t size)
{
	struct dc_attribute *dc_attr = container_of(attr, struct dc_attribute, attr);
	struct mlx5_dc_stats *d = container_of(kobj, struct mlx5_dc_stats, kobj);

	if (!dc_attr->store)
		return -EIO;

	return dc_attr->store(d, dc_attr, buf, size);
}

static const struct sysfs_ops dc_sysfs_ops = {
        .show = dc_attr_show,
	.store = dc_attr_store
};

static struct kobj_type dc_type = {
        .sysfs_ops     = &dc_sysfs_ops,
        .default_attrs = dc_attrs
};

static int init_sysfs(struct mlx5_ib_dev *dev)
{
        struct device *device = &dev->ib_dev.dev;

        dev->dc_kobj = kobject_create_and_add("dct", &device->kobj);
        if (!dev->dc_kobj) {
                mlx5_ib_err(dev, "failed to register DCT sysfs object\n");
                return -ENOMEM;
        }

        return 0;
}

static void cleanup_sysfs(struct mlx5_ib_dev *dev)
{
        if (dev->dc_kobj) {
                kobject_put(dev->dc_kobj);
                dev->dc_kobj = NULL;
        }
}

static int init_port_sysfs(struct mlx5_dc_stats *dc_stats,
			   struct mlx5_ib_dev *dev, int port)
{
	int ret;

	dc_stats->dev = dev;
	dc_stats->port = port;
	ret = kobject_init_and_add(&dc_stats->kobj, &dc_type,
				   dc_stats->dev->dc_kobj, "%d", dc_stats->port);
	if (!ret)
		dc_stats->initialized = 1;
	return ret;
}

static void cleanup_port_sysfs(struct mlx5_dc_stats *dc_stats)
{
	if (!dc_stats->initialized)
		return;
	kobject_put(&dc_stats->kobj);
}

static int comp_vector(struct ib_device *dev, int port, int index)
{
	int comp_per_port = dev->num_comp_vectors / dev->phys_port_cnt;

	return (port - 1) * comp_per_port + (index % comp_per_port);
}

static int init_driver_cnak(struct mlx5_ib_dev *dev, int port, int index)
{
	struct mlx5_dc_data *dcd = &dev->dcd[port - 1][index];
        struct mlx5_ib_resources *devr = &dev->devr;
        struct ib_cq_init_attr cq_attr = {};
        struct ib_qp_init_attr init_attr;
        struct ib_pd *pd = devr->p0;
        struct ib_qp_attr attr;
	int ncqe;
	int nwr;
        int err;
        int i;

        dcd->dev = dev;
        dcd->port = port;
	dcd->index = index;
        dcd->mr = pd->device->ops.get_dma_mr(pd,  IB_ACCESS_LOCAL_WRITE);
        if (IS_ERR(dcd->mr)) {
                mlx5_ib_warn(dev, "failed to create dc DMA MR\n");
                err = PTR_ERR(dcd->mr);
                goto error1;
        }

        dcd->mr->device      = pd->device;
        dcd->mr->pd          = pd;
        dcd->mr->uobject     = NULL;
        dcd->mr->need_inval  = false;

	ncqe = min_t(int, dc_cnak_qp_depth,
		     BIT(MLX5_CAP_GEN(dev->mdev, log_max_cq_sz)));
	nwr = min_t(int, ncqe,
		    BIT(MLX5_CAP_GEN(dev->mdev, log_max_qp_sz)));

	if (dc_cnak_qp_depth > nwr) {
		mlx5_ib_warn(dev, "Can't set DC CNAK QP size to %d. Set to default %d\n",
			     dc_cnak_qp_depth, nwr);
		dc_cnak_qp_depth = nwr;
	}

        cq_attr.cqe = ncqe;
	cq_attr.comp_vector = comp_vector(&dev->ib_dev, port, index);
        dcd->rcq = ib_create_cq(&dev->ib_dev, dc_cnack_rcv_comp_handler, NULL,
                                dcd, &cq_attr);
        if (IS_ERR(dcd->rcq)) {
                err = PTR_ERR(dcd->rcq);
                mlx5_ib_warn(dev, "failed to create dc cnack rx cq (%d)\n", err);
                goto error2;
        }

        err = ib_req_notify_cq(dcd->rcq, IB_CQ_NEXT_COMP);
        if (err) {
                mlx5_ib_warn(dev, "failed to setup dc cnack rx cq (%d)\n", err);
                goto error3;
        }

        dcd->scq = ib_create_cq(&dev->ib_dev, NULL, NULL,
                                dcd, &cq_attr);
        if (IS_ERR(dcd->scq)) {
                err = PTR_ERR(dcd->scq);
                mlx5_ib_warn(dev, "failed to create dc cnack tx cq (%d)\n", err);
                goto error3;
        }

        memset(&init_attr, 0, sizeof(init_attr));
        init_attr.qp_type = MLX5_IB_QPT_SW_CNAK;
	init_attr.cap.max_recv_wr = nwr;
        init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_send_wr = nwr;
 	init_attr.cap.max_send_sge = 1;
        init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
        init_attr.recv_cq = dcd->rcq;
        init_attr.send_cq = dcd->scq;
        dcd->dcqp = ib_create_qp(pd, &init_attr);
        if (IS_ERR(dcd->dcqp)) {
                mlx5_ib_warn(dev, "failed to create qp (%d)\n", err);
                err = PTR_ERR(dcd->dcqp);
                goto error4;
        }
        memset(&attr, 0, sizeof(attr));
        attr.qp_state = IB_QPS_INIT;
        attr.port_num = port;
        err = ib_modify_qp(dcd->dcqp, &attr,
                           IB_QP_STATE | IB_QP_PKEY_INDEX | IB_QP_PORT);
        if (err) {
                mlx5_ib_warn(dev, "failed to modify qp to init\n");
                goto error5;
        }

        memset(&attr, 0, sizeof(attr));
        attr.qp_state = IB_QPS_RTR;
        attr.path_mtu = IB_MTU_4096;
        err = ib_modify_qp(dcd->dcqp, &attr, IB_QP_STATE);
        if (err) {
                mlx5_ib_warn(dev, "failed to modify qp to rtr\n");
                goto error5;
        }

        memset(&attr, 0, sizeof(attr));
        attr.qp_state = IB_QPS_RTS;
        err = ib_modify_qp(dcd->dcqp, &attr, IB_QP_STATE);
        if (err) {
                mlx5_ib_warn(dev, "failed to modify qp to rts\n");
                goto error5;
        }

	dcd->max_wqes = nwr;
        err = alloc_dc_rx_buf(dcd);
        if (err) {
                mlx5_ib_warn(dev, "failed to allocate rx buf\n");
                goto error5;
        }

        err = alloc_dc_tx_buf(dcd);
        if (err) {
                mlx5_ib_warn(dev, "failed to allocate tx buf\n");
                goto error6;
        }

        for (i = 0; i < nwr; i++) {
                err = mlx5_post_one_rxdc(dcd, i);
                if (err)
                        goto error7;
        }

	dcd->tx_signal_factor = min_t(int, DIV_ROUND_UP(dcd->max_wqes, 2),
				      MLX5_CNAK_TX_CQ_SIGNAL_FACTOR);

        dcd->initialized = 1;
        return 0;

error7:
        free_dc_tx_buf(dcd);
error6:
        free_dc_rx_buf(dcd);
error5:
        if (ib_destroy_qp(dcd->dcqp))
                mlx5_ib_warn(dev, "failed to destroy dc qp\n");
error4:
        if (ib_destroy_cq(dcd->scq))
                mlx5_ib_warn(dev, "failed to destroy dc scq\n");
error3:
        if (ib_destroy_cq(dcd->rcq))
                mlx5_ib_warn(dev, "failed to destroy dc rcq\n");
error2:
        ib_dereg_mr(dcd->mr);
error1:
        return err;
}

static void cleanup_driver_cnak(struct mlx5_ib_dev *dev, int port, int index)
{
	struct mlx5_dc_data *dcd = &dev->dcd[port - 1][index];

        if (!dcd->initialized)
                return;

        if (ib_destroy_qp(dcd->dcqp))
                mlx5_ib_warn(dev, "destroy qp failed\n");

        if (ib_destroy_cq(dcd->scq))
                mlx5_ib_warn(dev, "destroy scq failed\n");

        if (ib_destroy_cq(dcd->rcq))
                mlx5_ib_warn(dev, "destroy rcq failed\n");

        ib_dereg_mr(dcd->mr);
        free_dc_tx_buf(dcd);
        free_dc_rx_buf(dcd);
        dcd->initialized = 0;
}

int mlx5_ib_init_dc_improvements(struct mlx5_ib_dev *dev)
{
        int port;
        int err;
	int i;
	struct mlx5_core_dev *mdev = dev->mdev;
	int max_dc_cnak_qps;
	int ini_dc_cnak_qps;

	if (!mlx5_core_is_pf(dev->mdev) ||
            !(MLX5_CAP_GEN(dev->mdev, dc_cnak_trace)))
                return 0;

        mlx5_ib_enable_dc_tracer(dev);

	max_dc_cnak_qps = min_t(int, 1 << MLX5_CAP_GEN(mdev, log_max_dc_cnak_qps),
				dev->ib_dev.num_comp_vectors / MLX5_CAP_GEN(mdev, num_ports));

        if (!MLX5_CAP_GEN(dev->mdev, dc_connect_qp))
                return 0;

	err = init_sysfs(dev);
	if (err)
		return err;

	/* start with 25% of maximum CNAK QPs */
	ini_dc_cnak_qps = DIV_ROUND_UP(max_dc_cnak_qps, 4);

        for (port = 1; port <= MLX5_CAP_GEN(dev->mdev, num_ports); port++) {
		dev->dcd[port - 1] =
			kcalloc(max_dc_cnak_qps, sizeof(struct mlx5_dc_data), GFP_KERNEL);
		if (!dev->dcd[port - 1]) {
			err = -ENOMEM;
			goto err;
		}
		dev->dc_stats[port - 1].rx_scatter =
			kcalloc(max_dc_cnak_qps, sizeof(int), GFP_KERNEL);
		if (!dev->dc_stats[port - 1].rx_scatter) {
			err = -ENOMEM;
			goto err;
		}
		for (i = 0; i < ini_dc_cnak_qps; i++) {
			err = init_driver_cnak(dev, port, i);
			if (err)
				goto err;
		}
		err = init_port_sysfs(&dev->dc_stats[port - 1], dev, port);
		if (err) {
			mlx5_ib_warn(dev, "failed to initialize DC cnak sysfs\n");
			goto err;
		}
        }
	dev->num_dc_cnak_qps = ini_dc_cnak_qps;
	dev->max_dc_cnak_qps = max_dc_cnak_qps;

        return 0;

err:
	for (port = 1; port <= MLX5_CAP_GEN(dev->mdev, num_ports); port++) {
		for (i = 0; i < ini_dc_cnak_qps; i++)
			cleanup_driver_cnak(dev, port, i);
		cleanup_port_sysfs(&dev->dc_stats[port - 1]);
		kfree(dev->dc_stats[port - 1].rx_scatter);
		kfree(dev->dcd[port - 1]);
	}
	cleanup_sysfs(dev);

        return err;
}

void mlx5_ib_cleanup_dc_improvements(struct mlx5_ib_dev *dev)
{
        int port;
	int i;

	if (dev->num_dc_cnak_qps) {
		for (port = 1; port <= MLX5_CAP_GEN(dev->mdev, num_ports); port++) {
			for (i = 0; i < dev->num_dc_cnak_qps; i++)
				cleanup_driver_cnak(dev, port, i);
			cleanup_port_sysfs(&dev->dc_stats[port - 1]);
			kfree(dev->dc_stats[port - 1].rx_scatter);
			kfree(dev->dcd[port - 1]);
		}
		cleanup_sysfs(dev);
	}

        mlx5_ib_disable_dc_tracer(dev);
}


