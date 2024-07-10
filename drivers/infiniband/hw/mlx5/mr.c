/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
 * Copyright (c) 2020, Intel Corporation. All rights reserved.
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


#include <linux/kref.h>
#include <linux/random.h>
#include <linux/debugfs.h>
#include <linux/export.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/sysfs.h>
#include <linux/dma-buf.h>
#include <linux/dma-resv.h>
#include <rdma/ib_umem_odp.h>
#include "dm.h"
#include "mlx5_ib.h"
#include "umr.h"
#include "ib_rep.h"

static void mlx5_invalidate_umem(struct ib_umem *umem, void *priv);

enum {
	MAX_PENDING_REG_MR = 8,
	MAX_MR_RELEASE_TIMEOUT = (60 * 20) /* Allow release timeout up to 20 min */
};

#define MLX5_UMR_ALIGN 2048

static void
create_mkey_callback(int status, struct mlx5_async_work *context);
static struct mlx5_ib_mr *reg_create(struct ib_pd *pd, struct ib_umem *umem,
				     u64 iova, int access_flags,
				     unsigned int page_size, bool populate);

static void set_mkc_access_pd_addr_fields(void *mkc, int acc, u64 start_addr,
					  struct ib_pd *pd)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);

	MLX5_SET(mkc, mkc, a, !!(acc & IB_ACCESS_REMOTE_ATOMIC));
	MLX5_SET(mkc, mkc, rw, !!(acc & IB_ACCESS_REMOTE_WRITE));
	MLX5_SET(mkc, mkc, rr, !!(acc & IB_ACCESS_REMOTE_READ));
	MLX5_SET(mkc, mkc, lw, !!(acc & IB_ACCESS_LOCAL_WRITE));
	MLX5_SET(mkc, mkc, lr, 1);

	if (acc & IB_ACCESS_RELAXED_ORDERING) {
		bool is_vf = mlx5_core_is_vf(dev->mdev);
		bool ro_read = MLX5_CAP_GEN(dev->mdev, relaxed_ordering_read);
		bool ro_read_pci_en =
			MLX5_CAP_GEN(dev->mdev,
				     relaxed_ordering_read_pci_enabled);

		if (MLX5_CAP_GEN(dev->mdev, relaxed_ordering_write))
			MLX5_SET(mkc, mkc, relaxed_ordering_write, 1);

		if (ro_read ||
		    (ro_read_pci_en &&
		     (is_vf || pcie_relaxed_ordering_enabled(dev->mdev->pdev))))
			MLX5_SET(mkc, mkc, relaxed_ordering_read, 1);
	}

	MLX5_SET(mkc, mkc, pd, to_mpd(pd)->pdn);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET64(mkc, mkc, start_addr, start_addr);
}

static void assign_mkey_variant(struct mlx5_ib_dev *dev, u32 *mkey, u32 *in)
{
	u8 key = atomic_inc_return(&dev->mkey_var);
	void *mkc;

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, mkey_7_0, key);
	*mkey = key;
}

static int mlx5_ib_create_mkey(struct mlx5_ib_dev *dev,
			       struct mlx5_ib_mkey *mkey, u32 *in, int inlen)
{
	int ret;

	assign_mkey_variant(dev, &mkey->key, in);
	ret = mlx5_core_create_mkey(dev->mdev, &mkey->key, in, inlen);
	if (!ret)
		init_waitqueue_head(&mkey->wait);

	return ret;
}

static int mlx5_ib_create_mkey_cb(struct mlx5r_async_create_mkey *async_create)
{
	struct mlx5_ib_dev *dev = async_create->ent->dev;
	size_t inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	size_t outlen = MLX5_ST_SZ_BYTES(create_mkey_out);

	MLX5_SET(create_mkey_in, async_create->in, opcode,
		 MLX5_CMD_OP_CREATE_MKEY);
	assign_mkey_variant(dev, &async_create->mkey, async_create->in);
	return mlx5_cmd_exec_cb(&dev->async_ctx, async_create->in, inlen,
				async_create->out, outlen, create_mkey_callback,
				&async_create->cb_work);
}

static int mlx5_mkey_cache_sysfs_init(struct mlx5_ib_dev *dev);
static int mlx5_mkey_cache_sysfs_add_ent(struct mlx5_ib_dev *dev, struct mlx5_cache_ent *ent);
static void mlx5_mkey_cache_sysfs_cleanup(struct mlx5_ib_dev *dev);
static void mlx5_mkey_cache_sysfs_ent_cleanup(struct mlx5_cache_ent *ent);

static int mkey_cache_max_order(struct mlx5_ib_dev *dev);
static void queue_adjust_cache_locked(struct mlx5_cache_ent *ent);

static int destroy_mkey(struct mlx5_ib_dev *dev, struct mlx5_ib_mr *mr)
{
	WARN_ON(xa_load(&dev->odp_mkeys, mlx5_base_mkey(mr->mmkey.key)));

	return mlx5_core_destroy_mkey(dev->mdev, mr->mmkey.key);
}

static void create_mkey_warn(struct mlx5_ib_dev *dev, int status, void *out)
{
	if (status == -ENXIO) /* core driver is not available */
		return;

	mlx5_ib_warn(dev, "async reg mr failed. status %d\n", status);
	if (status != -EREMOTEIO) /* driver specific failure */
		return;

	/* Failed in FW, print cmd out failure details */
	mlx5_cmd_out_err(dev->mdev, MLX5_CMD_OP_CREATE_MKEY, 0, out);
}

static int push_mkey_locked(struct mlx5_cache_ent *ent, bool limit_pendings,
			    void *to_store)
{
	XA_STATE(xas, &ent->mkeys, 0);
	void *curr;

	if (limit_pendings &&
	    (ent->reserved - ent->stored) > MAX_PENDING_REG_MR)
		return -EAGAIN;

	while (1) {
		/*
		 * This is cmpxchg (NULL, XA_ZERO_ENTRY) however this version
		 * doesn't transparently unlock. Instead we set the xas index to
		 * the current value of reserved every iteration.
		 */
		xas_set(&xas, ent->reserved);
		curr = xas_load(&xas);
		if (!curr) {
			if (to_store && ent->stored == ent->reserved)
				xas_store(&xas, to_store);
			else
				xas_store(&xas, XA_ZERO_ENTRY);
			if (xas_valid(&xas)) {
				ent->reserved++;
				if (to_store) {
					if (ent->stored != ent->reserved)
						__xa_store(&ent->mkeys,
							   ent->stored,
							   to_store,
							   GFP_KERNEL);
					ent->stored++;
					queue_adjust_cache_locked(ent);
					WRITE_ONCE(ent->dev->cache.last_add,
						   jiffies);
				}
			}
		}
		xa_unlock_irq(&ent->mkeys);

		/*
		 * Notice xas_nomem() must always be called as it cleans
		 * up any cached allocation.
		 */
		if (!xas_nomem(&xas, GFP_KERNEL))
			break;
		xa_lock_irq(&ent->mkeys);
	}
	xa_lock_irq(&ent->mkeys);
	if (xas_error(&xas))
		return xas_error(&xas);
	if (WARN_ON(curr))
		return -EINVAL;
	return 0;
}

static int push_mkey(struct mlx5_cache_ent *ent, bool limit_pendings,
		     void *to_store)
{
	int ret;

	xa_lock_irq(&ent->mkeys);
	ret = push_mkey_locked(ent, limit_pendings, to_store);
	xa_unlock_irq(&ent->mkeys);
	return ret;
}

static void undo_push_reserve_mkey(struct mlx5_cache_ent *ent)
{
	void *old;

	ent->reserved--;
	old = __xa_erase(&ent->mkeys, ent->reserved);
	WARN_ON(old);
}

static void push_to_reserved(struct mlx5_cache_ent *ent, u32 mkey)
{
	void *old;

	old = __xa_store(&ent->mkeys, ent->stored, xa_mk_value(mkey), 0);
	WARN_ON(old);
	ent->stored++;
}

static u32 pop_stored_mkey(struct mlx5_cache_ent *ent)
{
	void *old, *xa_mkey;

	ent->stored--;
	ent->reserved--;

	if (ent->stored == ent->reserved) {
		xa_mkey = __xa_erase(&ent->mkeys, ent->stored);
		WARN_ON(!xa_mkey);
		return (u32)xa_to_value(xa_mkey);
	}

	xa_mkey = __xa_store(&ent->mkeys, ent->stored, XA_ZERO_ENTRY,
			     GFP_KERNEL);
	WARN_ON(!xa_mkey || xa_is_err(xa_mkey));
	old = __xa_erase(&ent->mkeys, ent->reserved);
	WARN_ON(old);
	return (u32)xa_to_value(xa_mkey);
}

static void create_mkey_callback(int status, struct mlx5_async_work *context)
{
	struct mlx5r_async_create_mkey *mkey_out =
		container_of(context, struct mlx5r_async_create_mkey, cb_work);
	struct mlx5_cache_ent *ent = mkey_out->ent;
	struct mlx5_ib_dev *dev = ent->dev;
	unsigned long flags;

	if (status) {
		create_mkey_warn(dev, status, mkey_out->out);
		kfree(mkey_out);
		xa_lock_irqsave(&ent->mkeys, flags);
		undo_push_reserve_mkey(ent);
		WRITE_ONCE(dev->fill_delay, 1);
		xa_unlock_irqrestore(&ent->mkeys, flags);
		mod_timer(&dev->delay_timer, jiffies + HZ);
		return;
	}

	mkey_out->mkey |= mlx5_idx_to_mkey(
		MLX5_GET(create_mkey_out, mkey_out->out, mkey_index));
	WRITE_ONCE(dev->cache.last_add, jiffies);

	xa_lock_irqsave(&ent->mkeys, flags);
	push_to_reserved(ent, mkey_out->mkey);
	/* If we are doing fill_to_high_water then keep going. */
	queue_adjust_cache_locked(ent);
	xa_unlock_irqrestore(&ent->mkeys, flags);
	kfree(mkey_out);
}

static int get_mkc_octo_size(unsigned int access_mode, unsigned int ndescs)
{
	int ret = 0;

	switch (access_mode) {
	case MLX5_MKC_ACCESS_MODE_MTT:
		ret = DIV_ROUND_UP(ndescs, MLX5_IB_UMR_OCTOWORD /
						   sizeof(struct mlx5_mtt));
		break;
	case MLX5_MKC_ACCESS_MODE_KSM:
		ret = DIV_ROUND_UP(ndescs, MLX5_IB_UMR_OCTOWORD /
						   sizeof(struct mlx5_klm));
		break;
	default:
		WARN_ON(1);
	}
	return ret;
}

static void set_cache_mkc(struct mlx5_cache_ent *ent, void *mkc)
{
	set_mkc_access_pd_addr_fields(mkc, ent->rb_key.access_flags, 0,
				      ent->dev->umrc.pd);
	MLX5_SET(mkc, mkc, free, 1);
	MLX5_SET(mkc, mkc, umr_en, 1);
	MLX5_SET(mkc, mkc, access_mode_1_0, ent->rb_key.access_mode & 0x3);
	MLX5_SET(mkc, mkc, access_mode_4_2,
		(ent->rb_key.access_mode >> 2) & 0x7);
	if (ent->rb_key.ats)
		MLX5_SET(mkc, mkc, ma_translation_mode, 1);

	MLX5_SET(mkc, mkc, translations_octword_size,
		 get_mkc_octo_size(ent->rb_key.access_mode,
				   ent->rb_key.ndescs));
	MLX5_SET(mkc, mkc, log_page_size, PAGE_SHIFT);
}

/* Asynchronously schedule new MRs to be populated in the cache. */
static int add_keys(struct mlx5_cache_ent *ent, unsigned int num)
{
	struct mlx5r_async_create_mkey *async_create;
	void *mkc;
	int err = 0;
	int i;

	for (i = 0; i < num; i++) {
		async_create = kzalloc(sizeof(struct mlx5r_async_create_mkey),
				       GFP_KERNEL);
		if (!async_create)
			return -ENOMEM;
		mkc = MLX5_ADDR_OF(create_mkey_in, async_create->in,
				   memory_key_mkey_entry);
		set_cache_mkc(ent, mkc);
		async_create->ent = ent;

		err = push_mkey(ent, true, NULL);
		if (err)
			goto free_async_create;

		err = mlx5_ib_create_mkey_cb(async_create);
		if (err) {
			mlx5_ib_warn(ent->dev, "create mkey failed %d\n", err);
			goto err_undo_reserve;
		}
	}

	return 0;

err_undo_reserve:
	xa_lock_irq(&ent->mkeys);
	undo_push_reserve_mkey(ent);
	xa_unlock_irq(&ent->mkeys);
free_async_create:
	kfree(async_create);
	return err;
}

/* Synchronously create a MR in the cache */
static int create_cache_mkey(struct mlx5_cache_ent *ent, u32 *mkey)
{
	size_t inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	void *mkc;
	u32 *in;
	int err;

	in = kzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	set_cache_mkc(ent, mkc);

	err = mlx5_core_create_mkey(ent->dev->mdev, mkey, in, inlen);
	if (err)
		goto free_in;

	WRITE_ONCE(ent->dev->cache.last_add, jiffies);
free_in:
	kfree(in);
	return err;
}

static void remove_cache_mr_locked(struct mlx5_cache_ent *ent)
{
	u32 mkey;

	lockdep_assert_held(&ent->mkeys.xa_lock);
	if (!ent->stored)
		return;
	mkey = pop_stored_mkey(ent);
	xa_unlock_irq(&ent->mkeys);
	mlx5_core_destroy_mkey(ent->dev->mdev, mkey);
	xa_lock_irq(&ent->mkeys);
}

static int resize_available_mrs(struct mlx5_cache_ent *ent, unsigned int target,
				bool limit_fill)
	 __acquires(&ent->mkeys) __releases(&ent->mkeys)
{
	int err;

	lockdep_assert_held(&ent->mkeys.xa_lock);

	while (true) {
		if (limit_fill)
			target = ent->limit * 2;
		if (target == ent->reserved)
			return 0;
		if (target > ent->reserved) {
			u32 todo = target - ent->reserved;

			xa_unlock_irq(&ent->mkeys);
			err = add_keys(ent, todo);
			if (err == -EAGAIN)
				usleep_range(3000, 5000);
			xa_lock_irq(&ent->mkeys);
			if (err) {
				if (err != -EAGAIN)
					return err;
			} else
				return 0;
		} else {
			remove_cache_mr_locked(ent);
		}
	}
}

struct order_attribute {
	struct attribute attr;
	ssize_t (*show)(struct cache_order *co, struct order_attribute *oa,
			char *buf);
	ssize_t (*store)(struct cache_order *co, struct order_attribute *oa,
			 const char *buf, size_t count);
};

static ssize_t cur_show(struct cache_order *co, struct order_attribute *oa,
			char *buf)
{
	struct mlx5_cache_ent *ent = container_of(co, struct mlx5_cache_ent, co);
	int err;

	err = snprintf(buf, 20, "%lu\n", ent->stored);
	return err;
}

static ssize_t miss_show(struct cache_order *co, struct order_attribute *oa,
			 char *buf)
{
	struct mlx5_cache_ent *ent = container_of(co, struct mlx5_cache_ent, co);
	int err;

	err = snprintf(buf, 20, "%d\n", ent->miss);
	return err;
}

static ssize_t miss_store(struct cache_order *co, struct order_attribute *oa,
			  const char *buf, size_t count)
{
	struct mlx5_cache_ent *ent = container_of(co, struct mlx5_cache_ent, co);
	u32 var;

	if (kstrtouint(buf, 0, &var))
		return -EINVAL;

	if (var != 0)
		return -EINVAL;

	ent->miss = var;

	return count;
}

static ssize_t size_store(struct cache_order *co, struct order_attribute *oa,
			  const char *buf, size_t count)
{
	struct mlx5_cache_ent *ent = container_of(co, struct mlx5_cache_ent, co);
	u32 target;
	int err;

	err = kstrtouint(buf, 0, &target);
	if (err)
		return err;

	/*
	 * Target is the new value of total_mrs the user requests, however we
	 * cannot free MRs that are in use. Compute the target value for stored
	 * mkeys.
	 */
	xa_lock_irq(&ent->mkeys);
	if (target < ent->in_use) {
		err = -EINVAL;
		goto err_unlock;
	}
	target = target - ent->in_use;
	if (target < ent->limit || target > ent->limit*2) {
		err = -EINVAL;
		goto err_unlock;
	}
	err = resize_available_mrs(ent, target, false);
	if (err)
		goto err_unlock;
	xa_unlock_irq(&ent->mkeys);

	return count;

err_unlock:
	xa_unlock_irq(&ent->mkeys);
	return err;
}

static ssize_t size_show(struct cache_order *co, struct order_attribute *oa,
			 char *buf)
{
	struct mlx5_cache_ent *ent = container_of(co, struct mlx5_cache_ent, co);
	int err;

	err = snprintf(buf, 20, "%ld\n", ent->stored + ent->in_use);
	return err;
}

static ssize_t limit_store(struct cache_order *co, struct order_attribute *oa,
			   const char *buf, size_t count)
{
	struct mlx5_cache_ent *ent = container_of(co, struct mlx5_cache_ent, co);
	u32 var;
	int err;

	err = kstrtouint(buf, 0, &var);
	if (err)
		return err;

	/*
	 * Upon set we immediately fill the cache to high water mark implied by
	 * the limit.
	 */
	xa_lock_irq(&ent->mkeys);
	ent->limit = var;
	err = resize_available_mrs(ent, 0, true);
	xa_unlock_irq(&ent->mkeys);
	if (err)
		return err;
	return count;
}

static ssize_t limit_show(struct cache_order *co, struct order_attribute *oa,
			  char *buf)
{
	struct mlx5_cache_ent *ent = container_of(co, struct mlx5_cache_ent, co);
	int err;

	err = snprintf(buf, 20, "%d\n", ent->limit);
	return err;
}

static bool someone_adding(struct mlx5_mkey_cache *cache)
{
	struct mlx5_cache_ent *ent;
	struct rb_node *node;
	bool ret;

	mutex_lock(&cache->rb_lock);
	for (node = rb_first(&cache->rb_root); node; node = rb_next(node)) {
		ent = rb_entry(node, struct mlx5_cache_ent, node);
		xa_lock_irq(&ent->mkeys);
		ret = ent->stored < ent->limit;
		xa_unlock_irq(&ent->mkeys);
		if (ret) {
			mutex_unlock(&cache->rb_lock);
			return true;
		}
	}
	mutex_unlock(&cache->rb_lock);
	return false;
}

/*
 * Check if the bucket is outside the high/low water mark and schedule an async
 * update. The cache refill has hysteresis, once the low water mark is hit it is
 * refilled up to the high mark.
 */
static void queue_adjust_cache_locked(struct mlx5_cache_ent *ent)
{
	lockdep_assert_held(&ent->mkeys.xa_lock);

	if (ent->disabled || READ_ONCE(ent->dev->fill_delay) || ent->is_tmp)
		return;
	if (ent->stored < ent->limit) {
		ent->fill_to_high_water = true;
		mod_delayed_work(ent->dev->cache.wq, &ent->dwork, 0);
	} else if (ent->fill_to_high_water &&
		   ent->reserved < 2 * ent->limit) {
		/*
		 * Once we start populating due to hitting a low water mark
		 * continue until we pass the high water mark.
		 */
		mod_delayed_work(ent->dev->cache.wq, &ent->dwork, 0);
	} else if (ent->stored == 2 * ent->limit) {
		ent->fill_to_high_water = false;
	} else if (ent->stored > 2 * ent->limit) {
		/* Queue deletion of excess entries */
		ent->fill_to_high_water = false;
		if (ent->stored != ent->reserved) {
			cancel_delayed_work(&ent->dwork);
			queue_delayed_work(ent->dev->cache.wq, &ent->dwork,
					   msecs_to_jiffies(1000));
		} else {
			mod_delayed_work(ent->dev->cache.wq, &ent->dwork, 0);
		}
	}
}

static ssize_t order_attr_show(struct kobject *kobj,
			       struct attribute *attr, char *buf)
{
	struct order_attribute *oa =
		container_of(attr, struct order_attribute, attr);
	struct cache_order *co = container_of(kobj, struct cache_order, kobj);

	if (!oa->show)
		return -EIO;

	return oa->show(co, oa, buf);
}

static ssize_t order_attr_store(struct kobject *kobj,
				struct attribute *attr, const char *buf, size_t size)
{
	struct order_attribute *oa =
		container_of(attr, struct order_attribute, attr);
	struct cache_order *co = container_of(kobj, struct cache_order, kobj);

	if (!oa->store)
		return -EIO;

	return oa->store(co, oa, buf, size);
}

static const struct sysfs_ops order_sysfs_ops = {
	.show = order_attr_show,
	.store = order_attr_store,
};

#define ORDER_ATTR(_name) struct order_attribute order_attr_##_name = \
	__ATTR(_name, 0644, _name##_show, _name##_store)
#define ORDER_ATTR_RO(_name) struct order_attribute order_attr_##_name = \
	__ATTR(_name, 0444, _name##_show, NULL)

static ORDER_ATTR_RO(cur);
static ORDER_ATTR(limit);
static ORDER_ATTR(miss);
static ORDER_ATTR(size);

static struct attribute *order_default_attrs[] = {
	&order_attr_cur.attr,
	&order_attr_limit.attr,
	&order_attr_miss.attr,
	&order_attr_size.attr,
	NULL
};

ATTRIBUTE_GROUPS(order_default);
static const struct kobj_type order_type = {
	.sysfs_ops     = &order_sysfs_ops,
	.default_groups = order_default_groups
};

static bool someone_releasing(struct mlx5_mkey_cache *cache)
{
	struct mlx5_cache_ent *ent;
	struct rb_node *node;
	bool ret;

	mutex_lock(&cache->rb_lock);
	for (node = rb_first(&cache->rb_root); node; node = rb_next(node)) {
		ent = rb_entry(node, struct mlx5_cache_ent, node);
		xa_lock_irq(&ent->mkeys);
		ret = ent->stored > 2 * ent->limit;
		xa_unlock_irq(&ent->mkeys);
		if (ret) {
			mutex_unlock(&cache->rb_lock);
			return true;
		}
	}
	mutex_unlock(&cache->rb_lock);
	return false;
}

static void __cache_work_func(struct mlx5_cache_ent *ent)
{
	struct mlx5_ib_dev *dev = ent->dev;
	struct mlx5_mkey_cache *cache = &dev->cache;
	s64 dtime;
	int err;

	xa_lock_irq(&ent->mkeys);
	if (ent->disabled)
		goto out;

	if (ent->fill_to_high_water && ent->reserved < 2 * ent->limit &&
	    !READ_ONCE(dev->fill_delay)) {
		xa_unlock_irq(&ent->mkeys);
		err = add_keys(ent, 1);
		xa_lock_irq(&ent->mkeys);
		if (ent->disabled)
			goto out;
		if (err) {
			/*
			 * EAGAIN only happens if there are pending MRs, so we
			 * will be rescheduled when storing them. The only
			 * failure path here is ENOMEM.
			 */
			if (err != -EAGAIN) {
				mlx5_ib_warn(
					dev,
					"add keys command failed, err %d\n",
					err);
				cancel_delayed_work(&ent->dwork);
				queue_delayed_work(cache->wq, &ent->dwork,
						   msecs_to_jiffies(1000));
			}
		}
	} else if (ent->stored > 2 * ent->limit) {
		bool need_delay;

		/*
		 * The remove_cache_mr() logic is performed as garbage
		 * collection task. Such task is intended to be run when no
		 * other active processes are running.
		 *
		 * The need_resched() will return TRUE if there are user tasks
		 * to be activated in near future.
		 *
		 * In such case, we don't execute remove_cache_mr() and postpone
		 * the garbage collection work to try to run in next cycle, in
		 * order to free CPU resources to other tasks.
		 */
		xa_unlock_irq(&ent->mkeys);
		dtime = (cache->last_add + (s64)cache->rel_timeout * HZ) -
			jiffies;
		need_delay = cache->rel_imm || (!need_resched() &&
		    cache->rel_timeout >= 0 && !someone_adding(cache) &&
		    dtime <= 0);
		xa_lock_irq(&ent->mkeys);
		if (ent->disabled)
			goto out;
		if (!need_delay && cache->rel_timeout >= 0) {
			dtime = max_t(s64, dtime, msecs_to_jiffies(3));
			dtime = min_t(s64, dtime, (MAX_MR_RELEASE_TIMEOUT * HZ));
			cancel_delayed_work(&ent->dwork);
			queue_delayed_work(cache->wq, &ent->dwork, dtime);
			goto out;
		}
		remove_cache_mr_locked(ent);
		queue_adjust_cache_locked(ent);
	} else if (cache->rel_imm) {
		xa_unlock_irq(&ent->mkeys);
		if (!someone_releasing(cache))
			cache->rel_imm = 0;
		xa_lock_irq(&ent->mkeys);
	}
out:
	xa_unlock_irq(&ent->mkeys);
}

static void delayed_cache_work_func(struct work_struct *work)
{
	struct mlx5_cache_ent *ent;

	ent = container_of(work, struct mlx5_cache_ent, dwork.work);
	__cache_work_func(ent);
}

static int cache_ent_key_cmp(struct mlx5r_cache_rb_key key1,
			     struct mlx5r_cache_rb_key key2)
{
	int res;

	res = key1.ats - key2.ats;
	if (res)
		return res;

	res = key1.access_mode - key2.access_mode;
	if (res)
		return res;

	res = key1.access_flags - key2.access_flags;
	if (res)
		return res;

	/*
	 * keep ndescs the last in the compare table since the find function
	 * searches for an exact match on all properties and only closest
	 * match in size.
	 */
	return key1.ndescs - key2.ndescs;
}

static int mlx5_cache_ent_insert(struct mlx5_mkey_cache *cache,
				 struct mlx5_cache_ent *ent)
{
	struct rb_node **new = &cache->rb_root.rb_node, *parent = NULL;
	struct mlx5_cache_ent *cur;
	int cmp;

	/* Figure out where to put new node */
	while (*new) {
		cur = rb_entry(*new, struct mlx5_cache_ent, node);
		parent = *new;
		cmp = cache_ent_key_cmp(cur->rb_key, ent->rb_key);
		if (cmp > 0)
			new = &((*new)->rb_left);
		if (cmp < 0)
			new = &((*new)->rb_right);
		if (cmp == 0)
			return -EEXIST;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&ent->node, parent, new);
	rb_insert_color(&ent->node, &cache->rb_root);

	return 0;
}

static struct mlx5_cache_ent *
mkey_cache_ent_from_rb_key(struct mlx5_ib_dev *dev,
			   struct mlx5r_cache_rb_key rb_key)
{
	struct rb_node *node = dev->cache.rb_root.rb_node;
	struct mlx5_cache_ent *cur, *smallest = NULL;
	int cmp;

	/*
	 * Find the smallest ent with order >= requested_order.
	 */
	while (node) {
		cur = rb_entry(node, struct mlx5_cache_ent, node);
		cmp = cache_ent_key_cmp(cur->rb_key, rb_key);
		if (cmp > 0) {
			smallest = cur;
			node = node->rb_left;
		}
		if (cmp < 0)
			node = node->rb_right;
		if (cmp == 0)
			return cur;
	}

	return (smallest &&
		smallest->rb_key.access_mode == rb_key.access_mode &&
		smallest->rb_key.access_flags == rb_key.access_flags &&
		smallest->rb_key.ats == rb_key.ats &&
		smallest->rb_key.ndescs <= 2 * rb_key.ndescs) ?
		       smallest :
		       NULL;
}

static struct mlx5_ib_mr *_mlx5_mr_cache_alloc(struct mlx5_ib_dev *dev,
					struct mlx5_cache_ent *ent,
					int access_flags)
{
	struct mlx5_ib_mr *mr;
	int err;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	xa_lock_irq(&ent->mkeys);
	ent->in_use++;

	if (!ent->stored) {
		queue_adjust_cache_locked(ent);
		ent->miss++;
		xa_unlock_irq(&ent->mkeys);
		err = create_cache_mkey(ent, &mr->mmkey.key);
		if (err) {
			xa_lock_irq(&ent->mkeys);
			ent->in_use--;
			xa_unlock_irq(&ent->mkeys);
			kfree(mr);
			return ERR_PTR(err);
		}
	} else {
		mr->mmkey.key = pop_stored_mkey(ent);
		queue_adjust_cache_locked(ent);
		xa_unlock_irq(&ent->mkeys);
	}
	mr->mmkey.cache_ent = ent;
	mr->mmkey.type = MLX5_MKEY_MR;
	mr->mmkey.rb_key = ent->rb_key;
	mr->mmkey.cacheable = true;
	init_waitqueue_head(&mr->mmkey.wait);
	return mr;
}

static int get_unchangeable_access_flags(struct mlx5_ib_dev *dev,
					 int access_flags)
{
	int ret = 0;

	if ((access_flags & IB_ACCESS_REMOTE_ATOMIC) &&
	    MLX5_CAP_GEN(dev->mdev, atomic) &&
	    MLX5_CAP_GEN(dev->mdev, umr_modify_atomic_disabled))
		ret |= IB_ACCESS_REMOTE_ATOMIC;

	if ((access_flags & IB_ACCESS_RELAXED_ORDERING) &&
	    MLX5_CAP_GEN(dev->mdev, relaxed_ordering_write) &&
	    !MLX5_CAP_GEN(dev->mdev, relaxed_ordering_write_umr))
		ret |= IB_ACCESS_RELAXED_ORDERING;

	if ((access_flags & IB_ACCESS_RELAXED_ORDERING) &&
	    MLX5_CAP_GEN(dev->mdev, relaxed_ordering_read) &&
	    !MLX5_CAP_GEN(dev->mdev, relaxed_ordering_read_umr))
		ret |= IB_ACCESS_RELAXED_ORDERING;

	return ret;
}

struct mlx5_ib_mr *mlx5_mr_cache_alloc(struct mlx5_ib_dev *dev,
				       int access_flags, int access_mode,
				       int ndescs)
{
	struct mlx5r_cache_rb_key rb_key = {
		.ndescs = ndescs,
		.access_mode = access_mode,
		.access_flags = get_unchangeable_access_flags(dev, access_flags)
	};
	struct mlx5_cache_ent *ent = mkey_cache_ent_from_rb_key(dev, rb_key);

	if (!ent)
		return ERR_PTR(-EOPNOTSUPP);

	return _mlx5_mr_cache_alloc(dev, ent, access_flags);
}

static void clean_keys(struct mlx5_ib_dev *dev, struct mlx5_cache_ent *ent)
{
	u32 mkey;

	cancel_delayed_work(&ent->dwork);
	xa_lock_irq(&ent->mkeys);
	while (ent->stored) {
		mkey = pop_stored_mkey(ent);
		xa_unlock_irq(&ent->mkeys);
		mlx5_core_destroy_mkey(dev->mdev, mkey);
		xa_lock_irq(&ent->mkeys);
	}
	xa_unlock_irq(&ent->mkeys);
}

static void delay_time_func(struct timer_list *t)
{
	struct mlx5_ib_dev *dev = from_timer(dev, t, delay_timer);

	WRITE_ONCE(dev->fill_delay, 0);
}

struct mlx5_cache_ent *
mlx5r_cache_create_ent_locked(struct mlx5_ib_dev *dev,
			      struct mlx5r_cache_rb_key rb_key,
			      bool persistent_entry)
{
	struct mlx5_cache_ent *ent;
	int order;
	int ret;

	ent = kzalloc(sizeof(*ent), GFP_KERNEL);
	if (!ent)
		return ERR_PTR(-ENOMEM);

	xa_init_flags(&ent->mkeys, XA_FLAGS_LOCK_IRQ);
	ent->rb_key = rb_key;
	ent->dev = dev;
	ent->is_tmp = !persistent_entry;

	INIT_DELAYED_WORK(&ent->dwork, delayed_cache_work_func);

	ret = mlx5_cache_ent_insert(&dev->cache, ent);
	if (ret) {
		kfree(ent);
		return ERR_PTR(ret);
	}

	if (persistent_entry) {
		if (rb_key.access_mode == MLX5_MKC_ACCESS_MODE_KSM)
			order = MLX5_IMR_KSM_CACHE_ENTRY;
		else
			order = order_base_2(rb_key.ndescs) - 2;

		if ((dev->mdev->profile.mask & MLX5_PROF_MASK_MR_CACHE) &&
		    !dev->is_rep && mlx5_core_is_pf(dev->mdev) &&
		    mlx5r_umr_can_load_pas(dev, 0))
			ent->limit = dev->mdev->profile.mr_cache[order].limit;
		else
			ent->limit = 0;

		mlx5_mkey_cache_sysfs_add_ent(dev, ent);
	}

	return ent;
}

static void remove_ent_work_func(struct work_struct *work)
{
	struct mlx5_mkey_cache *cache;
	struct mlx5_cache_ent *ent;
	struct rb_node *cur;

	cache = container_of(work, struct mlx5_mkey_cache,
			     remove_ent_dwork.work);
	mutex_lock(&cache->rb_lock);
	cur = rb_last(&cache->rb_root);
	while (cur) {
		ent = rb_entry(cur, struct mlx5_cache_ent, node);
		cur = rb_prev(cur);
		mutex_unlock(&cache->rb_lock);

		xa_lock_irq(&ent->mkeys);
		if (!ent->is_tmp) {
			xa_unlock_irq(&ent->mkeys);
			mutex_lock(&cache->rb_lock);
			continue;
		}
		xa_unlock_irq(&ent->mkeys);

		clean_keys(ent->dev, ent);
		mutex_lock(&cache->rb_lock);
	}
	cache->tmp_clean = true;
	mutex_unlock(&cache->rb_lock);
}

int mlx5_mkey_cache_init(struct mlx5_ib_dev *dev)
{
	struct mlx5_mkey_cache *cache = &dev->cache;
	struct rb_root *root = &dev->cache.rb_root;
	struct mlx5r_cache_rb_key rb_key = {
		.access_mode = MLX5_MKC_ACCESS_MODE_MTT,
	};
	struct mlx5_cache_ent *ent, *del_entry;
	struct rb_node *node;
	int ret;
	int i;

	mutex_init(&dev->slow_path_mutex);
	mutex_init(&dev->cache.rb_lock);
	dev->cache.rb_root = RB_ROOT;
	INIT_DELAYED_WORK(&dev->cache.remove_ent_dwork, remove_ent_work_func);
	cache->rel_timeout = 300;
	cache->wq = alloc_ordered_workqueue("mkey_cache", WQ_MEM_RECLAIM);
	if (!cache->wq) {
		mlx5_ib_warn(dev, "failed to create work queue\n");
		return -ENOMEM;
	}

	mlx5_cmd_init_async_ctx(dev->mdev, &dev->async_ctx);
	timer_setup(&dev->delay_timer, delay_time_func, 0);
	mlx5_mkey_cache_sysfs_init(dev);
	mutex_lock(&cache->rb_lock);
	for (i = 0; i <= mkey_cache_max_order(dev); i++) {
		rb_key.ndescs = 1 << (i + 2);
		ent = mlx5r_cache_create_ent_locked(dev, rb_key, true);
		if (IS_ERR(ent)) {
			ret = PTR_ERR(ent);
			goto err;
		}
	}

	ret = mlx5_odp_init_mkey_cache(dev);
	if (ret)
		goto err;

	cache->tmp_clean = true;
	mutex_unlock(&cache->rb_lock);
	for (node = rb_first(root); node; node = rb_next(node)) {
		ent = rb_entry(node, struct mlx5_cache_ent, node);
		xa_lock_irq(&ent->mkeys);
		queue_adjust_cache_locked(ent);
		xa_unlock_irq(&ent->mkeys);
	}

	return 0;

err:
	mutex_unlock(&cache->rb_lock);
	for (node = rb_first(root); node; node = rb_next(node)) {
		del_entry = rb_entry(node, struct mlx5_cache_ent, node);
		mlx5_mkey_cache_sysfs_ent_cleanup(del_entry);
	}

	mlx5_mkey_cache_sysfs_cleanup(dev);
	mlx5_ib_warn(dev, "failed to create mkey cache entry\n");
	return ret;
}

void mlx5_mkey_cache_cleanup(struct mlx5_ib_dev *dev)
{
	struct rb_root *root = &dev->cache.rb_root;
	struct mlx5_cache_ent *ent;
	struct rb_node *node;

	if (!dev->cache.wq)
		return;

	mutex_lock(&dev->cache.rb_lock);
	cancel_delayed_work(&dev->cache.remove_ent_dwork);
	for (node = rb_first(root); node; node = rb_next(node)) {
		ent = rb_entry(node, struct mlx5_cache_ent, node);
		xa_lock_irq(&ent->mkeys);
		ent->disabled = true;
		xa_unlock_irq(&ent->mkeys);
		cancel_delayed_work(&ent->dwork);
		mlx5_mkey_cache_sysfs_ent_cleanup(ent);
	}
	mutex_unlock(&dev->cache.rb_lock);

	/*
	 * After all entries are disabled and will not reschedule on WQ,
	 * flush it and all async commands.
	 */
	flush_workqueue(dev->cache.wq);

	mlx5_mkey_cache_sysfs_cleanup(dev);
	mlx5_cmd_cleanup_async_ctx(&dev->async_ctx);

	/* At this point all entries are disabled and have no concurrent work. */
	mutex_lock(&dev->cache.rb_lock);
	node = rb_first(root);
	while (node) {
		ent = rb_entry(node, struct mlx5_cache_ent, node);
		node = rb_next(node);
		clean_keys(dev, ent);
		rb_erase(&ent->node, root);
		kfree(ent);
	}
	mutex_unlock(&dev->cache.rb_lock);

	destroy_workqueue(dev->cache.wq);
	del_timer_sync(&dev->delay_timer);
}

struct ib_mr *mlx5_ib_get_dma_mr(struct ib_pd *pd, int acc)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	struct mlx5_ib_mr *mr;
	void *mkc;
	u32 *in;
	int err;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	in = kzalloc(inlen, GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_free;
	}

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);

	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_PA);
	MLX5_SET(mkc, mkc, length64, 1);
	set_mkc_access_pd_addr_fields(mkc, acc | IB_ACCESS_RELAXED_ORDERING, 0,
				      pd);

#ifdef CONFIG_GPU_DIRECT_STORAGE
	MLX5_SET(mkc, mkc, ma_translation_mode, MLX5_CAP_GEN(dev->mdev, ats));
#endif

	err = mlx5_ib_create_mkey(dev, &mr->mmkey, in, inlen);
	if (err)
		goto err_in;

	kfree(in);
	mr->mmkey.type = MLX5_MKEY_MR;
	mr->ibmr.lkey = mr->mmkey.key;
	mr->ibmr.rkey = mr->mmkey.key;
	mr->umem = NULL;

	return &mr->ibmr;

err_in:
	kfree(in);

err_free:
	kfree(mr);

	return ERR_PTR(err);
}

static int get_octo_len(u64 addr, u64 len, int page_shift)
{
	u64 page_size = 1ULL << page_shift;
	u64 offset;
	int npages;

	offset = addr & (page_size - 1);
	npages = ALIGN(len + offset, page_size) >> page_shift;
	return (npages + 1) / 2;
}

static int mkey_cache_max_order(struct mlx5_ib_dev *dev)
{
	if (MLX5_CAP_GEN(dev->mdev, umr_extended_translation_offset))
		return MKEY_CACHE_LAST_STD_ENTRY;
	return MLX5_MAX_UMR_SHIFT;
}

static void set_mr_fields(struct mlx5_ib_dev *dev, struct mlx5_ib_mr *mr,
			  u64 length, int access_flags, u64 iova)
{
	mr->ibmr.lkey = mr->mmkey.key;
	mr->ibmr.rkey = mr->mmkey.key;
	mr->ibmr.length = length;
	mr->ibmr.device = &dev->ib_dev;
	mr->ibmr.iova = iova;
	mr->access_flags = access_flags;
}

static unsigned int mlx5_umem_dmabuf_default_pgsz(struct ib_umem *umem,
						  u64 iova)
{
	/*
	 * The alignment of iova has already been checked upon entering
	 * UVERBS_METHOD_REG_DMABUF_MR
	 */
	umem->iova = iova;
	return PAGE_SIZE;
}

static struct mlx5_ib_mr *alloc_cacheable_mr(struct ib_pd *pd,
					     struct ib_umem *umem, u64 iova,
					     int access_flags)
{
	struct mlx5r_cache_rb_key rb_key = {
		.access_mode = MLX5_MKC_ACCESS_MODE_MTT,
	};
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_cache_ent *ent;
	struct mlx5_ib_mr *mr;
	unsigned int page_size;

	if (umem->is_dmabuf)
		page_size = mlx5_umem_dmabuf_default_pgsz(umem, iova);
	else
		page_size = mlx5_umem_find_best_pgsz(umem, mkc, log_page_size,
						     0, iova);
	if (WARN_ON(!page_size))
		return ERR_PTR(-EINVAL);

	rb_key.ndescs = ib_umem_num_dma_blocks(umem, page_size);
	rb_key.ats = mlx5_umem_needs_ats(dev, umem, access_flags);
	rb_key.access_flags = get_unchangeable_access_flags(dev, access_flags);
	ent = mkey_cache_ent_from_rb_key(dev, rb_key);
	/*
	 * If the MR can't come from the cache then synchronously create an uncached
	 * one.
	 */
	if (!ent) {
		mutex_lock(&dev->slow_path_mutex);
		mr = reg_create(pd, umem, iova, access_flags, page_size, false);
		mutex_unlock(&dev->slow_path_mutex);
		if (IS_ERR(mr))
			return mr;
		mr->mmkey.rb_key = rb_key;
		mr->mmkey.cacheable = true;
		return mr;
	}

	mr = _mlx5_mr_cache_alloc(dev, ent, access_flags);
	if (IS_ERR(mr))
		return mr;

	mr->ibmr.pd = pd;
	mr->umem = umem;
	mr->page_shift = order_base_2(page_size);
	set_mr_fields(dev, mr, umem->length, access_flags, iova);

	return mr;
}

/*
 * If ibmr is NULL it will be allocated by reg_create.
 * Else, the given ibmr will be used.
 */
static struct mlx5_ib_mr *reg_create(struct ib_pd *pd, struct ib_umem *umem,
				     u64 iova, int access_flags,
				     unsigned int page_size, bool populate)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_ib_mr *mr;
	__be64 *pas;
	void *mkc;
	int inlen;
	u32 *in;
	int err;
	bool pg_cap = !!(MLX5_CAP_GEN(dev->mdev, pg));

	if (!page_size)
		return ERR_PTR(-EINVAL);
	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	mr->ibmr.pd = pd;
	mr->access_flags = access_flags;
	mr->page_shift = order_base_2(page_size);

	inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	if (populate)
		inlen += sizeof(*pas) *
			 roundup(ib_umem_num_dma_blocks(umem, page_size), 2);
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_1;
	}
	pas = (__be64 *)MLX5_ADDR_OF(create_mkey_in, in, klm_pas_mtt);
	if (populate) {
		if (WARN_ON(access_flags & IB_ACCESS_ON_DEMAND)) {
			err = -EINVAL;
			goto err_2;
		}
		mlx5_ib_populate_pas(umem, 1UL << mr->page_shift, pas,
				     pg_cap ? MLX5_IB_MTT_PRESENT : 0);
	}

	/* The pg_access bit allows setting the access flags
	 * in the page list submitted with the command. */
	MLX5_SET(create_mkey_in, in, pg_access, !!(pg_cap));

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	set_mkc_access_pd_addr_fields(mkc, access_flags, iova,
				      populate ? pd : dev->umrc.pd);
	MLX5_SET(mkc, mkc, free, !populate);
	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_MTT);
	MLX5_SET(mkc, mkc, umr_en, 1);

	MLX5_SET64(mkc, mkc, len, umem->length);
	MLX5_SET(mkc, mkc, bsf_octword_size, 0);
	MLX5_SET(mkc, mkc, translations_octword_size,
		 get_octo_len(iova, umem->length, mr->page_shift));
	MLX5_SET(mkc, mkc, log_page_size, mr->page_shift);
	if (mlx5_umem_needs_ats(dev, umem, access_flags))
		MLX5_SET(mkc, mkc, ma_translation_mode, 1);

	if (populate) {
		MLX5_SET(create_mkey_in, in, translations_octword_actual_size,
			 get_octo_len(iova, umem->length, mr->page_shift));
	}

	err = mlx5_ib_create_mkey(dev, &mr->mmkey, in, inlen);
	if (err) {
		mlx5_ib_warn(dev, "create mkey failed\n");
		goto err_2;
	}
	mr->mmkey.type = MLX5_MKEY_MR;
	mr->mmkey.ndescs = get_octo_len(iova, umem->length, mr->page_shift);
	mr->umem = umem;
	set_mr_fields(dev, mr, umem->length, access_flags, iova);
	kvfree(in);

	mlx5_ib_dbg(dev, "mkey = 0x%x\n", mr->mmkey.key);

	return mr;

err_2:
	kvfree(in);
err_1:
	kfree(mr);
	return ERR_PTR(err);
}

static struct ib_mr *mlx5_ib_get_dm_mr(struct ib_pd *pd, u64 start_addr,
				       u64 length, int acc, int mode)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	struct mlx5_ib_mr *mr;
	void *mkc;
	u32 *in;
	int err;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	in = kzalloc(inlen, GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_free;
	}

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);

	MLX5_SET(mkc, mkc, access_mode_1_0, mode & 0x3);
	MLX5_SET(mkc, mkc, access_mode_4_2, (mode >> 2) & 0x7);
	MLX5_SET64(mkc, mkc, len, length);
	set_mkc_access_pd_addr_fields(mkc, acc, start_addr, pd);

	err = mlx5_ib_create_mkey(dev, &mr->mmkey, in, inlen);
	if (err)
		goto err_in;

	kfree(in);

	set_mr_fields(dev, mr, length, acc, start_addr);

	return &mr->ibmr;

err_in:
	kfree(in);

err_free:
	kfree(mr);

	return ERR_PTR(err);
}

int mlx5_ib_advise_mr(struct ib_pd *pd,
		      enum ib_uverbs_advise_mr_advice advice,
		      u32 flags,
		      struct ib_sge *sg_list,
		      u32 num_sge,
		      struct uverbs_attr_bundle *attrs)
{
	if (advice != IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH &&
	    advice != IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE &&
	    advice != IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_NO_FAULT)
		return -EOPNOTSUPP;

	return mlx5_ib_advise_mr_prefetch(pd, advice, flags,
					 sg_list, num_sge);
}

struct ib_mr *mlx5_ib_reg_dm_mr(struct ib_pd *pd, struct ib_dm *dm,
				struct ib_dm_mr_attr *attr,
				struct uverbs_attr_bundle *attrs)
{
	struct mlx5_ib_dm *mdm = to_mdm(dm);
	struct mlx5_core_dev *dev = to_mdev(dm->device)->mdev;
	u64 start_addr = mdm->dev_addr + attr->offset;
	int mode;

	switch (mdm->type) {
	case MLX5_IB_UAPI_DM_TYPE_MEMIC:
		if (attr->access_flags & ~MLX5_IB_DM_MEMIC_ALLOWED_ACCESS)
			return ERR_PTR(-EINVAL);

		mode = MLX5_MKC_ACCESS_MODE_MEMIC;
		start_addr -= pci_resource_start(dev->pdev, 0);
		break;
	case MLX5_IB_UAPI_DM_TYPE_STEERING_SW_ICM:
	case MLX5_IB_UAPI_DM_TYPE_HEADER_MODIFY_SW_ICM:
	case MLX5_IB_UAPI_DM_TYPE_HEADER_MODIFY_PATTERN_SW_ICM:
	case MLX5_IB_UAPI_DM_TYPE_ENCAP_SW_ICM:
		if (attr->access_flags & ~MLX5_IB_DM_SW_ICM_ALLOWED_ACCESS)
			return ERR_PTR(-EINVAL);

		mode = MLX5_MKC_ACCESS_MODE_SW_ICM;
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	return mlx5_ib_get_dm_mr(pd, start_addr, attr->length,
				 attr->access_flags, mode);
}

static struct ib_mr *create_real_mr(struct ib_pd *pd, struct ib_umem *umem,
				    u64 iova, int access_flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_ib_mr *mr = NULL;
	bool xlt_with_umr;
	int err;

	xlt_with_umr = mlx5r_umr_can_load_pas(dev, umem->length);
	if (xlt_with_umr && !umem->is_peer) {
		mr = alloc_cacheable_mr(pd, umem, iova, access_flags);
	} else {
		unsigned int page_size = mlx5_umem_find_best_pgsz(
			umem, mkc, log_page_size, 0, iova);

		mutex_lock(&dev->slow_path_mutex);
		mr = reg_create(pd, umem, iova, access_flags, page_size,
				!xlt_with_umr);
		mutex_unlock(&dev->slow_path_mutex);
	}
	if (IS_ERR(mr)) {
		if (umem->is_peer)
			ib_umem_stop_invalidation_notifier(umem);
		ib_umem_release(umem);
		return ERR_CAST(mr);
	}

	mlx5_ib_dbg(dev, "mkey 0x%x\n", mr->mmkey.key);

	atomic_add(ib_umem_num_pages(umem), &dev->mdev->priv.reg_pages);

	if (xlt_with_umr) {
		/*
		 * If the MR was created with reg_create then it will be
		 * configured properly but left disabled. It is safe to go ahead
		 * and configure it again via UMR while enabling it.
		 */
		err = mlx5r_umr_update_mr_pas(mr, MLX5_IB_UPD_XLT_ENABLE);
		if (err) {
			mlx5_ib_dereg_mr(&mr->ibmr, NULL);
			return ERR_PTR(err);
		}
	}

	if (umem->is_peer)
		ib_umem_activate_invalidation_notifier(
			umem, mlx5_invalidate_umem, mr);

	return &mr->ibmr;
}

static struct ib_mr *create_user_odp_mr(struct ib_pd *pd, u64 start, u64 length,
					u64 iova, int access_flags,
					struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct ib_umem_odp *odp;
	struct mlx5_ib_mr *mr;
	int err;

	if (!IS_ENABLED(CONFIG_INFINIBAND_ON_DEMAND_PAGING))
		return ERR_PTR(-EOPNOTSUPP);

	err = mlx5r_odp_create_eq(dev, &dev->odp_pf_eq);
	if (err)
		return ERR_PTR(err);
	if (!start && length == U64_MAX) {
		if (iova != 0)
			return ERR_PTR(-EINVAL);
		if (!(dev->odp_caps.general_caps & IB_ODP_SUPPORT_IMPLICIT))
			return ERR_PTR(-EINVAL);

		mr = mlx5_ib_alloc_implicit_mr(to_mpd(pd), access_flags);
		if (IS_ERR(mr))
			return ERR_CAST(mr);
		return &mr->ibmr;
	}

	/* ODP requires xlt update via umr to work. */
	if (!mlx5r_umr_can_load_pas(dev, length))
		return ERR_PTR(-EINVAL);

	odp = ib_umem_odp_get(&dev->ib_dev, start, length, access_flags,
			      &mlx5_mn_ops);
	if (IS_ERR(odp))
		return ERR_CAST(odp);

	mr = alloc_cacheable_mr(pd, &odp->umem, iova, access_flags);
	if (IS_ERR(mr)) {
		ib_umem_release(&odp->umem);
		return ERR_CAST(mr);
	}
	xa_init(&mr->implicit_children);

	odp->private = mr;
	err = mlx5r_store_odp_mkey(dev, &mr->mmkey);
	if (err)
		goto err_dereg_mr;

	err = mlx5_ib_init_odp_mr(mr);
	if (err)
		goto err_dereg_mr;
	return &mr->ibmr;

err_dereg_mr:
	mlx5_ib_dereg_mr(&mr->ibmr, NULL);
	return ERR_PTR(err);
}

struct ib_mr *mlx5_ib_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				  u64 iova, int access_flags,
				  struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct ib_umem *umem;

	if (!IS_ENABLED(CONFIG_INFINIBAND_USER_MEM))
		return ERR_PTR(-EOPNOTSUPP);

	mlx5_ib_dbg(dev, "start 0x%llx, iova 0x%llx, length 0x%llx, access_flags 0x%x\n",
		    start, iova, length, access_flags);

	if ((access_flags & IB_ACCESS_ON_DEMAND) && (dev->profile != &raw_eth_profile))
		return create_user_odp_mr(pd, start, length, iova, access_flags,
					  udata);
	umem = ib_umem_get_peer(&dev->ib_dev, start, length, access_flags,
				IB_PEER_MEM_INVAL_SUPP);
	if (IS_ERR(umem))
		return ERR_CAST(umem);
	return create_real_mr(pd, umem, iova, access_flags);
}

static void mlx5_ib_dmabuf_invalidate_cb(struct dma_buf_attachment *attach)
{
	struct ib_umem_dmabuf *umem_dmabuf = attach->importer_priv;
	struct mlx5_ib_mr *mr = umem_dmabuf->private;

	dma_resv_assert_held(umem_dmabuf->attach->dmabuf->resv);

	if (!umem_dmabuf->sgt)
		return;

	mlx5r_umr_update_mr_pas(mr, MLX5_IB_UPD_XLT_ZAP);
	ib_umem_dmabuf_unmap_pages(umem_dmabuf);
}

static struct dma_buf_attach_ops mlx5_ib_dmabuf_attach_ops = {
	.allow_peer2peer = 1,
	.move_notify = mlx5_ib_dmabuf_invalidate_cb,
};

struct ib_mr *mlx5_ib_reg_user_mr_dmabuf(struct ib_pd *pd, u64 offset,
					 u64 length, u64 virt_addr,
					 int fd, int access_flags,
					 struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_ib_mr *mr = NULL;
	struct ib_umem_dmabuf *umem_dmabuf;
	int err;

	if (!IS_ENABLED(CONFIG_INFINIBAND_USER_MEM) ||
	    !IS_ENABLED(CONFIG_INFINIBAND_ON_DEMAND_PAGING))
		return ERR_PTR(-EOPNOTSUPP);

	mlx5_ib_dbg(dev,
		    "offset 0x%llx, virt_addr 0x%llx, length 0x%llx, fd %d, access_flags 0x%x\n",
		    offset, virt_addr, length, fd, access_flags);

	/* dmabuf requires xlt update via umr to work. */
	if (!mlx5r_umr_can_load_pas(dev, length))
		return ERR_PTR(-EINVAL);

	umem_dmabuf = ib_umem_dmabuf_get(&dev->ib_dev, offset, length, fd,
					 access_flags,
					 &mlx5_ib_dmabuf_attach_ops);
	if (IS_ERR(umem_dmabuf)) {
		mlx5_ib_dbg(dev, "umem_dmabuf get failed (%ld)\n",
			    PTR_ERR(umem_dmabuf));
		return ERR_CAST(umem_dmabuf);
	}

	mr = alloc_cacheable_mr(pd, &umem_dmabuf->umem, virt_addr,
				access_flags);
	if (IS_ERR(mr)) {
		ib_umem_release(&umem_dmabuf->umem);
		return ERR_CAST(mr);
	}

	mlx5_ib_dbg(dev, "mkey 0x%x\n", mr->mmkey.key);

	atomic_add(ib_umem_num_pages(mr->umem), &dev->mdev->priv.reg_pages);
	umem_dmabuf->private = mr;
	err = mlx5r_store_odp_mkey(dev, &mr->mmkey);
	if (err)
		goto err_dereg_mr;

	err = mlx5_ib_init_dmabuf_mr(mr);
	if (err)
		goto err_dereg_mr;
	return &mr->ibmr;

err_dereg_mr:
	mlx5_ib_dereg_mr(&mr->ibmr, NULL);
	return ERR_PTR(err);
}

/*
 * True if the change in access flags can be done via UMR, only some access
 * flags can be updated.
 */
static bool can_use_umr_rereg_access(struct mlx5_ib_dev *dev,
				     unsigned int current_access_flags,
				     unsigned int target_access_flags)
{
	unsigned int diffs = current_access_flags ^ target_access_flags;

	if (diffs & ~(IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE |
		      IB_ACCESS_REMOTE_READ | IB_ACCESS_RELAXED_ORDERING |
		      IB_ACCESS_REMOTE_ATOMIC))
		return false;
	return mlx5r_umr_can_reconfig(dev, current_access_flags,
				      target_access_flags);
}

static bool can_use_umr_rereg_pas(struct mlx5_ib_mr *mr,
				  struct ib_umem *new_umem,
				  int new_access_flags, u64 iova,
				  unsigned long *page_size)
{
	struct mlx5_ib_dev *dev = to_mdev(mr->ibmr.device);

	/* We only track the allocated sizes of MRs from the cache */
	if (!mr->mmkey.cache_ent)
		return false;
	if (!mlx5r_umr_can_load_pas(dev, new_umem->length))
		return false;

	*page_size =
		mlx5_umem_find_best_pgsz(new_umem, mkc, log_page_size, 0, iova);
	if (WARN_ON(!*page_size))
		return false;
	return (mr->mmkey.cache_ent->rb_key.ndescs) >=
	       ib_umem_num_dma_blocks(new_umem, *page_size);
}

static int umr_rereg_pas(struct mlx5_ib_mr *mr, struct ib_pd *pd,
			 int access_flags, int flags, struct ib_umem *new_umem,
			 u64 iova, unsigned long page_size)
{
	struct mlx5_ib_dev *dev = to_mdev(mr->ibmr.device);
	int upd_flags = MLX5_IB_UPD_XLT_ADDR | MLX5_IB_UPD_XLT_ENABLE;
	struct ib_umem *old_umem = mr->umem;
	int err;

	/*
	 * To keep everything simple the MR is revoked before we start to mess
	 * with it. This ensure the change is atomic relative to any use of the
	 * MR.
	 */
	err = mlx5r_umr_revoke_mr(mr);
	if (err)
		return err;

	if (flags & IB_MR_REREG_PD) {
		mr->ibmr.pd = pd;
		upd_flags |= MLX5_IB_UPD_XLT_PD;
	}
	if (flags & IB_MR_REREG_ACCESS) {
		mr->access_flags = access_flags;
		upd_flags |= MLX5_IB_UPD_XLT_ACCESS;
	}

	mr->ibmr.iova = iova;
	mr->ibmr.length = new_umem->length;
	mr->page_shift = order_base_2(page_size);
	mr->umem = new_umem;
	err = mlx5r_umr_update_mr_pas(mr, upd_flags);
	if (err) {
		/*
		 * The MR is revoked at this point so there is no issue to free
		 * new_umem.
		 */
		mr->umem = old_umem;
		return err;
	}

	if (new_umem->is_peer)
		ib_umem_activate_invalidation_notifier(
			new_umem, mlx5_invalidate_umem, mr);

	atomic_sub(ib_umem_num_pages(old_umem), &dev->mdev->priv.reg_pages);
	ib_umem_release(old_umem);
	atomic_add(ib_umem_num_pages(new_umem), &dev->mdev->priv.reg_pages);
	return 0;
}

struct ib_mr *mlx5_ib_rereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start,
				    u64 length, u64 iova, int new_access_flags,
				    struct ib_pd *new_pd,
				    struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(ib_mr->device);
	struct mlx5_ib_mr *mr = to_mmr(ib_mr);
	int err;

	if (!IS_ENABLED(CONFIG_INFINIBAND_USER_MEM))
		return ERR_PTR(-EOPNOTSUPP);

	mlx5_ib_dbg(
		dev,
		"start 0x%llx, iova 0x%llx, length 0x%llx, access_flags 0x%x\n",
		start, iova, length, new_access_flags);

	if (flags & ~(IB_MR_REREG_TRANS | IB_MR_REREG_PD | IB_MR_REREG_ACCESS))
		return ERR_PTR(-EOPNOTSUPP);

	if (!(flags & IB_MR_REREG_ACCESS))
		new_access_flags = mr->access_flags;
	if (!(flags & IB_MR_REREG_PD))
		new_pd = ib_mr->pd;

	if (!(flags & IB_MR_REREG_TRANS)) {
		struct ib_umem *umem;

		/* Fast path for PD/access change */
		if (can_use_umr_rereg_access(dev, mr->access_flags,
					     new_access_flags)) {
			err = mlx5r_umr_rereg_pd_access(mr, new_pd,
							new_access_flags);
			if (err)
				return ERR_PTR(err);
			return NULL;
		}
		/*
		 * DM or ODP MR's don't have a normal umem so we can't re-use it.
		 * Peer umems cannot have their MR's changed once created due
		 * to races with invalidation.
		 */
		if (!mr->umem || is_odp_mr(mr) || is_dmabuf_mr(mr) ||
		    mr->umem->is_peer)
			goto recreate;

		/*
		 * Only one active MR can refer to a umem at one time, revoke
		 * the old MR before assigning the umem to the new one.
		 */
		err = mlx5r_umr_revoke_mr(mr);
		if (err)
			return ERR_PTR(err);
		umem = mr->umem;
		mr->umem = NULL;
		atomic_sub(ib_umem_num_pages(umem), &dev->mdev->priv.reg_pages);

		return create_real_mr(new_pd, umem, mr->ibmr.iova,
				      new_access_flags);
	}

	/*
	 * DM doesn't have a PAS list so we can't re-use it, odp/dmabuf does but
	 * the logic around releasing the umem is different, peer memory
	 * invalidation semantics are incompatible.
	 */
	if (!mr->umem || is_odp_mr(mr) || is_dmabuf_mr(mr) || mr->umem->is_peer)
		goto recreate;

	if (!(new_access_flags & IB_ACCESS_ON_DEMAND) &&
	    can_use_umr_rereg_access(dev, mr->access_flags, new_access_flags)) {
		struct ib_umem *new_umem;
		unsigned long page_size;

		new_umem = ib_umem_get_peer(&dev->ib_dev, start, length,
					    new_access_flags,
					    IB_PEER_MEM_INVAL_SUPP);
		if (IS_ERR(new_umem))
			return ERR_CAST(new_umem);

		/* Fast path for PAS change */
		if (can_use_umr_rereg_pas(mr, new_umem, new_access_flags, iova,
					  &page_size)) {
			err = umr_rereg_pas(mr, new_pd, new_access_flags, flags,
					    new_umem, iova, page_size);
			if (err) {
				ib_umem_release(new_umem);
				return ERR_PTR(err);
			}
			return NULL;
		}
		return create_real_mr(new_pd, new_umem, iova, new_access_flags);
	}

	/*
	 * Everything else has no state we can preserve, just create a new MR
	 * from scratch
	 */
recreate:
	return mlx5_ib_reg_user_mr(new_pd, start, length, iova,
				   new_access_flags, udata);
}

static int
mlx5_alloc_priv_descs(struct ib_device *device,
		      struct mlx5_ib_mr *mr,
		      int ndescs,
		      int desc_size)
{
	struct mlx5_ib_dev *dev = to_mdev(device);
	struct device *ddev = &dev->mdev->pdev->dev;
	int size = ndescs * desc_size;
	int add_size;
	int ret;

	add_size = max_t(int, MLX5_UMR_ALIGN - ARCH_KMALLOC_MINALIGN, 0);

	mr->descs_alloc = kzalloc(size + add_size, GFP_KERNEL);
	if (!mr->descs_alloc)
		return -ENOMEM;

	mr->descs = PTR_ALIGN(mr->descs_alloc, MLX5_UMR_ALIGN);

	mr->desc_map = dma_map_single(ddev, mr->descs, size, DMA_TO_DEVICE);
	if (dma_mapping_error(ddev, mr->desc_map)) {
		ret = -ENOMEM;
		goto err;
	}

	return 0;
err:
	kfree(mr->descs_alloc);

	return ret;
}

static void
mlx5_free_priv_descs(struct mlx5_ib_mr *mr)
{
	if (!mr->umem && mr->descs) {
		struct ib_device *device = mr->ibmr.device;
		int size = mr->max_descs * mr->desc_size;
		struct mlx5_ib_dev *dev = to_mdev(device);

		dma_unmap_single(&dev->mdev->pdev->dev, mr->desc_map, size,
				 DMA_TO_DEVICE);
		kfree(mr->descs_alloc);
		mr->descs = NULL;
	}
}

static int cache_ent_find_and_store(struct mlx5_ib_dev *dev,
				    struct mlx5_ib_mr *mr)
{
	struct mlx5_mkey_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent;
	int ret;

	mutex_lock(&cache->rb_lock);
	if (mr->mmkey.cache_ent) {
		ent = mr->mmkey.cache_ent;
		xa_lock_irq(&mr->mmkey.cache_ent->mkeys);
		mr->mmkey.cache_ent->in_use--;
		goto end;
	}

	ent = mkey_cache_ent_from_rb_key(dev, mr->mmkey.rb_key);
	if (ent) {
		if (ent->rb_key.ndescs == mr->mmkey.rb_key.ndescs) {
			if (ent->disabled) {
				mutex_unlock(&cache->rb_lock);
				return -EOPNOTSUPP;
			}
			mr->mmkey.cache_ent = ent;
			xa_lock_irq(&mr->mmkey.cache_ent->mkeys);
			goto end;
		}
	}

	ent = mlx5r_cache_create_ent_locked(dev, mr->mmkey.rb_key, false);
	if (IS_ERR(ent)) {
		mutex_unlock(&cache->rb_lock);
		return PTR_ERR(ent);
	}

	mr->mmkey.cache_ent = ent;
	xa_lock_irq(&mr->mmkey.cache_ent->mkeys);

end:
	if (ent->is_tmp && cache->tmp_clean)
	{
		cache->tmp_clean = false;
		mod_delayed_work(cache->wq,
				 &cache->remove_ent_dwork,
				 msecs_to_jiffies(30 * 1000));
	}
	ret = push_mkey_locked(mr->mmkey.cache_ent, false,
			       xa_mk_value(mr->mmkey.key));
	xa_unlock_irq(&mr->mmkey.cache_ent->mkeys);
	mutex_unlock(&cache->rb_lock);
	return ret;
}

static int mlx5_revoke_mr(struct mlx5_ib_mr *mr)
{
	struct mlx5_ib_dev *dev = to_mdev(mr->ibmr.device);
	struct mlx5_cache_ent *ent = mr->mmkey.cache_ent;
	int rc;

	if (mr->mmkey.cacheable && !mlx5r_umr_revoke_mr(mr) && !cache_ent_find_and_store(dev, mr))
		return 0;

	if (ent) {
		xa_lock_irq(&ent->mkeys);
		ent->in_use--;
		mr->mmkey.cache_ent = NULL;
		xa_unlock_irq(&ent->mkeys);
	}

	if (mr->umem && mr->umem->is_peer) {
		rc = mlx5r_umr_revoke_mr(mr);
		if (rc)
			return rc;
		ib_umem_stop_invalidation_notifier(mr->umem);
	}

	return destroy_mkey(dev, mr);
}

int mlx5_ib_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
{
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	struct mlx5_ib_dev *dev = to_mdev(ibmr->device);
	int rc;

	/*
	 * Any async use of the mr must hold the refcount, once the refcount
	 * goes to zero no other thread, such as ODP page faults, prefetch, any
	 * UMR activity, etc can touch the mkey. Thus it is safe to destroy it.
	 */
	if (IS_ENABLED(CONFIG_INFINIBAND_ON_DEMAND_PAGING) &&
	    refcount_read(&mr->mmkey.usecount) != 0 &&
	    xa_erase(&mr_to_mdev(mr)->odp_mkeys, mlx5_base_mkey(mr->mmkey.key)))
		mlx5r_deref_wait_odp_mkey(&mr->mmkey);

	if (ibmr->type == IB_MR_TYPE_INTEGRITY) {
		xa_cmpxchg(&dev->sig_mrs, mlx5_base_mkey(mr->mmkey.key),
			   mr->sig, NULL, GFP_KERNEL);

		if (mr->mtt_mr) {
			rc = mlx5_ib_dereg_mr(&mr->mtt_mr->ibmr, NULL);
			if (rc)
				return rc;
			mr->mtt_mr = NULL;
		}
		if (mr->klm_mr) {
			rc = mlx5_ib_dereg_mr(&mr->klm_mr->ibmr, NULL);
			if (rc)
				return rc;
			mr->klm_mr = NULL;
		}

		if (mlx5_core_destroy_psv(dev->mdev,
					  mr->sig->psv_memory.psv_idx))
			mlx5_ib_warn(dev, "failed to destroy mem psv %d\n",
				     mr->sig->psv_memory.psv_idx);
		if (mlx5_core_destroy_psv(dev->mdev, mr->sig->psv_wire.psv_idx))
			mlx5_ib_warn(dev, "failed to destroy wire psv %d\n",
				     mr->sig->psv_wire.psv_idx);
		kfree(mr->sig);
		mr->sig = NULL;
	}

	/* Stop DMA */
	rc = mlx5_revoke_mr(mr);
	if (rc)
		return rc;

	if (mr->umem) {
		bool is_odp = is_odp_mr(mr);

		if (!is_odp)
			atomic_sub(ib_umem_num_pages(mr->umem),
				   &dev->mdev->priv.reg_pages);
		ib_umem_release(mr->umem);
		if (is_odp)
			mlx5_ib_free_odp_mr(mr);
	}

	if (!mr->mmkey.cache_ent)
		mlx5_free_priv_descs(mr);

	kfree(mr);
	return 0;
}

static void mlx5_set_umr_free_mkey(struct ib_pd *pd, u32 *in, int ndescs,
				   int access_mode, int page_shift)
{
	void *mkc;
#ifdef CONFIG_GPU_DIRECT_STORAGE
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
#endif

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);

	/* This is only used from the kernel, so setting the PD is OK. */
	set_mkc_access_pd_addr_fields(mkc, IB_ACCESS_RELAXED_ORDERING, 0, pd);
	MLX5_SET(mkc, mkc, free, 1);
	MLX5_SET(mkc, mkc, translations_octword_size, ndescs);
	MLX5_SET(mkc, mkc, access_mode_1_0, access_mode & 0x3);
	MLX5_SET(mkc, mkc, access_mode_4_2, (access_mode >> 2) & 0x7);
	MLX5_SET(mkc, mkc, umr_en, 1);
	MLX5_SET(mkc, mkc, log_page_size, page_shift);
#ifdef CONFIG_GPU_DIRECT_STORAGE
	if (access_mode == MLX5_MKC_ACCESS_MODE_PA ||
	    access_mode == MLX5_MKC_ACCESS_MODE_MTT)
		MLX5_SET(mkc, mkc, ma_translation_mode, MLX5_CAP_GEN(dev->mdev,
								     ats));
	else
		pr_err_once("mlx5_ib: %s: Translation mode supported only when access_mode is MTT or PA\n", __func__);
#endif
}

static int _mlx5_alloc_mkey_descs(struct ib_pd *pd, struct mlx5_ib_mr *mr,
				  int ndescs, int desc_size, int page_shift,
				  int access_mode, u32 *in, int inlen)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	int err;

	mr->access_mode = access_mode;
	mr->desc_size = desc_size;
	mr->max_descs = ndescs;

	err = mlx5_alloc_priv_descs(pd->device, mr, ndescs, desc_size);
	if (err)
		return err;

	mlx5_set_umr_free_mkey(pd, in, ndescs, access_mode, page_shift);

	err = mlx5_ib_create_mkey(dev, &mr->mmkey, in, inlen);
	if (err)
		goto err_free_descs;

	mr->mmkey.type = MLX5_MKEY_MR;
	mr->ibmr.lkey = mr->mmkey.key;
	mr->ibmr.rkey = mr->mmkey.key;

	return 0;

err_free_descs:
	mlx5_free_priv_descs(mr);
	return err;
}

static struct mlx5_ib_mr *mlx5_ib_alloc_pi_mr(struct ib_pd *pd,
				u32 max_num_sg, u32 max_num_meta_sg,
				int desc_size, int access_mode)
{
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	int ndescs = ALIGN(max_num_sg + max_num_meta_sg, 4);
	int page_shift = 0;
	struct mlx5_ib_mr *mr;
	u32 *in;
	int err;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	mr->ibmr.pd = pd;
	mr->ibmr.device = pd->device;

	in = kzalloc(inlen, GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_free;
	}

	if (access_mode == MLX5_MKC_ACCESS_MODE_MTT)
		page_shift = PAGE_SHIFT;

	err = _mlx5_alloc_mkey_descs(pd, mr, ndescs, desc_size, page_shift,
				     access_mode, in, inlen);
	if (err)
		goto err_free_in;

	mr->umem = NULL;
	kfree(in);

	return mr;

err_free_in:
	kfree(in);
err_free:
	kfree(mr);
	return ERR_PTR(err);
}

static int mlx5_alloc_mem_reg_descs(struct ib_pd *pd, struct mlx5_ib_mr *mr,
				    int ndescs, u32 *in, int inlen)
{
	return _mlx5_alloc_mkey_descs(pd, mr, ndescs, sizeof(struct mlx5_mtt),
				      PAGE_SHIFT, MLX5_MKC_ACCESS_MODE_MTT, in,
				      inlen);
}

static int mlx5_alloc_sg_gaps_descs(struct ib_pd *pd, struct mlx5_ib_mr *mr,
				    int ndescs, u32 *in, int inlen)
{
	return _mlx5_alloc_mkey_descs(pd, mr, ndescs, sizeof(struct mlx5_klm),
				      0, MLX5_MKC_ACCESS_MODE_KLMS, in, inlen);
}

static int mlx5_alloc_integrity_descs(struct ib_pd *pd, struct mlx5_ib_mr *mr,
				      int max_num_sg, int max_num_meta_sg,
				      u32 *in, int inlen)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	u32 psv_index[2];
	void *mkc;
	int err;

	mr->sig = kzalloc(sizeof(*mr->sig), GFP_KERNEL);
	if (!mr->sig)
		return -ENOMEM;

	/* create mem & wire PSVs */
	err = mlx5_core_create_psv(dev->mdev, to_mpd(pd)->pdn, 2, psv_index);
	if (err)
		goto err_free_sig;

	mr->sig->psv_memory.psv_idx = psv_index[0];
	mr->sig->psv_wire.psv_idx = psv_index[1];

	mr->sig->sig_status_checked = true;
	mr->sig->sig_err_exists = false;
	/* Next UMR, Arm SIGERR */
	++mr->sig->sigerr_count;
	mr->klm_mr = mlx5_ib_alloc_pi_mr(pd, max_num_sg, max_num_meta_sg,
					 sizeof(struct mlx5_klm),
					 MLX5_MKC_ACCESS_MODE_KLMS);
	if (IS_ERR(mr->klm_mr)) {
		err = PTR_ERR(mr->klm_mr);
		goto err_destroy_psv;
	}
	mr->mtt_mr = mlx5_ib_alloc_pi_mr(pd, max_num_sg, max_num_meta_sg,
					 sizeof(struct mlx5_mtt),
					 MLX5_MKC_ACCESS_MODE_MTT);
	if (IS_ERR(mr->mtt_mr)) {
		err = PTR_ERR(mr->mtt_mr);
		goto err_free_klm_mr;
	}

	/* Set bsf descriptors for mkey */
	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, bsf_en, 1);
	MLX5_SET(mkc, mkc, bsf_octword_size, MLX5_MKEY_BSF_OCTO_SIZE);

	err = _mlx5_alloc_mkey_descs(pd, mr, 4, sizeof(struct mlx5_klm), 0,
				     MLX5_MKC_ACCESS_MODE_KLMS, in, inlen);
	if (err)
		goto err_free_mtt_mr;

	err = xa_err(xa_store(&dev->sig_mrs, mlx5_base_mkey(mr->mmkey.key),
			      mr->sig, GFP_KERNEL));
	if (err)
		goto err_free_descs;
	return 0;

err_free_descs:
	destroy_mkey(dev, mr);
	mlx5_free_priv_descs(mr);
err_free_mtt_mr:
	mlx5_ib_dereg_mr(&mr->mtt_mr->ibmr, NULL);
	mr->mtt_mr = NULL;
err_free_klm_mr:
	mlx5_ib_dereg_mr(&mr->klm_mr->ibmr, NULL);
	mr->klm_mr = NULL;
err_destroy_psv:
	if (mlx5_core_destroy_psv(dev->mdev, mr->sig->psv_memory.psv_idx))
		mlx5_ib_warn(dev, "failed to destroy mem psv %d\n",
			     mr->sig->psv_memory.psv_idx);
	if (mlx5_core_destroy_psv(dev->mdev, mr->sig->psv_wire.psv_idx))
		mlx5_ib_warn(dev, "failed to destroy wire psv %d\n",
			     mr->sig->psv_wire.psv_idx);
err_free_sig:
	kfree(mr->sig);

	return err;
}

static struct ib_mr *__mlx5_ib_alloc_mr(struct ib_pd *pd,
					enum ib_mr_type mr_type, u32 max_num_sg,
					u32 max_num_meta_sg)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	int ndescs = ALIGN(max_num_sg, 4);
	struct mlx5_ib_mr *mr;
	u32 *in;
	int err;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	in = kzalloc(inlen, GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_free;
	}

	mr->ibmr.device = pd->device;
	mr->umem = NULL;

	switch (mr_type) {
	case IB_MR_TYPE_MEM_REG:
		err = mlx5_alloc_mem_reg_descs(pd, mr, ndescs, in, inlen);
		break;
	case IB_MR_TYPE_SG_GAPS:
		err = mlx5_alloc_sg_gaps_descs(pd, mr, ndescs, in, inlen);
		break;
	case IB_MR_TYPE_INTEGRITY:
		err = mlx5_alloc_integrity_descs(pd, mr, max_num_sg,
						 max_num_meta_sg, in, inlen);
		break;
	default:
		mlx5_ib_warn(dev, "Invalid mr type %d\n", mr_type);
		err = -EINVAL;
	}

	if (err)
		goto err_free_in;

	kfree(in);

	return &mr->ibmr;

err_free_in:
	kfree(in);
err_free:
	kfree(mr);
	return ERR_PTR(err);
}

struct ib_mr *mlx5_ib_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			       u32 max_num_sg)
{
	return __mlx5_ib_alloc_mr(pd, mr_type, max_num_sg, 0);
}

struct ib_mr *mlx5_ib_alloc_mr_integrity(struct ib_pd *pd,
					 u32 max_num_sg, u32 max_num_meta_sg)
{
	return __mlx5_ib_alloc_mr(pd, IB_MR_TYPE_INTEGRITY, max_num_sg,
				  max_num_meta_sg);
}

int mlx5_ib_alloc_mw(struct ib_mw *ibmw, struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(ibmw->device);
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	struct mlx5_ib_mw *mw = to_mmw(ibmw);
	unsigned int ndescs;
	u32 *in = NULL;
	void *mkc;
	int err;
	struct mlx5_ib_alloc_mw req = {};
	struct {
		__u32	comp_mask;
		__u32	response_length;
	} resp = {};

	err = ib_copy_from_udata(&req, udata, min(udata->inlen, sizeof(req)));
	if (err)
		return err;

	if (req.comp_mask || req.reserved1 || req.reserved2)
		return -EOPNOTSUPP;

	if (udata->inlen > sizeof(req) &&
	    !ib_is_udata_cleared(udata, sizeof(req),
				 udata->inlen - sizeof(req)))
		return -EOPNOTSUPP;

	ndescs = req.num_klms ? roundup(req.num_klms, 4) : roundup(1, 4);

	in = kzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);

	MLX5_SET(mkc, mkc, free, 1);
	MLX5_SET(mkc, mkc, translations_octword_size, ndescs);
	MLX5_SET(mkc, mkc, pd, to_mpd(ibmw->pd)->pdn);
	MLX5_SET(mkc, mkc, umr_en, 1);
	MLX5_SET(mkc, mkc, lr, 1);
	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_KLMS);
	MLX5_SET(mkc, mkc, en_rinval, !!((ibmw->type == IB_MW_TYPE_2)));
	MLX5_SET(mkc, mkc, qpn, 0xffffff);

	err = mlx5_ib_create_mkey(dev, &mw->mmkey, in, inlen);
	if (err)
		goto free;

	mw->mmkey.type = MLX5_MKEY_MW;
	ibmw->rkey = mw->mmkey.key;
	mw->mmkey.ndescs = ndescs;

	resp.response_length =
		min(offsetofend(typeof(resp), response_length), udata->outlen);
	if (resp.response_length) {
		err = ib_copy_to_udata(udata, &resp, resp.response_length);
		if (err)
			goto free_mkey;
	}

	if (IS_ENABLED(CONFIG_INFINIBAND_ON_DEMAND_PAGING)) {
		err = mlx5r_store_odp_mkey(dev, &mw->mmkey);
		if (err)
			goto free_mkey;
	}

	kfree(in);
	return 0;

free_mkey:
	mlx5_core_destroy_mkey(dev->mdev, mw->mmkey.key);
free:
	kfree(in);
	return err;
}

int mlx5_ib_dealloc_mw(struct ib_mw *mw)
{
	struct mlx5_ib_dev *dev = to_mdev(mw->device);
	struct mlx5_ib_mw *mmw = to_mmw(mw);

	if (IS_ENABLED(CONFIG_INFINIBAND_ON_DEMAND_PAGING) &&
	    xa_erase(&dev->odp_mkeys, mlx5_base_mkey(mmw->mmkey.key)))
		/*
		 * pagefault_single_data_segment() may be accessing mmw
		 * if the user bound an ODP MR to this MW.
		 */
		mlx5r_deref_wait_odp_mkey(&mmw->mmkey);

	return mlx5_core_destroy_mkey(dev->mdev, mmw->mmkey.key);
}

int mlx5_ib_check_mr_status(struct ib_mr *ibmr, u32 check_mask,
			    struct ib_mr_status *mr_status)
{
	struct mlx5_ib_mr *mmr = to_mmr(ibmr);
	int ret = 0;

	if (check_mask & ~IB_MR_CHECK_SIG_STATUS) {
		pr_err("Invalid status check mask\n");
		ret = -EINVAL;
		goto done;
	}

	mr_status->fail_status = 0;
	if (check_mask & IB_MR_CHECK_SIG_STATUS) {
		if (!mmr->sig) {
			ret = -EINVAL;
			pr_err("signature status check requested on a non-signature enabled MR\n");
			goto done;
		}

		mmr->sig->sig_status_checked = true;
		if (!mmr->sig->sig_err_exists)
			goto done;

		if (ibmr->lkey == mmr->sig->err_item.key)
			memcpy(&mr_status->sig_err, &mmr->sig->err_item,
			       sizeof(mr_status->sig_err));
		else {
			mr_status->sig_err.err_type = IB_SIG_BAD_GUARD;
			mr_status->sig_err.sig_err_offset = 0;
			mr_status->sig_err.key = mmr->sig->err_item.key;
		}

		mmr->sig->sig_err_exists = false;
		mr_status->fail_status |= IB_MR_CHECK_SIG_STATUS;
	}

done:
	return ret;
}

static int
mlx5_ib_map_pa_mr_sg_pi(struct ib_mr *ibmr, struct scatterlist *data_sg,
			int data_sg_nents, unsigned int *data_sg_offset,
			struct scatterlist *meta_sg, int meta_sg_nents,
			unsigned int *meta_sg_offset)
{
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	unsigned int sg_offset = 0;
	int n = 0;

	mr->meta_length = 0;
	if (data_sg_nents == 1) {
		n++;
		mr->mmkey.ndescs = 1;
		if (data_sg_offset)
			sg_offset = *data_sg_offset;
		mr->data_length = sg_dma_len(data_sg) - sg_offset;
		mr->data_iova = sg_dma_address(data_sg) + sg_offset;
		if (meta_sg_nents == 1) {
			n++;
			mr->meta_ndescs = 1;
			if (meta_sg_offset)
				sg_offset = *meta_sg_offset;
			else
				sg_offset = 0;
			mr->meta_length = sg_dma_len(meta_sg) - sg_offset;
			mr->pi_iova = sg_dma_address(meta_sg) + sg_offset;
		}
		ibmr->length = mr->data_length + mr->meta_length;
	}

	return n;
}

static int
mlx5_ib_sg_to_klms(struct mlx5_ib_mr *mr,
		   struct scatterlist *sgl,
		   unsigned short sg_nents,
		   unsigned int *sg_offset_p,
		   struct scatterlist *meta_sgl,
		   unsigned short meta_sg_nents,
		   unsigned int *meta_sg_offset_p)
{
	struct scatterlist *sg = sgl;
	struct mlx5_klm *klms = mr->descs;
	unsigned int sg_offset = sg_offset_p ? *sg_offset_p : 0;
	u32 lkey = mr->ibmr.pd->local_dma_lkey;
	int i, j = 0;

	mr->ibmr.iova = sg_dma_address(sg) + sg_offset;
	mr->ibmr.length = 0;

	for_each_sg(sgl, sg, sg_nents, i) {
		if (unlikely(i >= mr->max_descs))
			break;
		klms[i].va = cpu_to_be64(sg_dma_address(sg) + sg_offset);
		klms[i].bcount = cpu_to_be32(sg_dma_len(sg) - sg_offset);
		klms[i].key = cpu_to_be32(lkey);
		mr->ibmr.length += sg_dma_len(sg) - sg_offset;

		sg_offset = 0;
	}

	if (sg_offset_p)
		*sg_offset_p = sg_offset;

	mr->mmkey.ndescs = i;
	mr->data_length = mr->ibmr.length;

	if (meta_sg_nents) {
		sg = meta_sgl;
		sg_offset = meta_sg_offset_p ? *meta_sg_offset_p : 0;
		for_each_sg(meta_sgl, sg, meta_sg_nents, j) {
			if (unlikely(i + j >= mr->max_descs))
				break;
			klms[i + j].va = cpu_to_be64(sg_dma_address(sg) +
						     sg_offset);
			klms[i + j].bcount = cpu_to_be32(sg_dma_len(sg) -
							 sg_offset);
			klms[i + j].key = cpu_to_be32(lkey);
			mr->ibmr.length += sg_dma_len(sg) - sg_offset;

			sg_offset = 0;
		}
		if (meta_sg_offset_p)
			*meta_sg_offset_p = sg_offset;

		mr->meta_ndescs = j;
		mr->meta_length = mr->ibmr.length - mr->data_length;
	}

	return i + j;
}

static int mlx5_set_page(struct ib_mr *ibmr, u64 addr)
{
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	__be64 *descs;

	if (unlikely(mr->mmkey.ndescs == mr->max_descs))
		return -ENOMEM;

	descs = mr->descs;
	descs[mr->mmkey.ndescs++] = cpu_to_be64(addr | MLX5_EN_RD | MLX5_EN_WR);

	return 0;
}

static int mlx5_set_page_pi(struct ib_mr *ibmr, u64 addr)
{
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	__be64 *descs;

	if (unlikely(mr->mmkey.ndescs + mr->meta_ndescs == mr->max_descs))
		return -ENOMEM;

	descs = mr->descs;
	descs[mr->mmkey.ndescs + mr->meta_ndescs++] =
		cpu_to_be64(addr | MLX5_EN_RD | MLX5_EN_WR);

	return 0;
}

static int
mlx5_ib_map_mtt_mr_sg_pi(struct ib_mr *ibmr, struct scatterlist *data_sg,
			 int data_sg_nents, unsigned int *data_sg_offset,
			 struct scatterlist *meta_sg, int meta_sg_nents,
			 unsigned int *meta_sg_offset)
{
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	struct mlx5_ib_mr *pi_mr = mr->mtt_mr;
	int n;

	pi_mr->mmkey.ndescs = 0;
	pi_mr->meta_ndescs = 0;
	pi_mr->meta_length = 0;

	ib_dma_sync_single_for_cpu(ibmr->device, pi_mr->desc_map,
				   pi_mr->desc_size * pi_mr->max_descs,
				   DMA_TO_DEVICE);

	pi_mr->ibmr.page_size = ibmr->page_size;
	n = ib_sg_to_pages(&pi_mr->ibmr, data_sg, data_sg_nents, data_sg_offset,
			   mlx5_set_page);
	if (n != data_sg_nents)
		return n;

	pi_mr->data_iova = pi_mr->ibmr.iova;
	pi_mr->data_length = pi_mr->ibmr.length;
	pi_mr->ibmr.length = pi_mr->data_length;
	ibmr->length = pi_mr->data_length;

	if (meta_sg_nents) {
		u64 page_mask = ~((u64)ibmr->page_size - 1);
		u64 iova = pi_mr->data_iova;

		n += ib_sg_to_pages(&pi_mr->ibmr, meta_sg, meta_sg_nents,
				    meta_sg_offset, mlx5_set_page_pi);

		pi_mr->meta_length = pi_mr->ibmr.length;
		/*
		 * PI address for the HW is the offset of the metadata address
		 * relative to the first data page address.
		 * It equals to first data page address + size of data pages +
		 * metadata offset at the first metadata page
		 */
		pi_mr->pi_iova = (iova & page_mask) +
				 pi_mr->mmkey.ndescs * ibmr->page_size +
				 (pi_mr->ibmr.iova & ~page_mask);
		/*
		 * In order to use one MTT MR for data and metadata, we register
		 * also the gaps between the end of the data and the start of
		 * the metadata (the sig MR will verify that the HW will access
		 * to right addresses). This mapping is safe because we use
		 * internal mkey for the registration.
		 */
		pi_mr->ibmr.length = pi_mr->pi_iova + pi_mr->meta_length - iova;
		pi_mr->ibmr.iova = iova;
		ibmr->length += pi_mr->meta_length;
	}

	ib_dma_sync_single_for_device(ibmr->device, pi_mr->desc_map,
				      pi_mr->desc_size * pi_mr->max_descs,
				      DMA_TO_DEVICE);

	return n;
}

static int
mlx5_ib_map_klm_mr_sg_pi(struct ib_mr *ibmr, struct scatterlist *data_sg,
			 int data_sg_nents, unsigned int *data_sg_offset,
			 struct scatterlist *meta_sg, int meta_sg_nents,
			 unsigned int *meta_sg_offset)
{
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	struct mlx5_ib_mr *pi_mr = mr->klm_mr;
	int n;

	pi_mr->mmkey.ndescs = 0;
	pi_mr->meta_ndescs = 0;
	pi_mr->meta_length = 0;

	ib_dma_sync_single_for_cpu(ibmr->device, pi_mr->desc_map,
				   pi_mr->desc_size * pi_mr->max_descs,
				   DMA_TO_DEVICE);

	n = mlx5_ib_sg_to_klms(pi_mr, data_sg, data_sg_nents, data_sg_offset,
			       meta_sg, meta_sg_nents, meta_sg_offset);

	ib_dma_sync_single_for_device(ibmr->device, pi_mr->desc_map,
				      pi_mr->desc_size * pi_mr->max_descs,
				      DMA_TO_DEVICE);

	/* This is zero-based memory region */
	pi_mr->data_iova = 0;
	pi_mr->ibmr.iova = 0;
	pi_mr->pi_iova = pi_mr->data_length;
	ibmr->length = pi_mr->ibmr.length;

	return n;
}

int mlx5_ib_map_mr_sg_pi(struct ib_mr *ibmr, struct scatterlist *data_sg,
			 int data_sg_nents, unsigned int *data_sg_offset,
			 struct scatterlist *meta_sg, int meta_sg_nents,
			 unsigned int *meta_sg_offset)
{
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	struct mlx5_ib_mr *pi_mr = NULL;
	int n;

	WARN_ON(ibmr->type != IB_MR_TYPE_INTEGRITY);

	mr->mmkey.ndescs = 0;
	mr->data_length = 0;
	mr->data_iova = 0;
	mr->meta_ndescs = 0;
	mr->pi_iova = 0;
	/*
	 * As a performance optimization, if possible, there is no need to
	 * perform UMR operation to register the data/metadata buffers.
	 * First try to map the sg lists to PA descriptors with local_dma_lkey.
	 * Fallback to UMR only in case of a failure.
	 */
	n = mlx5_ib_map_pa_mr_sg_pi(ibmr, data_sg, data_sg_nents,
				    data_sg_offset, meta_sg, meta_sg_nents,
				    meta_sg_offset);
	if (n == data_sg_nents + meta_sg_nents)
		goto out;
	/*
	 * As a performance optimization, if possible, there is no need to map
	 * the sg lists to KLM descriptors. First try to map the sg lists to MTT
	 * descriptors and fallback to KLM only in case of a failure.
	 * It's more efficient for the HW to work with MTT descriptors
	 * (especially in high load).
	 * Use KLM (indirect access) only if it's mandatory.
	 */
	pi_mr = mr->mtt_mr;
	n = mlx5_ib_map_mtt_mr_sg_pi(ibmr, data_sg, data_sg_nents,
				     data_sg_offset, meta_sg, meta_sg_nents,
				     meta_sg_offset);
	if (n == data_sg_nents + meta_sg_nents)
		goto out;

	pi_mr = mr->klm_mr;
	n = mlx5_ib_map_klm_mr_sg_pi(ibmr, data_sg, data_sg_nents,
				     data_sg_offset, meta_sg, meta_sg_nents,
				     meta_sg_offset);
	if (unlikely(n != data_sg_nents + meta_sg_nents))
		return -ENOMEM;

out:
	/* This is zero-based memory region */
	ibmr->iova = 0;
	mr->pi_mr = pi_mr;
	if (pi_mr)
		ibmr->sig_attrs->meta_length = pi_mr->meta_length;
	else
		ibmr->sig_attrs->meta_length = mr->meta_length;

	return 0;
}

int mlx5_ib_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg, int sg_nents,
		      unsigned int *sg_offset)
{
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	int n;

	mr->mmkey.ndescs = 0;

	ib_dma_sync_single_for_cpu(ibmr->device, mr->desc_map,
				   mr->desc_size * mr->max_descs,
				   DMA_TO_DEVICE);

	if (mr->access_mode == MLX5_MKC_ACCESS_MODE_KLMS)
		n = mlx5_ib_sg_to_klms(mr, sg, sg_nents, sg_offset, NULL, 0,
				       NULL);
	else
		n = ib_sg_to_pages(ibmr, sg, sg_nents, sg_offset,
				mlx5_set_page);

	ib_dma_sync_single_for_device(ibmr->device, mr->desc_map,
				      mr->desc_size * mr->max_descs,
				      DMA_TO_DEVICE);

	return n;
}

static void mlx5_invalidate_umem(struct ib_umem *umem, void *priv)
{
	struct mlx5_ib_mr *mr = priv;

	/*
	 * DMA is turned off for the mkey, but the mkey remains otherwise
	 * untouched until the normal flow of dereg_mr happens. Any access to
	 * this mkey will generate CQEs.
	 */
	mlx5r_umr_revoke_mr(mr);
}


struct cache_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx5_ib_dev *dev, char *buf);
	ssize_t (*store)(struct mlx5_ib_dev *dev, const char *buf, size_t count);
};

static ssize_t rel_imm_show(struct mlx5_ib_dev *dev, char *buf)
{
	struct mlx5_mkey_cache *cache = &dev->cache;
	int err;

	err = snprintf(buf, 20, "%d\n", cache->rel_imm);
	return err;
}

static ssize_t rel_imm_store(struct mlx5_ib_dev *dev, const char *buf, size_t count)
{
	struct mlx5_mkey_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent;
	struct rb_node *node;
	u32 var;
	int over;
	int found = 0;

	if (kstrtouint(buf, 0, &var))
		return -EINVAL;

	if (var > 1)
		return -EINVAL;

	if (var == cache->rel_imm)
		return count;

	cache->rel_imm = var;
	if (cache->rel_imm == 1) {
		mutex_lock(&cache->rb_lock);
		for (node = rb_first(&cache->rb_root); node; node = rb_next(node)) {
			ent = rb_entry(node, struct mlx5_cache_ent, node);
			xa_lock_irq(&ent->mkeys);
			over = ent->stored > 2 * ent->limit;
			xa_unlock_irq(&ent->mkeys);
			if (over) {
				mod_delayed_work(cache->wq, &ent->dwork, 0);
				found = 1;
			}
		}
		mutex_unlock(&cache->rb_lock);
		if (!found)
			cache->rel_imm = 0;
	}

	return count;
}
static ssize_t rel_timeout_show(struct mlx5_ib_dev *dev, char *buf)
{
	struct mlx5_mkey_cache *cache = &dev->cache;
	int err;

	err = snprintf(buf, 20, "%d\n", cache->rel_timeout);
	return err;
}

static ssize_t rel_timeout_store(struct mlx5_ib_dev *dev, const char *buf, size_t count)
{
	struct mlx5_mkey_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent;
	struct rb_node *node;
	int var;
	int over;

	if (kstrtoint(buf, 0, &var))
		return -EINVAL;

	if (var < -1 || var > MAX_MR_RELEASE_TIMEOUT)
		return -EINVAL;

	if (var == cache->rel_timeout)
		return count;

	if (cache->rel_timeout == -1 || (var < cache->rel_timeout && var != -1)) {
		cache->rel_timeout = var;
		mutex_lock(&cache->rb_lock);
		for (node = rb_first(&cache->rb_root); node; node = rb_next(node)) {
			ent = rb_entry(node, struct mlx5_cache_ent, node);
			xa_lock_irq(&ent->mkeys);
			over = ent->stored > 2 * ent->limit;
			xa_unlock_irq(&ent->mkeys);
			if (over)
				mod_delayed_work(cache->wq, &ent->dwork, 0);
		}
		mutex_unlock(&cache->rb_lock);
	} else {
		cache->rel_timeout = var;
	}

	return count;
}

static ssize_t cache_attr_show(struct kobject *kobj,
			       struct attribute *attr, char *buf)
{
	struct cache_attribute *ca =
		container_of(attr, struct cache_attribute, attr);
	struct mlx5_ib_dev *dev = container_of(kobj, struct mlx5_ib_dev, mr_cache);

	if (!ca->show)
		return -EIO;

	return ca->show(dev, buf);
}

static ssize_t cache_attr_store(struct kobject *kobj,
				struct attribute *attr, const char *buf, size_t size)
{
	struct cache_attribute *ca =
		container_of(attr, struct cache_attribute, attr);
	struct mlx5_ib_dev *dev = container_of(kobj, struct mlx5_ib_dev, mr_cache);

	if (!ca->store)
		return -EIO;

	return ca->store(dev, buf, size);
}

static const struct sysfs_ops cache_sysfs_ops = {
	.show = cache_attr_show,
	.store = cache_attr_store,
};

#define CACHE_ATTR(_name) struct cache_attribute cache_attr_##_name = \
	__ATTR(_name, 0644, _name##_show, _name##_store)

static CACHE_ATTR(rel_imm);
static CACHE_ATTR(rel_timeout);

static struct attribute *cache_default_attrs[] = {
	&cache_attr_rel_imm.attr,
	&cache_attr_rel_timeout.attr,
	NULL
};

ATTRIBUTE_GROUPS(cache_default);
static const struct kobj_type cache_type = {
	.sysfs_ops     = &cache_sysfs_ops,
	.default_groups = cache_default_groups
};

static int mlx5_mkey_cache_sysfs_init(struct mlx5_ib_dev *dev)
{
	struct device *device = &dev->ib_dev.dev;
	int err;

	if (dev->is_rep)
		return 0;

	err = kobject_init_and_add(&dev->mr_cache, &cache_type,
				   &device->kobj, "mr_cache");
	if (err)
		kobject_put(&dev->mr_cache);
	return err;
}

static int mlx5_mkey_cache_sysfs_add_ent(struct mlx5_ib_dev *dev,
					    struct mlx5_cache_ent *ent)
{
	int order = order_base_2(ent->rb_key.ndescs);
	struct cache_order *co;
	int err = 0;

	if (dev->is_rep)
		return 0;

	if (ent->rb_key.access_mode == MLX5_MKC_ACCESS_MODE_KSM)
		order = MLX5_IMR_KSM_CACHE_ENTRY + 2;

	co = &ent->co;
	co->order = order;

	/* verify that the parent kobject exists */
	if (kref_read(&dev->mr_cache.kref) == 0)
		return -ENOENT;

	err = kobject_init_and_add(&co->kobj, &order_type,
				   &dev->mr_cache, "%d", order);
	if (!err)
		kobject_uevent(&co->kobj, KOBJ_ADD);
	else
		kobject_put(&co->kobj);
	return err;
}

static void mlx5_mkey_cache_sysfs_ent_cleanup(struct mlx5_cache_ent *ent)
{

	if ((ent->dev->is_rep) || (ent->is_tmp))
		return;

	/* verify that the kobj still exists */
	if (kref_read(&ent->co.kobj.kref) == 0)
		return;

	kobject_put(&ent->co.kobj);
}

static void mlx5_mkey_cache_sysfs_cleanup(struct mlx5_ib_dev *dev)
{
	/* verify that the kobj exists */
	if (kref_read(&dev->mr_cache.kref) != 0)
		kobject_put(&dev->mr_cache);
}
