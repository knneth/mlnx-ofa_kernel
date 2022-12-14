/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
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
#include <rdma/ib_umem.h>
#include <rdma/ib_umem_odp.h>
#include <rdma/ib_verbs.h>
#include "mlx5_ib.h"

static void mlx5_invalidate_umem(void *invalidation_cookie,
				 struct ib_umem *umem,
				 unsigned long addr, size_t size);

enum {
	MAX_PENDING_REG_MR = 8,
	MAX_MR_RELEASE_TIMEOUT = (60 * 20) /* Allow release timeout up to 20 min */
};

#define MLX5_UMR_ALIGN 2048
#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
static __be64 mlx5_ib_update_mtt_emergency_buffer[
		MLX5_UMR_MTT_MIN_CHUNK_SIZE/sizeof(__be64)]
	__aligned(MLX5_UMR_ALIGN);
static DEFINE_MUTEX(mlx5_ib_update_mtt_emergency_buffer_mutex);
#endif

static int clean_mr(struct mlx5_ib_mr *mr);

static int mlx5_mr_sysfs_init(struct mlx5_ib_dev *dev);
static void mlx5_mr_sysfs_cleanup(struct mlx5_ib_dev *dev);

static struct mlx5_ib_mr *reg_klm(struct ib_pd *pd, struct ib_umem *umem,
				  u64 virt_addr, u64 len, int npages,
				  int page_shift, int order, int access_flags);
static int use_klm(int order);

static int destroy_mkey(struct mlx5_ib_dev *dev, struct mlx5_ib_mr *mr)
{
	int err = mlx5_core_destroy_mkey(dev->mdev, &mr->mmkey);

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	/* Wait until all page fault handlers using the mr complete. */
	synchronize_srcu(&dev->mr_srcu);
#endif

	return err;
}

static int order2idx(struct mlx5_ib_dev *dev, int order)
{
	struct mlx5_mr_cache *cache = &dev->cache;

	if (order < cache->ent[0].order)
		return 0;
	else
		return order - cache->ent[0].order;
}

static bool use_umr_mtt_update(struct mlx5_ib_mr *mr, u64 start, u64 length)
{
	return ((u64)1 << mr->order) * MLX5_ADAPTER_PAGE_SIZE >=
		length + (start & (MLX5_ADAPTER_PAGE_SIZE - 1));
}

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
static void update_odp_mr(struct mlx5_ib_mr *mr, struct mlx5_ib_dev *dev)
{
	if (mr->umem->odp_data) {
		/*
		 * This barrier prevents the compiler from moving the
		 * setting of umem->odp_data->private to point to our
		 * MR, before reg_umr finished, to ensure that the MR
		 * initialization have finished before starting to
		 * handle invalidations.
		 */
		smp_wmb();
		mr->umem->odp_data->private = mr;
		/*
		 * Make sure we will see the new
		 * umem->odp_data->private value in the invalidation
		 * routines, before we can get page faults on the
		 * MR. Page faults can happen once we put the MR in
		 * the tree, below this line. Without the barrier,
		 * there can be a fault handling and an invalidation
		 * before umem->odp_data->private == mr is visible to
		 * the invalidation handler.
		 */
		smp_wmb();
		if (dev) {
			atomic_inc(&dev->odp_stats.num_odp_mrs);
			atomic_add(ib_umem_num_pages(mr->umem),
				   &dev->odp_stats.num_odp_mr_pages);
		}
	}
}
#endif

static void reg_mr_callback(int status, void *context)
{
	struct mlx5_ib_mr *mr = context;
	struct mlx5_ib_dev *dev = mr->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	int c = order2idx(dev, mr->order);
	struct mlx5_cache_ent *ent = &cache->ent[c];
	struct mlx5_core_mkey *mkey = &mr->mmkey;
	struct mlx5_mkey_table *table = &dev->mdev->priv.mkey_table;
	unsigned long flags;
	int err;
	u8 key;

	spin_lock_irqsave(&ent->lock, flags);
	ent->pending--;
	spin_unlock_irqrestore(&ent->lock, flags);
	if (status) {
		mlx5_ib_warn(dev, "async reg mr failed. status %d\n", status);
		kfree(mr);
		dev->fill_delay = 1;
		mod_timer(&dev->delay_timer, jiffies + HZ);
		return;
	}

	spin_lock_irqsave(&dev->mdev->priv.mkey_lock, flags);
	key = dev->mdev->priv.mkey_key++;
	spin_unlock_irqrestore(&dev->mdev->priv.mkey_lock, flags);
	mkey->key = mlx5_idx_to_mkey(MLX5_GET(create_mkey_out, mr->out,
					      mkey_index)) | key;

	cache->last_add = jiffies;

	spin_lock_irqsave(&ent->lock, flags);
	list_add_tail(&mr->list, &ent->head);
	ent->cur++;
	ent->size++;
	spin_unlock_irqrestore(&ent->lock, flags);

	spin_lock_irqsave(&table->lock, flags);
	err = radix_tree_insert(&table->tree, mlx5_mkey_to_idx(mkey->key),
				mkey);
	spin_unlock_irqrestore(&table->lock, flags);
	if (err)
		pr_err("failed radix tree insert of mkey 0x%x, %d\n",
		       mkey->key, err);
}

static int add_keys(struct mlx5_ib_dev *dev, int c, int num)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[c];
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	struct mlx5_ib_mr *mr;
	int npages = 1 << ent->order;
	void *mkc;
	u32 *in;
	int err = 0;
	int i;

	in = kzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	for (i = 0; i < num; i++) {
		if (ent->pending >= MAX_PENDING_REG_MR) {
			err = -EAGAIN;
			break;
		}

		mr = kzalloc(sizeof(*mr), GFP_KERNEL);
		if (!mr) {
			err = -ENOMEM;
			break;
		}
		mr->order = ent->order;
		mr->umred = 1;
		mr->dev = dev;

		MLX5_SET(mkc, mkc, free, 1);
		MLX5_SET(mkc, mkc, umr_en, 1);
		MLX5_SET(mkc, mkc, access_mode, MLX5_MKC_ACCESS_MODE_MTT);

		MLX5_SET(mkc, mkc, qpn, 0xffffff);
		MLX5_SET(mkc, mkc, translations_octword_size, (npages + 1) / 2);
		MLX5_SET(mkc, mkc, log_page_size, 12);

		spin_lock_irq(&ent->lock);
		ent->pending++;
		spin_unlock_irq(&ent->lock);
		err = mlx5_core_create_mkey_cb(dev->mdev, &mr->mmkey,
					       in, inlen,
					       mr->out, sizeof(mr->out),
					       reg_mr_callback, mr);
		if (err) {
			spin_lock_irq(&ent->lock);
			ent->pending--;
			spin_unlock_irq(&ent->lock);
			mlx5_ib_warn(dev, "create mkey failed %d\n", err);
			kfree(mr);
			break;
		}
	}

	kfree(in);
	return err;
}

static void remove_keys(struct mlx5_ib_dev *dev, int c, int num)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[c];
	struct mlx5_ib_mr *mr;
	int err;
	int i;

	for (i = 0; i < num; i++) {
		spin_lock_irq(&ent->lock);
		if (list_empty(&ent->head)) {
			spin_unlock_irq(&ent->lock);
			return;
		}
		mr = list_first_entry(&ent->head, struct mlx5_ib_mr, list);
		list_del(&mr->list);
		ent->cur--;
		ent->size--;
		spin_unlock_irq(&ent->lock);
		err = destroy_mkey(dev, mr);
		if (err)
			mlx5_ib_warn(dev, "failed destroy mkey\n");
		else
			kfree(mr);
	}
}

static int someone_adding(struct mlx5_mr_cache *cache)
{
	int i;

	for (i = 0; i < MAX_MR_CACHE_ENTRIES; i++) {
		if (cache->ent[i].cur < cache->ent[i].limit)
			return 1;
	}

	return 0;
}

static int someone_releasing(struct mlx5_mr_cache *cache)
{
	int i;

	for (i = 0; i < MAX_MR_CACHE_ENTRIES; i++) {
		if (cache->ent[i].cur > 2 * cache->ent[i].limit)
			return 1;
	}

	return 0;
}

static void __cache_work_func(struct mlx5_cache_ent *ent)
{
	struct mlx5_ib_dev *dev = ent->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	int i = order2idx(dev, ent->order);
	int err;
	s64 dtime;

	if (cache->stopped)
		return;

	ent = &dev->cache.ent[i];
	if (ent->cur < 2 * ent->limit && !dev->fill_delay) {
		err = add_keys(dev, i, 1);
		if (ent->cur < 2 * ent->limit) {
			if (err == -EAGAIN) {
				mlx5_ib_dbg(dev, "returned eagain, order %d\n",
					    i + 2);
				cancel_delayed_work(&ent->dwork);
				queue_delayed_work(cache->wq, &ent->dwork,
						   msecs_to_jiffies(3));
			} else if (err) {
				mlx5_ib_warn(dev, "command failed order %d, err %d\n",
					     i + 2, err);
				cancel_delayed_work(&ent->dwork);
				queue_delayed_work(cache->wq, &ent->dwork,
						   msecs_to_jiffies(1000));
			} else {
				queue_work(cache->wq, &ent->work);
			}
		}
	} else if (ent->cur > 2 * ent->limit) {
		/*
		 * The remove_keys() logic is performed as garbage collection
		 * task. Such task is intended to be run when no other active
		 * processes are running.
		 *
		 * The need_resched() will return TRUE if there are user tasks
		 * to be activated in near future.
		 *
		 * In such case, we don't execute remove_keys() and postpone
		 * the garbage collection work to try to run in next cycle,
		 * in order to free CPU resources to other tasks.
		 */
		dtime = (cache->last_add + (s64)cache->rel_timeout * HZ) -
			jiffies;
		if (cache->rel_imm ||
		    (cache->rel_timeout >= 0 && !someone_adding(cache) &&
		     dtime <= 0)) {
			remove_keys(dev, i, 1);
			if (ent->cur > ent->limit)
				queue_work(cache->wq, &ent->work);
		} else if (cache->rel_timeout >= 0) {
			dtime = max_t(s64, dtime, 0);
			dtime = min_t(s64, dtime, (MAX_MR_RELEASE_TIMEOUT * HZ));
			cancel_delayed_work(&ent->dwork);
			queue_delayed_work(cache->wq, &ent->dwork, dtime);
		}
	} else if (cache->rel_imm && !someone_releasing(cache)) {
		cache->rel_imm = 0;
	}
}

static void delayed_cache_work_func(struct work_struct *work)
{
	struct mlx5_cache_ent *ent;

	ent = container_of(work, struct mlx5_cache_ent, dwork.work);
	__cache_work_func(ent);
}

static void cache_work_func(struct work_struct *work)
{
	struct mlx5_cache_ent *ent;

	ent = container_of(work, struct mlx5_cache_ent, work);
	__cache_work_func(ent);
}

static struct mlx5_ib_mr *alloc_cached_mr(struct mlx5_ib_dev *dev, int order)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_ib_mr *mr = NULL;
	struct mlx5_cache_ent *ent;
	int c;
	int i;

	c = order2idx(dev, order);
	if (c < 0 || c >= MAX_MR_CACHE_ENTRIES) {
		mlx5_ib_warn(dev, "order %d, cache index %d\n", order, c);
		return NULL;
	}

	for (i = c; i < MAX_MR_CACHE_ENTRIES; i++) {
		ent = &cache->ent[i];

		mlx5_ib_dbg(dev, "order %d, cache index %d\n", ent->order, i);

		spin_lock_irq(&ent->lock);
		if (!list_empty(&ent->head)) {
			mr = list_first_entry(&ent->head, struct mlx5_ib_mr,
					      list);
			list_del(&mr->list);
			ent->cur--;
			spin_unlock_irq(&ent->lock);
			if (ent->cur < ent->limit)
				queue_work(cache->wq, &ent->work);
			break;
		}
		spin_unlock_irq(&ent->lock);

		queue_work(cache->wq, &ent->work);
	}

	if (!mr)
		cache->ent[c].miss++;

	return mr;
}

static void free_cached_mr(struct mlx5_ib_dev *dev, struct mlx5_ib_mr *mr)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent;
	int shrink = 0;
	int c;

	c = order2idx(dev, mr->order);
	if (c < 0 || c >= MAX_MR_CACHE_ENTRIES) {
		mlx5_ib_warn(dev, "order %d, cache index %d\n", mr->order, c);
		return;
	}
	ent = &cache->ent[c];
	spin_lock_irq(&ent->lock);
	list_add_tail(&mr->list, &ent->head);
	ent->cur++;
	if (ent->cur > 2 * ent->limit)
		shrink = 1;
	spin_unlock_irq(&ent->lock);

	if (shrink)
		queue_work(cache->wq, &ent->work);
}

static void clean_keys(struct mlx5_ib_dev *dev, int c)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[c];
	struct mlx5_ib_mr *mr;
	int err;

	cancel_delayed_work(&ent->dwork);
	while (1) {
		spin_lock_irq(&ent->lock);
		if (list_empty(&ent->head)) {
			spin_unlock_irq(&ent->lock);
			return;
		}
		mr = list_first_entry(&ent->head, struct mlx5_ib_mr, list);
		list_del(&mr->list);
		ent->cur--;
		ent->size--;
		spin_unlock_irq(&ent->lock);
		err = destroy_mkey(dev, mr);
		if (err)
			mlx5_ib_warn(dev, "failed destroy mkey\n");
		else
			kfree(mr);
	}
}

static void delay_time_func(unsigned long ctx)
{
	struct mlx5_ib_dev *dev = (struct mlx5_ib_dev *)ctx;

	dev->fill_delay = 0;
}

int mlx5_mr_cache_init(struct mlx5_ib_dev *dev)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent;
	int limit;
	int err;
	int i;

	mutex_init(&dev->slow_path_mutex);
	cache->rel_timeout = 300;
	cache->wq = alloc_ordered_workqueue("mkey_cache", WQ_MEM_RECLAIM);
	if (!cache->wq) {
		mlx5_ib_warn(dev, "failed to create work queue\n");
		return -ENOMEM;
	}

	setup_timer(&dev->delay_timer, delay_time_func, (unsigned long)dev);
	for (i = 0; i < MAX_MR_CACHE_ENTRIES; i++) {
		INIT_LIST_HEAD(&cache->ent[i].head);
		spin_lock_init(&cache->ent[i].lock);

		ent = &cache->ent[i];
		INIT_LIST_HEAD(&ent->head);
		spin_lock_init(&ent->lock);
		ent->order = i + 2;
		ent->dev = dev;

		if ((dev->mdev->profile->mask & MLX5_PROF_MASK_MR_CACHE) &&
		    (mlx5_core_is_pf(dev->mdev)))
			limit = dev->mdev->profile->mr_cache[i].limit;
		else
			limit = 0;

		INIT_WORK(&ent->work, cache_work_func);
		INIT_DELAYED_WORK(&ent->dwork, delayed_cache_work_func);
		ent->limit = limit;
		queue_work(cache->wq, &ent->work);
	}

	err = mlx5_mr_sysfs_init(dev);
	if (err)
		mlx5_ib_warn(dev, "failed to init mr cache sysfs\n");

	return 0;
}

static void wait_for_async_commands(struct mlx5_ib_dev *dev)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent;
	int total = 0;
	int i;
	int j;

	for (i = 0; i < MAX_MR_CACHE_ENTRIES; i++) {
		ent = &cache->ent[i];
		for (j = 0 ; j < 1000; j++) {
			if (!ent->pending)
				break;
			msleep(50);
		}
	}
	for (i = 0; i < MAX_MR_CACHE_ENTRIES; i++) {
		ent = &cache->ent[i];
		total += ent->pending;
	}

	if (total)
		mlx5_ib_warn(dev, "aborted while there are %d pending mr requests\n", total);
	else
		mlx5_ib_warn(dev, "done with all pending requests\n");
}

int mlx5_mr_cache_cleanup(struct mlx5_ib_dev *dev)
{
	int i;

	dev->cache.stopped = 1;
	flush_workqueue(dev->cache.wq);

	mlx5_mr_sysfs_cleanup(dev);

	for (i = 0; i < MAX_MR_CACHE_ENTRIES; i++)
		clean_keys(dev, i);

	destroy_workqueue(dev->cache.wq);
	wait_for_async_commands(dev);
	del_timer_sync(&dev->delay_timer);

	return 0;
}

struct ib_mr *mlx5_ib_get_dma_mr(struct ib_pd *pd, int acc)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	struct mlx5_core_dev *mdev = dev->mdev;
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

	MLX5_SET(mkc, mkc, access_mode, MLX5_MKC_ACCESS_MODE_PA);
	MLX5_SET(mkc, mkc, a, !!(acc & IB_ACCESS_REMOTE_ATOMIC));
	MLX5_SET(mkc, mkc, rw, !!(acc & IB_ACCESS_REMOTE_WRITE));
	MLX5_SET(mkc, mkc, rr, !!(acc & IB_ACCESS_REMOTE_READ));
	MLX5_SET(mkc, mkc, lw, !!(acc & IB_ACCESS_LOCAL_WRITE));
	MLX5_SET(mkc, mkc, lr, 1);

	MLX5_SET(mkc, mkc, length64, 1);
	MLX5_SET(mkc, mkc, pd, to_mpd(pd)->pdn);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET64(mkc, mkc, start_addr, 0);

	err = mlx5_core_create_mkey(mdev, &mr->mmkey, in, inlen);
	if (err)
		goto err_in;

	kfree(in);
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

static int get_octo_len(u64 addr, u64 len, int page_size)
{
	u64 offset;
	int npages;

	offset = addr & (page_size - 1);
	npages = ALIGN(len + offset, page_size) >> ilog2(page_size);
	return (npages + 1) / 2;
}

static int use_umr(int order)
{
	return order <= MLX5_MAX_UMR_SHIFT;
}

static int dma_map_mr_pas(struct mlx5_ib_dev *dev, struct ib_umem *umem,
			  int npages, int page_shift, int *size,
			  __be64 **mr_pas, dma_addr_t *dma)
{
	__be64 *pas;
	struct device *ddev = dev->ib_dev.dma_device;

	/*
	 * UMR copies MTTs in units of MLX5_UMR_MTT_ALIGNMENT bytes.
	 * To avoid copying garbage after the pas array, we allocate
	 * a little more.
	 */
	*size = ALIGN(sizeof(u64) * npages, MLX5_UMR_MTT_ALIGNMENT);
	*mr_pas = kmalloc(*size + MLX5_UMR_ALIGN - 1, GFP_KERNEL);
	if (!(*mr_pas))
		return -ENOMEM;

	pas = PTR_ALIGN(*mr_pas, MLX5_UMR_ALIGN);
	mlx5_ib_populate_pas(dev, umem, page_shift, pas, MLX5_IB_MTT_PRESENT);
	/* Clear padding after the actual pages. */
	memset(pas + npages, 0, *size - npages * sizeof(u64));

	*dma = dma_map_single(ddev, pas, *size, DMA_TO_DEVICE);
	if (dma_mapping_error(ddev, *dma)) {
		kfree(*mr_pas);
		return -ENOMEM;
	}

	return 0;
}

static void prep_umr_wqe_common(struct ib_pd *pd, struct ib_send_wr *wr,
				struct ib_sge *sg, u64 dma, int n, u32 key,
				int page_shift)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_umr_wr *umrwr = umr_wr(wr);

	sg->addr = dma;
	sg->length = ALIGN(sizeof(u64) * n, 64);
	sg->lkey = dev->umrc.pd->local_dma_lkey;

	wr->next = NULL;
	wr->sg_list = sg;
	if (n)
		wr->num_sge = 1;
	else
		wr->num_sge = 0;

	wr->opcode = MLX5_IB_WR_UMR;

	umrwr->npages = n;
	umrwr->page_shift = page_shift;
	umrwr->mkey = key;
}

static void prep_umr_reg_wqe(struct ib_pd *pd, struct ib_send_wr *wr,
			     struct ib_sge *sg, u64 dma, int n, u32 key,
			     int page_shift, u64 virt_addr, u64 len,
			     int access_flags)
{
	struct mlx5_umr_wr *umrwr = umr_wr(wr);

	prep_umr_wqe_common(pd, wr, sg, dma, n, key, page_shift);

	wr->send_flags = 0;

	umrwr->target.virt_addr = virt_addr;
	umrwr->length = len;
	umrwr->access_flags = access_flags;
	umrwr->pd = pd;
}

static void prep_umr_unreg_wqe(struct mlx5_ib_dev *dev,
			       struct ib_send_wr *wr, u32 key)
{
	struct mlx5_umr_wr *umrwr = umr_wr(wr);

	wr->send_flags = MLX5_IB_SEND_UMR_UNREG | MLX5_IB_SEND_UMR_FAIL_IF_FREE;
	wr->opcode = MLX5_IB_WR_UMR;
	umrwr->mkey = key;
}

static struct ib_umem *mr_umem_get(struct ib_pd *pd, u64 start, u64 length,
				   int access_flags, int *npages,
				   int *page_shift, int *ncont, int *order, int peer_mem_flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct ib_umem *umem = ib_umem_get(pd->uobject->context, start, length,
					   access_flags, 0, peer_mem_flags);
	if (IS_ERR(umem)) {
		mlx5_ib_err(dev, "umem get failed (%ld)\n", PTR_ERR(umem));
		return (void *)umem;
	}

	mlx5_ib_cont_pages(umem, start, MLX5_MKEY_PAGE_SHIFT_MASK, npages,
			   page_shift, ncont, order);
	if (!*npages) {
		mlx5_ib_warn(dev, "avoid zero region\n");
		ib_umem_release(umem);
		return ERR_PTR(-EINVAL);
	}

	mlx5_ib_dbg(dev, "npages %d, ncont %d, order %d, page_shift %d\n",
		    *npages, *ncont, *order, *page_shift);

	return umem;
}

static void mlx5_ib_umr_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct mlx5_ib_umr_context *context =
		container_of(wc->wr_cqe, struct mlx5_ib_umr_context, cqe);

	context->status = wc->status;
	complete(&context->done);
}

static inline void mlx5_ib_init_umr_context(struct mlx5_ib_umr_context *context)
{
	context->cqe.done = mlx5_ib_umr_done;
	context->status = -1;
	init_completion(&context->done);
}

static struct mlx5_ib_mr *reg_umr(struct ib_pd *pd, struct ib_umem *umem,
				  u64 virt_addr, u64 len, int npages,
				  int page_shift, int order, int access_flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct device *ddev = dev->ib_dev.dma_device;
	struct umr_common *umrc = &dev->umrc;
	struct mlx5_ib_umr_context umr_context;
	struct mlx5_umr_wr umrwr = {};
	struct ib_send_wr *bad;
	struct mlx5_ib_mr *mr;
	struct ib_sge sg;
	int size;
	__be64 *mr_pas;
	dma_addr_t dma;
	int err = 0;
	int i;

	for (i = 0; i < 1; i++) {
		mr = alloc_cached_mr(dev, order);
		if (mr)
			break;

		err = add_keys(dev, order2idx(dev, order), 1);
		if (err && err != -EAGAIN) {
			mlx5_ib_warn(dev, "add_keys failed, err %d\n", err);
			break;
		}
	}

	if (!mr)
		return ERR_PTR(-EAGAIN);

	err = dma_map_mr_pas(dev, umem, npages, page_shift, &size, &mr_pas,
			     &dma);
	if (err)
		goto free_mr;

	mlx5_ib_init_umr_context(&umr_context);

	umrwr.wr.wr_cqe = &umr_context.cqe;
	prep_umr_reg_wqe(pd, &umrwr.wr, &sg, dma, npages, mr->mmkey.key,
			 page_shift, virt_addr, len, access_flags);

	down(&umrc->sem);
	err = ib_post_send(umrc->qp, &umrwr.wr, &bad);
	if (err) {
		mlx5_ib_warn(dev, "post send failed, err %d\n", err);
		goto unmap_dma;
	} else {
		wait_for_completion(&umr_context.done);
		if (umr_context.status != IB_WC_SUCCESS) {
			mlx5_ib_warn(dev, "reg umr failed\n");
			err = -EFAULT;
		}
	}

	mr->mmkey.iova = virt_addr;
	mr->mmkey.size = len;
	mr->mmkey.pd = to_mpd(pd)->pdn;

	mr->live = 1;

unmap_dma:
	up(&umrc->sem);
	dma_unmap_single(ddev, dma, size, DMA_TO_DEVICE);

	kfree(mr_pas);

free_mr:
	if (err) {
		free_cached_mr(dev, mr);
		return ERR_PTR(err);
	}

	return mr;
}

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
int mlx5_ib_update_mtt(struct mlx5_ib_mr *mr, u64 start_page_index, int npages,
		       int zap)
{
	struct mlx5_ib_dev *dev = mr->dev;
	struct device *ddev = dev->ib_dev.dma_device;
	struct umr_common *umrc = &dev->umrc;
	struct mlx5_ib_umr_context umr_context;
	struct ib_umem *umem = mr->umem;
	int size;
	__be64 *pas;
	dma_addr_t dma;
	struct ib_send_wr *bad;
	struct mlx5_umr_wr wr;
	struct ib_sge sg;
	int err = 0;
	const int page_index_alignment = MLX5_UMR_MTT_ALIGNMENT / sizeof(u64);
	const int page_index_mask = page_index_alignment - 1;
	size_t pages_mapped = 0;
	size_t pages_to_map = 0;
	size_t pages_iter = 0;
	int use_emergency_buf = 0;

	/* UMR copies MTTs in units of MLX5_UMR_MTT_ALIGNMENT bytes,
	 * so we need to align the offset and length accordingly */
	if (start_page_index & page_index_mask) {
		npages += start_page_index & page_index_mask;
		start_page_index &= ~page_index_mask;
	}

	pages_to_map = ALIGN(npages, page_index_alignment);

	if (start_page_index + pages_to_map > MLX5_MAX_UMR_PAGES)
		return -EINVAL;

	size = sizeof(u64) * pages_to_map;
	size = min_t(int, PAGE_SIZE, size);
	/* We allocate with GFP_ATOMIC to avoid recursion into page-reclaim
	 * code, when we are called from an invalidation. The pas buffer must
	 * be 2k-aligned for Connect-IB. */
	pas = (__be64 *)get_zeroed_page(GFP_ATOMIC);
	if (!pas) {
		mlx5_ib_warn(dev, "unable to allocate memory during MTT update, falling back to slower chunked mechanism.\n");
		pas = mlx5_ib_update_mtt_emergency_buffer;
		size = MLX5_UMR_MTT_MIN_CHUNK_SIZE;
		use_emergency_buf = 1;
		mutex_lock(&mlx5_ib_update_mtt_emergency_buffer_mutex);
		memset(pas, 0, size);
	}
	pages_iter = size / sizeof(u64);
	dma = dma_map_single(ddev, pas, size, DMA_TO_DEVICE);
	if (dma_mapping_error(ddev, dma)) {
		mlx5_ib_err(dev, "unable to map DMA during MTT update.\n");
		err = -ENOMEM;
		goto free_pas;
	}

	for (pages_mapped = 0;
	     pages_mapped < pages_to_map && !err;
	     pages_mapped += pages_iter, start_page_index += pages_iter) {
		dma_sync_single_for_cpu(ddev, dma, size, DMA_TO_DEVICE);

		npages = min_t(size_t,
			       pages_iter,
			       ib_umem_num_pages(umem) - start_page_index);

		if (!zap) {
			__mlx5_ib_populate_pas(dev, umem, PAGE_SHIFT,
					       start_page_index, npages, pas,
					       MLX5_IB_MTT_PRESENT);
			/* Clear padding after the pages brought from the
			 * umem. */
			memset(pas + npages, 0, size - npages * sizeof(u64));
		}

		dma_sync_single_for_device(ddev, dma, size, DMA_TO_DEVICE);

		mlx5_ib_init_umr_context(&umr_context);

		memset(&wr, 0, sizeof(wr));
		wr.wr.wr_cqe = &umr_context.cqe;

		sg.addr = dma;
		sg.length = ALIGN(npages * sizeof(u64),
				MLX5_UMR_MTT_ALIGNMENT);
		sg.lkey = dev->umrc.pd->local_dma_lkey;

		wr.wr.send_flags = MLX5_IB_SEND_UMR_FAIL_IF_FREE |
				MLX5_IB_SEND_UMR_UPDATE_MTT;
		wr.wr.sg_list = &sg;
		wr.wr.num_sge = 1;
		wr.wr.opcode = MLX5_IB_WR_UMR;
		wr.npages = sg.length / sizeof(u64);
		wr.page_shift = PAGE_SHIFT;
		wr.mkey = mr->mmkey.key;
		wr.target.offset = start_page_index;

		down(&umrc->sem);
		err = ib_post_send(umrc->qp, &wr.wr, &bad);
		if (err) {
			mlx5_ib_err(dev, "UMR post send failed, err %d\n", err);
		} else {
			wait_for_completion(&umr_context.done);
			if (umr_context.status != IB_WC_SUCCESS) {
				mlx5_ib_err(dev, "UMR completion failed, code %d\n",
					    umr_context.status);
				err = -EFAULT;
			}
		}
		up(&umrc->sem);
	}
	dma_unmap_single(ddev, dma, size, DMA_TO_DEVICE);

free_pas:
	if (!use_emergency_buf)
		free_page((unsigned long)pas);
	else
		mutex_unlock(&mlx5_ib_update_mtt_emergency_buffer_mutex);

	return err;
}
#endif

/*
 * If ibmr is NULL it will be allocated by reg_create.
 * Else, the given ibmr will be used.
 */
static struct mlx5_ib_mr *reg_create(struct ib_mr *ibmr, struct ib_pd *pd,
				     u64 virt_addr, u64 length,
				     struct ib_umem *umem, int npages,
				     int page_shift, int access_flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_ib_mr *mr;
	__be64 *pas;
	void *mkc;
	int inlen;
	u32 *in;
	int err;
	bool pg_cap = !!(MLX5_CAP_GEN(dev->mdev, pg));

	mr = ibmr ? to_mmr(ibmr) : kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	inlen = MLX5_ST_SZ_BYTES(create_mkey_in) +
		sizeof(*pas) * ((npages + 1) / 2) * 2;
	in = mlx5_vzalloc(inlen);
	if (!in) {
		err = -ENOMEM;
		goto err_1;
	}
	pas = (__be64 *)MLX5_ADDR_OF(create_mkey_in, in, klm_pas_mtt);
	mlx5_ib_populate_pas(dev, umem, page_shift, pas,
			     pg_cap ? MLX5_IB_MTT_PRESENT : 0);

	/* The pg_access bit allows setting the access flags
	 * in the page list submitted with the command. */
	MLX5_SET(create_mkey_in, in, pg_access, !!(pg_cap));

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, access_mode, MLX5_MKC_ACCESS_MODE_MTT);
	MLX5_SET(mkc, mkc, a, !!(access_flags & IB_ACCESS_REMOTE_ATOMIC));
	MLX5_SET(mkc, mkc, rw, !!(access_flags & IB_ACCESS_REMOTE_WRITE));
	MLX5_SET(mkc, mkc, rr, !!(access_flags & IB_ACCESS_REMOTE_READ));
	MLX5_SET(mkc, mkc, lw, !!(access_flags & IB_ACCESS_LOCAL_WRITE));
	MLX5_SET(mkc, mkc, lr, 1);

	MLX5_SET64(mkc, mkc, start_addr, virt_addr);
	MLX5_SET64(mkc, mkc, len, length);
	MLX5_SET(mkc, mkc, pd, to_mpd(pd)->pdn);
	MLX5_SET(mkc, mkc, bsf_octword_size, 0);
	MLX5_SET(mkc, mkc, translations_octword_size,
		 get_octo_len(virt_addr, length, 1 << page_shift));
	MLX5_SET(mkc, mkc, log_page_size, page_shift);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET(create_mkey_in, in, translations_octword_actual_size,
		 get_octo_len(virt_addr, length, 1 << page_shift));

	err = mlx5_core_create_mkey(dev->mdev, &mr->mmkey, in, inlen);
	if (err) {
		mlx5_ib_warn(dev, "create mkey failed\n");
		goto err_2;
	}
	mr->umem = umem;
	mr->dev = dev;
	mr->live = 1;
	kvfree(in);

	mlx5_ib_dbg(dev, "mkey = 0x%x\n", mr->mmkey.key);

	return mr;

err_2:
	kvfree(in);

err_1:
	if (!ibmr)
		kfree(mr);

	return ERR_PTR(err);
}

static void set_mr_fileds(struct mlx5_ib_dev *dev, struct mlx5_ib_mr *mr,
			  int npages, u64 length, int access_flags)
{
	mr->npages = npages;
	atomic_add(npages, &dev->mdev->priv.reg_pages);
	mr->ibmr.lkey = mr->mmkey.key;
	mr->ibmr.rkey = mr->mmkey.key;
	mr->ibmr.length = length;
	mr->access_flags = access_flags;
}

struct ib_mr *mlx5_ib_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				  u64 virt_addr, int access_flags,
				  struct ib_udata *udata, int mr_id)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_ib_mr *mr = NULL;
	struct ib_umem *umem;
	int page_shift;
	int npages;
	int ncont;
	int order;
	int err;
	struct ib_peer_memory_client *ib_peer_mem;
	struct mlx5_ib_peer_id *mlx5_ib_peer_id = NULL;


	if (access_flags & IB_EXP_ACCESS_PHYSICAL_ADDR)
		return mlx5_ib_phys_addr(pd, length, virt_addr, access_flags);

	mlx5_ib_dbg(dev, "start 0x%llx, virt_addr 0x%llx, length 0x%llx, access_flags 0x%x\n",
		    start, virt_addr, length, access_flags);
	umem = mr_umem_get(pd, start, length, access_flags, &npages,
			   &page_shift, &ncont, &order, IB_PEER_MEM_ALLOW | IB_PEER_MEM_INVAL_SUPP);

	if (IS_ERR(umem))
		return (void *)umem;

	ib_peer_mem = umem->ib_peer_mem;
	if (ib_peer_mem) {
		mlx5_ib_peer_id = kzalloc(sizeof(*mlx5_ib_peer_id), GFP_KERNEL);
		if (!mlx5_ib_peer_id) {
			err = -ENOMEM;
			goto error;
		}

		init_completion(&mlx5_ib_peer_id->comp);
		err = ib_umem_activate_invalidation_notifier(umem, mlx5_invalidate_umem,
							     mlx5_ib_peer_id);
		if (err)
			goto error;
	}

	if (use_umr(order)) {
		mr = reg_umr(pd, umem, virt_addr, length, ncont, page_shift,
			     order, access_flags);
		if (PTR_ERR(mr) == -EAGAIN) {
			mlx5_ib_dbg(dev, "cache empty for order %d", order);
			mr = NULL;
		}
	} else if (use_klm(order) && !(access_flags & IB_ACCESS_ON_DEMAND)) {
		mr = reg_klm(pd, umem, virt_addr, length, ncont, page_shift,
			     order, access_flags);
		if (IS_ERR(mr)) {
			mlx5_ib_dbg(dev, "reg_klm failed for order %d (%ld)", order, PTR_ERR(mr));
			mr = NULL;
		}
	} else if (access_flags & IB_ACCESS_ON_DEMAND) {
		err = -EINVAL;
		pr_err("Got MR registration for ODP MR > 512MB, not supported for Connect-IB");
		goto error;
	}

	if (!mr) {
		mutex_lock(&dev->slow_path_mutex);
		mr = reg_create(NULL, pd, virt_addr, length, umem, ncont,
				page_shift, access_flags);
		mutex_unlock(&dev->slow_path_mutex);
	}

	if (IS_ERR(mr)) {
		err = PTR_ERR(mr);
		goto error;
	}

	mlx5_ib_dbg(dev, "mkey 0x%x\n", mr->mmkey.key);

	mr->umem = umem;
	set_mr_fileds(dev, mr, npages, length, access_flags);
	atomic_set(&mr->invalidated, 0);
	if (ib_peer_mem) {
		init_completion(&mr->invalidation_comp);
		mlx5_ib_peer_id->mr = mr;
		mr->peer_id = mlx5_ib_peer_id;
		complete(&mlx5_ib_peer_id->comp);
	}

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	update_odp_mr(mr, dev);
#endif

	return &mr->ibmr;

error:
	if (mlx5_ib_peer_id)
		complete(&mlx5_ib_peer_id->comp);

	ib_umem_release(umem);
	kfree(mlx5_ib_peer_id);
	return ERR_PTR(err);
}

static int unreg_umr(struct mlx5_ib_dev *dev, struct mlx5_ib_mr *mr)
{
	struct mlx5_core_dev *mdev = dev->mdev;
	struct umr_common *umrc = &dev->umrc;
	struct mlx5_ib_umr_context umr_context;
	struct mlx5_umr_wr umrwr = {};
	struct ib_send_wr *bad;
	int err;

	if (mdev->state == MLX5_DEVICE_STATE_INTERNAL_ERROR)
		return 0;

	mlx5_ib_init_umr_context(&umr_context);

	umrwr.wr.wr_cqe = &umr_context.cqe;
	prep_umr_unreg_wqe(dev, &umrwr.wr, mr->mmkey.key);

	down(&umrc->sem);
	err = ib_post_send(umrc->qp, &umrwr.wr, &bad);
	if (err) {
		up(&umrc->sem);
		mlx5_ib_dbg(dev, "err %d\n", err);
		goto error;
	} else {
		wait_for_completion(&umr_context.done);
		up(&umrc->sem);
	}
	if (umr_context.status != IB_WC_SUCCESS) {
		mlx5_ib_warn(dev, "unreg umr failed\n");
		err = -EFAULT;
		goto error;
	}
	return 0;

error:
	return err;
}

static int rereg_umr(struct ib_pd *pd, struct mlx5_ib_mr *mr, u64 virt_addr,
		     u64 length, int npages, int page_shift, int order,
		     int access_flags, int flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct device *ddev = dev->ib_dev.dma_device;
	struct mlx5_ib_umr_context umr_context;
	struct ib_send_wr *bad;
	struct mlx5_umr_wr umrwr = {};
	struct ib_sge sg;
	struct umr_common *umrc = &dev->umrc;
	dma_addr_t dma = 0;
	__be64 *mr_pas = NULL;
	int size;
	int err;

	mlx5_ib_init_umr_context(&umr_context);

	umrwr.wr.wr_cqe = &umr_context.cqe;
	umrwr.wr.send_flags = MLX5_IB_SEND_UMR_FAIL_IF_FREE;

	if (flags & IB_MR_REREG_TRANS) {
		err = dma_map_mr_pas(dev, mr->umem, npages, page_shift, &size,
				     &mr_pas, &dma);
		if (err)
			return err;

		umrwr.target.virt_addr = virt_addr;
		umrwr.length = length;
		umrwr.wr.send_flags |= MLX5_IB_SEND_UMR_UPDATE_TRANSLATION;
	}

	prep_umr_wqe_common(pd, &umrwr.wr, &sg, dma, npages, mr->mmkey.key,
			    page_shift);

	if (flags & IB_MR_REREG_PD) {
		umrwr.pd = pd;
		umrwr.wr.send_flags |= MLX5_IB_SEND_UMR_UPDATE_PD;
	}

	if (flags & IB_MR_REREG_ACCESS) {
		umrwr.access_flags = access_flags;
		umrwr.wr.send_flags |= MLX5_IB_SEND_UMR_UPDATE_ACCESS;
	}

	/* post send request to UMR QP */
	down(&umrc->sem);
	err = ib_post_send(umrc->qp, &umrwr.wr, &bad);

	if (err) {
		mlx5_ib_warn(dev, "post send failed, err %d\n", err);
	} else {
		wait_for_completion(&umr_context.done);
		if (umr_context.status != IB_WC_SUCCESS) {
			mlx5_ib_warn(dev, "reg umr failed (%u)\n",
				     umr_context.status);
			err = -EFAULT;
		}
	}

	up(&umrc->sem);
	if (flags & IB_MR_REREG_TRANS) {
		dma_unmap_single(ddev, dma, size, DMA_TO_DEVICE);
		kfree(mr_pas);
	}
	return err;
}

int mlx5_ib_rereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start,
			  u64 length, u64 virt_addr, int new_access_flags,
			  struct ib_pd *new_pd, struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(ib_mr->device);
	struct mlx5_ib_mr *mr = to_mmr(ib_mr);
	struct ib_pd *pd = (flags & IB_MR_REREG_PD) ? new_pd : ib_mr->pd;
	int access_flags = flags & IB_MR_REREG_ACCESS ?
			    new_access_flags :
			    mr->access_flags;
	u64 addr = (flags & IB_MR_REREG_TRANS) ? virt_addr : mr->umem->address;
	u64 len = (flags & IB_MR_REREG_TRANS) ? length : mr->umem->length;
	int page_shift = 0;
	int npages = 0;
	int ncont = 0;
	int order = 0;
	int err;

	mlx5_ib_dbg(dev, "start 0x%llx, virt_addr 0x%llx, length 0x%llx, access_flags 0x%x\n",
		    start, virt_addr, length, access_flags);

	/* Peer memory isn't supported */
	 if (mr->umem->ib_peer_mem)
		return -ENOTSUPP;

	if (flags != IB_MR_REREG_PD) {
		/*
		 * Replace umem. This needs to be done whether or not UMR is
		 * used.
		 */
		flags |= IB_MR_REREG_TRANS;
		ib_umem_release(mr->umem);
		mr->umem = mr_umem_get(pd, addr, len, access_flags, &npages,
				       &page_shift, &ncont, &order, 0);
		if (IS_ERR(mr->umem)) {
			err = PTR_ERR(mr->umem);
			mr->umem = NULL;
			return err;
		}
	}

	if (flags & IB_MR_REREG_TRANS && !use_umr_mtt_update(mr, addr, len)) {
		/*
		 * UMR can't be used - MKey needs to be replaced.
		 */
		if (mr->umred) {
			err = unreg_umr(dev, mr);
			if (err)
				mlx5_ib_warn(dev, "Failed to unregister MR\n");
		} else {
			err = destroy_mkey(dev, mr);
			if (err)
				mlx5_ib_warn(dev, "Failed to destroy MKey\n");
		}
		if (err)
			return err;

		mr = reg_create(ib_mr, pd, addr, len, mr->umem, ncont,
				page_shift, access_flags);

		if (IS_ERR(mr))
			return PTR_ERR(mr);

		mr->umred = 0;
	} else {
		/*
		 * Send a UMR WQE
		 */
		err = rereg_umr(pd, mr, addr, len, npages, page_shift,
				order, access_flags, flags);
		if (err) {
			mlx5_ib_warn(dev, "Failed to rereg UMR\n");
			return err;
		}
	}

	if (flags & IB_MR_REREG_PD) {
		ib_mr->pd = pd;
		mr->mmkey.pd = to_mpd(pd)->pdn;
	}

	if (flags & IB_MR_REREG_ACCESS)
		mr->access_flags = access_flags;

	if (flags & IB_MR_REREG_TRANS) {
		atomic_sub(mr->npages, &dev->mdev->priv.reg_pages);
		set_mr_fileds(dev, mr, npages, len, access_flags);
		mr->mmkey.iova = addr;
		mr->mmkey.size = len;
	}
#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	update_odp_mr(mr, NULL);
#endif

	return 0;
}

static int
mlx5_alloc_priv_descs(struct ib_device *device,
		      struct mlx5_ib_mr *mr,
		      int ndescs,
		      int desc_size)
{
	int size = ndescs * desc_size;
	int add_size;
	int ret;

	add_size = max_t(int, MLX5_UMR_ALIGN - ARCH_KMALLOC_MINALIGN, 0);

	mr->descs_alloc = kzalloc(size + add_size, GFP_KERNEL);
	if (!mr->descs_alloc)
		return -ENOMEM;

	mr->descs = PTR_ALIGN(mr->descs_alloc, MLX5_UMR_ALIGN);

	mr->desc_map = dma_map_single(device->dma_device, mr->descs,
				      size, DMA_TO_DEVICE);
	if (dma_mapping_error(device->dma_device, mr->desc_map)) {
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
	if (mr->descs) {
		struct ib_device *device = mr->ibmr.device;
		int size = mr->max_descs * mr->desc_size;

		dma_unmap_single(device->dma_device, mr->desc_map,
				 size, DMA_TO_DEVICE);
		kfree(mr->descs_alloc);
		mr->descs = NULL;
	}
}

static int clean_mr(struct mlx5_ib_mr *mr)
{
	struct mlx5_ib_dev *dev = to_mdev(mr->ibmr.device);
	int umred = mr->umred;
	int err;
	int i;

	if (mr->sig) {
		if (mlx5_core_destroy_psv(dev->mdev,
					  mr->sig->psv_memory.psv_idx))
			mlx5_ib_warn(dev, "failed to destroy mem psv %d\n",
				     mr->sig->psv_memory.psv_idx);
		if (mlx5_core_destroy_psv(dev->mdev,
					  mr->sig->psv_wire.psv_idx))
			mlx5_ib_warn(dev, "failed to destroy wire psv %d\n",
				     mr->sig->psv_wire.psv_idx);
		kfree(mr->sig);
		mr->sig = NULL;
	}

	mlx5_free_priv_descs(mr);

	if (!umred) {
		for (i = 0; i < mr->nchild; ++i) {
			if (unreg_umr(dev, mr->children[i]))
				mlx5_ib_warn(dev, "child %d\n", i);

			free_cached_mr(dev, mr->children[i]);
		}
		kfree(mr->children);
		err = destroy_mkey(dev, mr);
		if (err) {
			mlx5_ib_warn(dev, "failed to destroy mkey 0x%x (%d)\n",
				     mr->mmkey.key, err);
			return err;
		}
	} else {
		err = unreg_umr(dev, mr);
		if (err) {
			mlx5_ib_warn(dev, "failed unregister\n");
			return err;
		}
	}

	return 0;
}

int mlx5_ib_invalidate_mr(struct ib_mr *ibmr)
{
	struct mlx5_ib_dev *dev = to_mdev(ibmr->device);
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	int npages = mr->npages;
	struct ib_umem *umem = mr->umem;
	int err;

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	if (umem && umem->odp_data) {
		/* Prevent new page faults from succeeding */
		mr->live = 0;
		/* Wait for all running page-fault handlers to finish. */
		synchronize_srcu(&dev->mr_srcu);
		/* Destroy all page mappings */
		mlx5_ib_invalidate_range(umem, ib_umem_start(umem),
					 ib_umem_end(umem));
		atomic_dec(&dev->odp_stats.num_odp_mrs);

		atomic_sub(ib_umem_num_pages(mr->umem),
			   &dev->odp_stats.num_odp_mr_pages);
		/*
		 * We kill the umem before the MR for ODP,
		 * so that there will not be any invalidations in
		 * flight, looking at the *mr struct.
		 */
		ib_umem_release(umem);
		atomic_sub(npages, &dev->mdev->priv.reg_pages);

		/* Avoid double-freeing the umem. */
		umem = NULL;
	}
#endif

	err = clean_mr(mr);
	if (err)
		return err;

	if (umem) {
		ib_umem_release(umem);
		atomic_sub(npages, &dev->mdev->priv.reg_pages);
	}

	return 0;
}

int mlx5_ib_dereg_mr(struct ib_mr *ibmr)
{
	struct mlx5_ib_dev *dev = to_mdev(ibmr->device);
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	int ret = 0;
	int umred = mr->umred;

	if (atomic_inc_return(&mr->invalidated) > 1) {
		/* In case there is inflight invalidation call pending for its termination */
		wait_for_completion(&mr->invalidation_comp);
	} else {
		ret = mlx5_ib_invalidate_mr(ibmr);
		if (ret) {
			atomic_set(&mr->invalidated, 0);
			return ret;
		}
	}

	kfree(mr->peer_id);
	mr->peer_id = NULL;

	if (umred) {
		atomic_set(&mr->invalidated, 0);
		free_cached_mr(dev, mr);
	} else
		kfree(mr);

	return 0;
}

struct ib_mr *mlx5_ib_alloc_mr(struct ib_pd *pd,
			       enum ib_mr_type mr_type,
			       u32 max_num_sg)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	int ndescs = ALIGN(max_num_sg, 4);
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
	MLX5_SET(mkc, mkc, free, 1);
	MLX5_SET(mkc, mkc, translations_octword_size, ndescs);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET(mkc, mkc, pd, to_mpd(pd)->pdn);

	if (mr_type == IB_MR_TYPE_MEM_REG) {
		mr->access_mode = MLX5_MKC_ACCESS_MODE_MTT;
		MLX5_SET(mkc, mkc, log_page_size, PAGE_SHIFT);
		err = mlx5_alloc_priv_descs(pd->device, mr,
					    ndescs, sizeof(u64));
		if (err)
			goto err_free_in;

		mr->desc_size = sizeof(u64);
		mr->max_descs = ndescs;
	} else if (mr_type == IB_MR_TYPE_SG_GAPS) {
		mr->access_mode = MLX5_MKC_ACCESS_MODE_KLMS;

		err = mlx5_alloc_priv_descs(pd->device, mr,
					    ndescs, sizeof(struct mlx5_klm));
		if (err)
			goto err_free_in;
		mr->desc_size = sizeof(struct mlx5_klm);
		mr->max_descs = ndescs;
	} else if (mr_type == IB_MR_TYPE_SIGNATURE) {
		u32 psv_index[2];

		MLX5_SET(mkc, mkc, bsf_en, 1);
		MLX5_SET(mkc, mkc, bsf_octword_size, MLX5_MKEY_BSF_OCTO_SIZE);
		mr->sig = kzalloc(sizeof(*mr->sig), GFP_KERNEL);
		if (!mr->sig) {
			err = -ENOMEM;
			goto err_free_in;
		}

		/* create mem & wire PSVs */
		err = mlx5_core_create_psv(dev->mdev, to_mpd(pd)->pdn,
					   2, psv_index);
		if (err)
			goto err_free_sig;

		mr->access_mode = MLX5_MKC_ACCESS_MODE_KLMS;
		mr->sig->psv_memory.psv_idx = psv_index[0];
		mr->sig->psv_wire.psv_idx = psv_index[1];

		mr->sig->sig_status_checked = true;
		mr->sig->sig_err_exists = false;
		/* Next UMR, Arm SIGERR */
		++mr->sig->sigerr_count;
	} else if (mr_type == IB_MR_INDIRECT_REG) {
		MLX5_SET(mkc, mkc, translations_octword_size,
			 ALIGN(max_num_sg + 1, 4));
		mr->access_mode = MLX5_MKC_ACCESS_MODE_KLMS | MLX5_PERM_UMR_EN;
		mr->max_descs = ndescs;
	} else {
		mlx5_ib_warn(dev, "Invalid mr type %d\n", mr_type);
		err = -EINVAL;
		goto err_free_in;
	}

	MLX5_SET(mkc, mkc, access_mode, mr->access_mode);
	MLX5_SET(mkc, mkc, umr_en, 1);

	err = mlx5_core_create_mkey(dev->mdev, &mr->mmkey, in, inlen);
	if (err)
		goto err_destroy_psv;

	mr->ibmr.lkey = mr->mmkey.key;
	mr->ibmr.rkey = mr->mmkey.key;
	mr->umem = NULL;
	kfree(in);

	return &mr->ibmr;

err_destroy_psv:
	if (mr->sig) {
		if (mlx5_core_destroy_psv(dev->mdev,
					  mr->sig->psv_memory.psv_idx))
			mlx5_ib_warn(dev, "failed to destroy mem psv %d\n",
				     mr->sig->psv_memory.psv_idx);
		if (mlx5_core_destroy_psv(dev->mdev,
					  mr->sig->psv_wire.psv_idx))
			mlx5_ib_warn(dev, "failed to destroy wire psv %d\n",
				     mr->sig->psv_wire.psv_idx);
	}
	mlx5_free_priv_descs(mr);
err_free_sig:
	kfree(mr->sig);
err_free_in:
	kfree(in);
err_free:
	kfree(mr);
	return ERR_PTR(err);
}

struct ib_mw *mlx5_ib_alloc_mw(struct ib_pd *pd, enum ib_mw_type type,
			       struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	struct mlx5_ib_mw *mw = NULL;
	u32 *in = NULL;
	void *mkc;
	int ndescs;
	int err;
	struct mlx5_ib_alloc_mw req = {};
	struct {
		__u32	comp_mask;
		__u32	response_length;
	} resp = {};

	err = ib_copy_from_udata(&req, udata, min(udata->inlen, sizeof(req)));
	if (err)
		return ERR_PTR(err);

	if (req.comp_mask || req.reserved1 || req.reserved2)
		return ERR_PTR(-EOPNOTSUPP);

	if (udata->inlen > sizeof(req) &&
	    !ib_is_udata_cleared(udata, sizeof(req),
				 udata->inlen - sizeof(req)))
		return ERR_PTR(-EOPNOTSUPP);

	ndescs = req.num_klms ? roundup(req.num_klms, 4) : roundup(1, 4);

	mw = kzalloc(sizeof(*mw), GFP_KERNEL);
	in = kzalloc(inlen, GFP_KERNEL);
	if (!mw || !in) {
		err = -ENOMEM;
		goto free;
	}

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);

	MLX5_SET(mkc, mkc, free, 1);
	MLX5_SET(mkc, mkc, translations_octword_size, ndescs);
	MLX5_SET(mkc, mkc, pd, to_mpd(pd)->pdn);
	MLX5_SET(mkc, mkc, umr_en, 1);
	MLX5_SET(mkc, mkc, lr, 1);
	MLX5_SET(mkc, mkc, access_mode, MLX5_MKC_ACCESS_MODE_KLMS);
	MLX5_SET(mkc, mkc, en_rinval, !!((type == IB_MW_TYPE_2)));
	MLX5_SET(mkc, mkc, qpn, 0xffffff);

	err = mlx5_core_create_mkey(dev->mdev, &mw->mmkey, in, inlen);
	if (err)
		goto free;

	mw->ibmw.rkey = mw->mmkey.key;

	resp.response_length = min(offsetof(typeof(resp), response_length) +
				   sizeof(resp.response_length), udata->outlen);
	if (resp.response_length) {
		err = ib_copy_to_udata(udata, &resp, resp.response_length);
		if (err) {
			mlx5_core_destroy_mkey(dev->mdev, &mw->mmkey);
			goto free;
		}
	}

	kfree(in);
	return &mw->ibmw;

free:
	kfree(mw);
	kfree(in);
	return ERR_PTR(err);
}

int mlx5_ib_dealloc_mw(struct ib_mw *mw)
{
	struct mlx5_ib_mw *mmw = to_mmw(mw);
	int err;

	err =  mlx5_core_destroy_mkey((to_mdev(mw->device))->mdev,
				      &mmw->mmkey);
	if (!err)
		kfree(mmw);
	return err;
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
mlx5_ib_sg_to_klms(struct mlx5_ib_mr *mr,
		   struct scatterlist *sgl,
		   unsigned short sg_nents,
		   unsigned int *sg_offset_p)
{
	struct scatterlist *sg = sgl;
	struct mlx5_klm *klms = mr->descs;
	unsigned int sg_offset = sg_offset_p ? *sg_offset_p : 0;
	u32 lkey = mr->ibmr.pd->local_dma_lkey;
	int i;

	mr->ibmr.iova = sg_dma_address(sg) + sg_offset;
	mr->ibmr.length = 0;
	mr->ndescs = sg_nents;

	for_each_sg(sgl, sg, sg_nents, i) {
		if (unlikely(i > mr->max_descs))
			break;
		klms[i].va = cpu_to_be64(sg_dma_address(sg) + sg_offset);
		klms[i].bcount = cpu_to_be32(sg_dma_len(sg) - sg_offset);
		klms[i].key = cpu_to_be32(lkey);
		mr->ibmr.length += sg_dma_len(sg);

		sg_offset = 0;
	}

	if (sg_offset_p)
		*sg_offset_p = sg_offset;

	return i;
}

static int mlx5_set_page(struct ib_mr *ibmr, u64 addr)
{
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	__be64 *descs;

	if (unlikely(mr->ndescs == mr->max_descs))
		return -ENOMEM;

	descs = mr->descs;
	descs[mr->ndescs++] = cpu_to_be64(addr | MLX5_EN_RD | MLX5_EN_WR);

	return 0;
}

int mlx5_ib_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg, int sg_nents,
		      unsigned int *sg_offset)
{
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	int n;

	mr->ndescs = 0;

	ib_dma_sync_single_for_cpu(ibmr->device, mr->desc_map,
				   mr->desc_size * mr->max_descs,
				   DMA_TO_DEVICE);

	if (mr->access_mode == MLX5_MKC_ACCESS_MODE_KLMS)
		n = mlx5_ib_sg_to_klms(mr, sg, sg_nents, sg_offset);
	else
		n = ib_sg_to_pages(ibmr, sg, sg_nents, sg_offset,
				mlx5_set_page);

	ib_dma_sync_single_for_device(ibmr->device, mr->desc_map,
				      mr->desc_size * mr->max_descs,
				      DMA_TO_DEVICE);

	return n;
}

struct order_attribute {
	struct attribute attr;
	ssize_t (*show)(struct cache_order *, struct order_attribute *, char *buf);
	ssize_t (*store)(struct cache_order *, struct order_attribute *,
			 const char *buf, size_t count);
};

static ssize_t cur_show(struct cache_order *co, struct order_attribute *oa,
			char *buf)
{
	struct mlx5_ib_dev *dev = co->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[co->index];
	int err;

	err = snprintf(buf, 20, "%d\n", ent->cur);
	return err;
}

static ssize_t limit_show(struct cache_order *co, struct order_attribute *oa,
			  char *buf)
{
	struct mlx5_ib_dev *dev = co->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[co->index];
	int err;

	err = snprintf(buf, 20, "%d\n", ent->limit);
	return err;
}

static ssize_t limit_store(struct cache_order *co, struct order_attribute *oa,
			   const char *buf, size_t count)
{
	struct mlx5_ib_dev *dev = co->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[co->index];
	u32 var;
	int err;

	if (kstrtouint(buf, 0, &var))
		return -EINVAL;

	if (var > ent->size)
		return -EINVAL;

	ent->limit = var;

	if (ent->cur < ent->limit) {
		err = add_keys(dev, co->index, 2 * ent->limit - ent->cur);
		if (err)
			return err;
	}

	return count;
}

static ssize_t miss_show(struct cache_order *co, struct order_attribute *oa,
			 char *buf)
{
	struct mlx5_ib_dev *dev = co->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[co->index];
	int err;

	err = snprintf(buf, 20, "%d\n", ent->miss);
	return err;
}

static ssize_t miss_store(struct cache_order *co, struct order_attribute *oa,
			  const char *buf, size_t count)
{
	struct mlx5_ib_dev *dev = co->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[co->index];
	u32 var;

	if (kstrtouint(buf, 0, &var))
		return -EINVAL;

	if (var != 0)
		return -EINVAL;

	ent->miss = var;

	return count;
}

static ssize_t size_show(struct cache_order *co, struct order_attribute *oa,
			 char *buf)
{
	struct mlx5_ib_dev *dev = co->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[co->index];
	int err;

	err = snprintf(buf, 20, "%d\n", ent->size);
	return err;
}

static ssize_t size_store(struct cache_order *co, struct order_attribute *oa,
			  const char *buf, size_t count)
{
	struct mlx5_ib_dev *dev = co->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[co->index];
	u32 var;
	int err;

	if (kstrtouint(buf, 0, &var))
		return -EINVAL;

	if (var < ent->limit)
		return -EINVAL;

	if (var > ent->size) {
		do {
			err = add_keys(dev, co->index, var - ent->size);
			if (err && err != -EAGAIN)
				return err;

			usleep_range(3000, 5000);
		} while (err);
	} else if (var < ent->size) {
		remove_keys(dev, co->index, ent->size - var);
	}

	return count;
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

static struct kobj_type order_type = {
	.sysfs_ops     = &order_sysfs_ops,
	.default_attrs = order_default_attrs
};



struct cache_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx5_ib_dev *dev, char *buf);
	ssize_t (*store)(struct mlx5_ib_dev *dev, const char *buf, size_t count);
};

static ssize_t rel_imm_show(struct mlx5_ib_dev *dev, char *buf)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	int err;

	err = snprintf(buf, 20, "%d\n", cache->rel_imm);
	return err;
}

static ssize_t rel_imm_store(struct mlx5_ib_dev *dev, const char *buf, size_t count)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	u32 var;
	int i;
	int found = 0;

	if (kstrtouint(buf, 0, &var))
		return -EINVAL;

	if (var > 1)
		return -EINVAL;

	if (var == cache->rel_imm)
		return count;

	cache->rel_imm = var;
	if (cache->rel_imm == 1) {
		for (i = 0; i < MAX_MR_CACHE_ENTRIES; i++) {
			if (cache->ent[i].cur > 2 * cache->ent[i].limit) {
				queue_work(cache->wq, &cache->ent[i].work);
				found = 1;
			}
		}
		if (!found)
			cache->rel_imm = 0;
	}

	return count;
}
static ssize_t rel_timeout_show(struct mlx5_ib_dev *dev, char *buf)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	int err;

	err = snprintf(buf, 20, "%d\n", cache->rel_timeout);
	return err;
}

static ssize_t rel_timeout_store(struct mlx5_ib_dev *dev, const char *buf, size_t count)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	int var;
	int i;

	if (kstrtoint(buf, 0, &var))
		return -EINVAL;

	if (var < -1 || var > MAX_MR_RELEASE_TIMEOUT)
		return -EINVAL;

	if (var == cache->rel_timeout)
		return count;

	if (cache->rel_timeout == -1 || (var < cache->rel_timeout && var != -1)) {
		cache->rel_timeout = var;
		for (i = 0; i < MAX_MR_CACHE_ENTRIES; i++) {
			if (cache->ent[i].cur > 2 * cache->ent[i].limit)
				queue_work(cache->wq, &cache->ent[i].work);
		}
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

static struct kobj_type cache_type = {
	.sysfs_ops     = &cache_sysfs_ops,
	.default_attrs = cache_default_attrs
};

static int mlx5_mr_sysfs_init(struct mlx5_ib_dev *dev)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct device *device = &dev->ib_dev.dev;
	struct cache_order *co;
	int o;
	int i;
	int err;

	err = kobject_init_and_add(&dev->mr_cache, &cache_type,
				   &device->kobj, "mr_cache");
	if (err)
		return -ENOMEM;

	for (o = 2, i = 0; i < MAX_MR_CACHE_ENTRIES; o++, i++) {
		co = &cache->ent[i].co;
		co->order = o;
		co->index = i;
		co->dev = dev;
		err = kobject_init_and_add(&co->kobj, &order_type,
					   &dev->mr_cache, "%d", o);
		if (err)
			goto err_put;

		kobject_uevent(&co->kobj, KOBJ_ADD);
	}

	return 0;

err_put:
	for (; i >= 0; i--) {
		co = &cache->ent[i].co;
		kobject_put(&co->kobj);
	}
	kobject_put(&dev->mr_cache);

	return err;
}

static void mlx5_mr_sysfs_cleanup(struct mlx5_ib_dev *dev)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct cache_order *co;
	int i;

	for (i = MAX_MR_CACHE_ENTRIES - 1; i >= 0; i--) {
		co = &cache->ent[i].co;
		kobject_put(&co->kobj);
	}
	kobject_put(&dev->mr_cache);
}

static int use_klm(int order)
{
	return order <= 31;
}

enum {
	MLX5_MAX_REG_ORDER = MAX_MR_CACHE_ENTRIES + 1,
	MLX5_MAX_REG_SIZE = 2ul * 1024 * 1024 * 1024,
};

static u64 get_lsize(int page_shift)
{
	u64 l1;
	u64 l2;

	l1 = (u64)1 << (page_shift + MLX5_MAX_REG_ORDER);
	l2 = MLX5_MAX_REG_SIZE;

	if (l1 > l2)
		return l2;

	return l1;
}

static int alloc_mrs(struct mlx5_ib_dev *dev, struct mlx5_ib_mr **lmr, int n,
		     int order, u64 size, int nchild, int sorder, u64 len,
		     u64 off, int npages)
{
	int err = 0;
	int i;
	int k;

	for (i = 0, k = 0; i < n; i++) {
again:
		if (k++ > 3) {
			err = -EAGAIN;
			goto out;
		}
		lmr[i] = alloc_cached_mr(dev, order);
		if (!lmr[i]) {
			err = add_keys(dev, order2idx(dev, order), n - i);
			if (err) {
				if (err != -EAGAIN) {
					mlx5_ib_warn(dev, "add_keys failed to add %d keys (%d)\n", n - i, err);
					goto out;
				}
				msleep(20);
			}
			goto again;
		}
		lmr[i]->size = size;
		lmr[i]->page_count = 1 << order;
		k = 0;
	}

	if (nchild == n)
		return 0;

	for (k = 0; k < 3; k++) {
		lmr[i] = alloc_cached_mr(dev, sorder);
		if (lmr[i])
			break;
		err = add_keys(dev, order2idx(dev, sorder), 1);
		if (err) {
			if (err != -EAGAIN) {
				mlx5_ib_warn(dev, "add_keys failed, err %d\n", err);
				goto out;
			}
			msleep(20);
		}
	}

	if (!lmr[i]) {
		err = -EAGAIN;
		goto out;
	}
	lmr[i]->size = len - size * n + off;
	lmr[i]->page_count = npages - (n << order);

	return 0;

out:
	for (--i; i >= 0; --i)
		free_cached_mr(dev, lmr[i]);

	return err;
}

static int create_indirect_key(struct mlx5_ib_dev *dev, struct ib_pd *pd,
			       struct mlx5_ib_mr *mr, unsigned n)
{
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	void *mkc;
	u32 *in;
	int err;

	in = kzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	mr->dev = dev;
	MLX5_SET(mkc, mkc, free, 1);
	MLX5_SET(mkc, mkc, umr_en, 1);
	MLX5_SET(mkc, mkc, access_mode, MLX5_MKC_ACCESS_MODE_KLMS);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET(mkc, mkc, pd, to_mpd(pd)->pdn);
	MLX5_SET(mkc, mkc, translations_octword_size, ALIGN(n, 4));
	err = mlx5_core_create_mkey(dev->mdev, &mr->mmkey, in, inlen);

	kfree(in);
	return err;
}

static int reg_mrs(struct ib_pd *pd, struct mlx5_ib_mr **mrs, int n,
		   dma_addr_t dma, int copy, int page_shift, void *dptr,
		   __be64 *pas, int access_flags, u64 maxorder)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct umr_common *umrc = &dev->umrc;
	struct mlx5_ib_umr_context umr_context;
	struct mlx5_umr_wr umrwr = {};
	struct ib_send_wr *bad;
	struct ib_sge sg;
	int err1;
	int err;
	int i;

	for (i = 0; i < n; ++i) {
		if (copy) {
			memcpy(dptr, pas + (i << maxorder),
			       sizeof(__be64) * mrs[i]->page_count);
			mrs[i]->dma = dma;
		} else {
			mrs[i]->dma = dma + (sizeof(__be64) << maxorder) * i;
		}

		mlx5_ib_init_umr_context(&umr_context);
		umrwr.wr.wr_cqe = &umr_context.cqe;
		prep_umr_reg_wqe(pd,
				 &umrwr.wr,
				 &sg,
				 mrs[i]->dma,
				 mrs[i]->page_count,
				 mrs[i]->mmkey.key,
				 page_shift,
				 0,
				 mrs[i]->size,
				 access_flags);
		down(&umrc->sem);
		err = ib_post_send(umrc->qp, &umrwr.wr, &bad);
		if (err) {
			mlx5_ib_warn(dev, "post send failed, err %d\n", err);
			up(&umrc->sem);
			goto out;
		}
		wait_for_completion(&umr_context.done);
		up(&umrc->sem);
		if (umr_context.status != IB_WC_SUCCESS) {
			mlx5_ib_warn(dev, "reg umr failed\n");
			err = -EFAULT;
			goto out;
		}
	}
	return 0;
out:
	for (--i; i >= 0; --i) {
		err1 = unreg_umr(dev, mrs[i]);
		if (err1)
			mlx5_ib_warn(dev, "unreg_umr failed %d\n", err1);
	}

	return err;
}

static void populate_klm(void *dma, struct mlx5_ib_mr **lmr, int n, u64 off)
{
	struct mlx5_wqe_data_seg *dseg = dma;
	int i;

	for (i = 0; i < n; i++) {
		dseg[i].lkey = cpu_to_be32(lmr[i]->mmkey.key);
		if (!i) {
			dseg[i].byte_count = cpu_to_be32((u32)(lmr[i]->size - off));
			dseg[0].addr = cpu_to_be64(off);
		} else {
			dseg[i].byte_count = cpu_to_be32((u32)(lmr[i]->size));
			dseg[i].addr = 0;
		}
	}
}

static void prep_indirect_wqe(struct ib_pd *pd, struct ib_send_wr *wr,
			      struct ib_sge *sg, u64 dma, int n, u32 key,
			      int page_shift, u64 virt_addr, u64 len,
			      int access_flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_umr_wr *umrwr = umr_wr(wr);

	sg->addr = dma;
	sg->length = ALIGN(sizeof(u64) * n, 64);
	sg->lkey = dev->umrc.pd->local_dma_lkey;

	wr->next = NULL;
	wr->send_flags = 0;
	wr->sg_list = sg;
	wr->num_sge = 1;
	wr->opcode = MLX5_IB_WR_UMR;
	wr->send_flags = 0;
	/* since post send interprets this as MTTs and since a KLM
	   is two MTTs, we multiply by two to have  */
	umrwr->npages = n * 2;
	umrwr->page_shift = page_shift;
	umrwr->mkey = key;
	umrwr->target.virt_addr = virt_addr;
	umrwr->length = len;
	umrwr->access_flags = access_flags;
	umrwr->pd = pd;
}

static void free_mrs(struct mlx5_ib_dev *dev, struct mlx5_ib_mr **lmr, int n)
{
	int i;

	for (i = 0; i < n; i++)
		if (lmr[i])
			free_cached_mr(dev, lmr[i]);
}

static int get_nchild(int npages, int page_shift, u64 *maxorder, int *sorder, int *quot)
{
	int res;
	int denom;

	denom = min_t(int, 1 << MLX5_MAX_REG_ORDER, MLX5_MAX_REG_SIZE >> page_shift);
	res = npages % denom;
	*quot = npages / denom;
	*maxorder = ilog2(denom);
	*sorder = max_t(int, ilog2(roundup_pow_of_two(res)), 2);
	return *quot + (res ? 1 : 0);
}

static struct mlx5_ib_mr *reg_klm(struct ib_pd *pd, struct ib_umem *umem,
				  u64 virt_addr, u64 len, int npages,
				  int page_shift, int order, int access_flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct device *ddev = dev->ib_dev.dma_device;
	unsigned size = sizeof(__be64) * npages;
	struct umr_common *umrc = &dev->umrc;
	struct mlx5_ib_mr **lmr = NULL;
	struct mlx5_ib_mr *imr = NULL;
	struct mlx5_umr_wr umrwr = {};
	struct ib_send_wr *bad;
	struct mlx5_ib_umr_context umr_context;
	__be64 *spas = NULL;
	__be64 *pas = NULL;
	dma_addr_t dma = 0;
	unsigned dsize;
	int err = -ENOMEM;
	struct ib_sge sg;
	int nchild;
	int sorder;
	void *dptr;
	u64 lsize;
	int i = 0;
	int err1;
	int quot;
	u64 off;
	u64 maxorder;

	mlx5_ib_dbg(dev, "addr 0x%llx, len 0x%llx, npages %d, page_shift %d, order %d, access_flags 0x%x\n",
		    virt_addr, len, npages, page_shift, order, access_flags);
	lsize = get_lsize(page_shift);
	nchild = get_nchild(npages, page_shift, &maxorder, &sorder, &quot);
	off = (virt_addr & ((1 << page_shift) - 1));
	lmr = kcalloc(nchild, sizeof(*lmr), GFP_KERNEL);
	if (!lmr) {
		mlx5_ib_warn(dev, "allocation failed\n");
		err = -ENOMEM;
		goto out;
	}

	pas = mlx5_vmalloc(size);
	if (!pas) {
		mlx5_ib_warn(dev, "allocation failed\n");
		err = -ENOMEM;
		goto out;
	}

	mlx5_ib_populate_pas(dev, umem, page_shift, pas, MLX5_IB_MTT_PRESENT);
	if (is_vmalloc_addr(pas)) {
		dsize = sizeof(__be64) << maxorder;
		spas = kmalloc(dsize, GFP_KERNEL);
		if (!spas) {
			err = -ENOMEM;
			mlx5_ib_warn(dev, "allocation failed\n");
			goto out;
		}
		dptr = spas;
	} else {
		dsize = size;
		dptr = pas;
	}

	dma = dma_map_single(ddev, dptr, dsize, DMA_TO_DEVICE);
	if (dma_mapping_error(ddev, dma)) {
		err = -ENOMEM;
		mlx5_ib_warn(dev, "dma map failed\n");
		goto out;
	}

	err = alloc_mrs(dev, lmr, quot, maxorder, lsize, nchild, sorder, len, off, npages);
	if (err) {
		mlx5_ib_dbg(dev, "alloc_mrs failed\n");
		goto out_map;
	}

	imr = kzalloc(sizeof(*imr), GFP_KERNEL);
	if (!imr) {
		err = -ENOMEM;
		mlx5_ib_warn(dev, "failed allocation\n");
		goto out_mrs;
	}

	err = create_indirect_key(dev, pd, imr, nchild);
	if (err) {
		mlx5_ib_warn(dev, "failed creating indirect key %d\n", err);
		goto out_mrs;
	}
	imr->size = len;

	err = reg_mrs(pd, lmr, nchild, dma, !!spas,
		      page_shift, dptr, pas, access_flags, maxorder);
	if (err) {
		mlx5_ib_warn(dev, "reg_mrs failed %d\n", err);
		goto out_indir;
	}

	populate_klm(dptr, lmr, nchild, off);
	imr->dma = dma;

	mlx5_ib_init_umr_context(&umr_context);
	umrwr.wr.wr_cqe = &umr_context.cqe;
	prep_indirect_wqe(pd, &umrwr.wr, &sg, dma, nchild, imr->mmkey.key, page_shift,
			  virt_addr, len, access_flags);

	down(&umrc->sem);
	err = ib_post_send(umrc->qp, &umrwr.wr, &bad);
	if (err) {
		mlx5_ib_warn(dev, "post send failed, err %d\n", err);
		up(&umrc->sem);
		goto out_unreg;
	}
	wait_for_completion(&umr_context.done);
	up(&umrc->sem);
	if (umr_context.status != IB_WC_SUCCESS) {
		mlx5_ib_warn(dev, "reg umr failed\n");
		err = -EFAULT;
		goto out_unreg;
	}
	imr->children = lmr;
	imr->nchild = nchild;

	dma_unmap_single(ddev, dma, dsize, DMA_TO_DEVICE);
	kfree(spas);
	kvfree(pas);

	return imr;

out_unreg:
	for (i = 0; i < nchild; ++i) {
		err1 = unreg_umr(dev, lmr[i]);
		if (err1)
			mlx5_ib_warn(dev, "unreg_umr failed %d\n", err1);
	}
out_indir:
	err1 = mlx5_core_destroy_mkey(dev->mdev, &imr->mmkey);
	if (err1)
		mlx5_ib_warn(dev, "destroy imr mkey failed %d\n", err1);
out_mrs:
	kfree(imr);
	free_mrs(dev, lmr, nchild);
out_map:
	dma_unmap_single(ddev, dma, dsize, DMA_TO_DEVICE);
out:
	kfree(spas);
	kvfree(pas);
	kfree(lmr);
	return ERR_PTR(err);
}

static void mlx5_invalidate_umem(void *invalidation_cookie,
				 struct ib_umem *umem,
				 unsigned long addr, size_t size)
{
	struct mlx5_ib_mr *mr;
	struct mlx5_ib_peer_id *peer_id = (struct mlx5_ib_peer_id *)invalidation_cookie;

	wait_for_completion(&peer_id->comp);
	if (peer_id->mr == NULL)
		return;

	mr = peer_id->mr;
	/* This function is called under client peer lock so its resources are race protected */
	if (atomic_inc_return(&mr->invalidated) > 1) {
		umem->invalidation_ctx->inflight_invalidation = 1;
		return;
	}

	umem->invalidation_ctx->peer_callback = 1;
	mlx5_ib_invalidate_mr(&mr->ibmr);
	complete(&mr->invalidation_comp);
}
