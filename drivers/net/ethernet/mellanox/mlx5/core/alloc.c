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

#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/bitmap.h>
#include <linux/dma-mapping.h>
#include <linux/vmalloc.h>
#include <linux/mlx5/driver.h>

#include "mlx5_core.h"

struct mlx5_db_pgdir {
	struct list_head	list;
	unsigned long	       *bitmap;
	__be32		       *db_page;
	dma_addr_t		db_dma;
};

/* Handling for queue buffers -- we allocate a bunch of memory and
 * register it in a memory region at HCA virtual address 0.
 */

static void *mlx5_dma_zalloc_coherent_node(struct mlx5_core_dev *dev,
					   size_t size, dma_addr_t *dma_handle,
					   int node)
{
	struct mlx5_priv *priv = &dev->priv;
	int original_node;
	void *cpu_handle;

	/* WA for kernels that don't use numa_mem_id in alloc_pages_node */
	if (node == NUMA_NO_NODE)
#ifdef HAVE_NUMA_MEM_ID
		node = numa_mem_id();
#else
		node = first_memory_node;
#endif

	mutex_lock(&priv->alloc_mutex);
	original_node = dev_to_node(&dev->pdev->dev);
	set_dev_node(&dev->pdev->dev, node);
	cpu_handle = dma_zalloc_coherent(&dev->pdev->dev, size,
					 dma_handle, GFP_KERNEL);
	set_dev_node(&dev->pdev->dev, original_node);
	mutex_unlock(&priv->alloc_mutex);
	return cpu_handle;
}

int mlx5_buf_alloc_node(struct mlx5_core_dev *dev, int size,
			struct mlx5_buf *buf, int node)
{
	dma_addr_t t;

	buf->size = size;
	buf->npages       = 1;
	buf->page_shift   = (u8)get_order(size) + PAGE_SHIFT;
	buf->direct.buf   = mlx5_dma_zalloc_coherent_node(dev, size,
							  &t, node);
	if (!buf->direct.buf)
		return -ENOMEM;

	buf->direct.map = t;

	while (t & ((1 << buf->page_shift) - 1)) {
		--buf->page_shift;
		buf->npages *= 2;
	}

	return 0;
}

int mlx5_buf_alloc(struct mlx5_core_dev *dev, int size, struct mlx5_buf *buf)
{
	return mlx5_buf_alloc_node(dev, size, buf, dev->priv.numa_node);
}
EXPORT_SYMBOL_GPL(mlx5_buf_alloc);

void mlx5_buf_free(struct mlx5_core_dev *dev, struct mlx5_buf *buf)
{
	dma_free_coherent(&dev->pdev->dev, buf->size, buf->direct.buf,
			  buf->direct.map);
}
EXPORT_SYMBOL_GPL(mlx5_buf_free);

int mlx5_frag_buf_alloc_node(struct mlx5_core_dev *dev, int size,
			     struct mlx5_frag_buf *buf, int node)
{
	int i;

	buf->size = size;
	buf->npages = 1 << get_order(size);
	buf->page_shift = PAGE_SHIFT;
	buf->frags = kcalloc(buf->npages, sizeof(struct mlx5_buf_list),
			     GFP_KERNEL);
	if (!buf->frags)
		goto err_out;

	for (i = 0; i < buf->npages; i++) {
		struct mlx5_buf_list *frag = &buf->frags[i];
		int frag_sz = min_t(int, size, PAGE_SIZE);

		frag->buf = mlx5_dma_zalloc_coherent_node(dev, frag_sz,
							  &frag->map, node);
		if (!frag->buf)
			goto err_free_buf;
		if (frag->map & ((1 << buf->page_shift) - 1)) {
			dma_free_coherent(&dev->pdev->dev, frag_sz,
					  buf->frags[i].buf, buf->frags[i].map);
			mlx5_core_warn(dev, "unexpected map alignment: %pad, page_shift=%d\n",
				       &frag->map, buf->page_shift);
			goto err_free_buf;
		}
		size -= frag_sz;
	}

	return 0;

err_free_buf:
	while (i--)
		dma_free_coherent(&dev->pdev->dev, PAGE_SIZE, buf->frags[i].buf,
				  buf->frags[i].map);
	kfree(buf->frags);
err_out:
	return -ENOMEM;
}

void mlx5_frag_buf_free(struct mlx5_core_dev *dev, struct mlx5_frag_buf *buf)
{
	int size = buf->size;
	int i;

	for (i = 0; i < buf->npages; i++) {
		int frag_sz = min_t(int, size, PAGE_SIZE);

		dma_free_coherent(&dev->pdev->dev, frag_sz, buf->frags[i].buf,
				  buf->frags[i].map);
		size -= frag_sz;
	}
	kfree(buf->frags);
}

static struct mlx5_db_pgdir *mlx5_alloc_db_pgdir(struct mlx5_core_dev *dev,
						 int node)
{
	u32 db_per_page = PAGE_SIZE / cache_line_size();
	struct mlx5_db_pgdir *pgdir;

	pgdir = kzalloc(sizeof(*pgdir), GFP_KERNEL);
	if (!pgdir)
		return NULL;

	pgdir->bitmap = kcalloc(BITS_TO_LONGS(db_per_page),
				sizeof(unsigned long),
				GFP_KERNEL);

	if (!pgdir->bitmap) {
		kfree(pgdir);
		return NULL;
	}

	bitmap_fill(pgdir->bitmap, db_per_page);

	pgdir->db_page = mlx5_dma_zalloc_coherent_node(dev, PAGE_SIZE,
						       &pgdir->db_dma, node);
	if (!pgdir->db_page) {
		kfree(pgdir->bitmap);
		kfree(pgdir);
		return NULL;
	}

	return pgdir;
}

static int mlx5_alloc_db_from_pgdir(struct mlx5_db_pgdir *pgdir,
				    struct mlx5_db *db)
{
	u32 db_per_page = PAGE_SIZE / cache_line_size();
	int offset;
	int i;

	i = find_first_bit(pgdir->bitmap, db_per_page);
	if (i >= db_per_page)
		return -ENOMEM;

	__clear_bit(i, pgdir->bitmap);

	db->u.pgdir = pgdir;
	db->index   = i;
	offset = db->index * cache_line_size();
	db->db      = pgdir->db_page + offset / sizeof(*pgdir->db_page);
	db->dma     = pgdir->db_dma  + offset;

	db->db[0] = 0;
	db->db[1] = 0;

	return 0;
}

int mlx5_db_alloc_node(struct mlx5_core_dev *dev, struct mlx5_db *db, int node)
{
	struct mlx5_db_pgdir *pgdir;
	int ret = 0;

	mutex_lock(&dev->priv.pgdir_mutex);

	list_for_each_entry(pgdir, &dev->priv.pgdir_list, list)
		if (!mlx5_alloc_db_from_pgdir(pgdir, db))
			goto out;

	pgdir = mlx5_alloc_db_pgdir(dev, node);
	if (!pgdir) {
		ret = -ENOMEM;
		goto out;
	}

	list_add(&pgdir->list, &dev->priv.pgdir_list);

	/* This should never fail -- we just allocated an empty page: */
	WARN_ON(mlx5_alloc_db_from_pgdir(pgdir, db));

out:
	mutex_unlock(&dev->priv.pgdir_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(mlx5_db_alloc_node);

int mlx5_db_alloc(struct mlx5_core_dev *dev, struct mlx5_db *db)
{
	return mlx5_db_alloc_node(dev, db, dev->priv.numa_node);
}
EXPORT_SYMBOL_GPL(mlx5_db_alloc);

void mlx5_db_free(struct mlx5_core_dev *dev, struct mlx5_db *db)
{
	u32 db_per_page = PAGE_SIZE / cache_line_size();

	mutex_lock(&dev->priv.pgdir_mutex);

	__set_bit(db->index, db->u.pgdir->bitmap);

	if (bitmap_full(db->u.pgdir->bitmap, db_per_page)) {
		dma_free_coherent(&(dev->pdev->dev), PAGE_SIZE,
				  db->u.pgdir->db_page, db->u.pgdir->db_dma);
		list_del(&db->u.pgdir->list);
		kfree(db->u.pgdir->bitmap);
		kfree(db->u.pgdir);
	}

	mutex_unlock(&dev->priv.pgdir_mutex);
}
EXPORT_SYMBOL_GPL(mlx5_db_free);

void mlx5_fill_page_array(struct mlx5_buf *buf, __be64 *pas)
{
	u64 addr;
	int i;

	for (i = 0; i < buf->npages; i++) {
		addr = buf->direct.map + (i << buf->page_shift);

		pas[i] = cpu_to_be64(addr);
	}
}
EXPORT_SYMBOL_GPL(mlx5_fill_page_array);

void mlx5_fill_page_frag_array(struct mlx5_frag_buf *buf, __be64 *pas)
{
	int i;

	for (i = 0; i < buf->npages; i++)
		pas[i] = cpu_to_be64(buf->frags[i].map);
}
EXPORT_SYMBOL_GPL(mlx5_fill_page_frag_array);

#define MEMIC_ALLOC_MASK 0x3f
int mlx5_core_alloc_memic(struct mlx5_core_dev *dev, phys_addr_t *addr,
			  u64 length)
{
	u64 num_memic_hw_pages = MLX5_CAP_DEVICE_MEM(dev, memic_bar_size)
					>> PAGE_SHIFT;
	u64 hw_start_addr = MLX5_CAP64_DEVICE_MEM(dev, memic_bar_start_addr);
	u32 num_pages = DIV_ROUND_UP(length, PAGE_SIZE);
	u32 out[MLX5_ST_SZ_DW(alloc_memic_out)] = {0};
	u32 in[MLX5_ST_SZ_DW(alloc_memic_in)] = {0};
	struct mlx5_priv *priv = &dev->priv;
	u64 page_idx = 0;
	int ret = 0;

	if (!length || (length & MEMIC_ALLOC_MASK))
		return -EINVAL;

	mlx5_core_dbg(dev, "alloc_memic req: length=0x%llx hw_pages=0x%llx hw_start=0x%llx num_page=%d\n",
		      length, num_memic_hw_pages, hw_start_addr, num_pages);

	do {
		spin_lock(&dev->priv.memic_lock);
		page_idx = bitmap_find_next_zero_area(priv->memic_alloc_pages,
						      num_memic_hw_pages,
						      page_idx,
						      num_pages, 0);

		if (page_idx < num_memic_hw_pages)
			bitmap_set(dev->priv.memic_alloc_pages,
				   page_idx, num_pages);
		else
			ret = -ENOMEM;

		spin_unlock(&dev->priv.memic_lock);

		if (ret)
			return ret;

		MLX5_SET(alloc_memic_in, in, opcode, MLX5_CMD_OP_ALLOC_MEMIC);
		MLX5_SET64(alloc_memic_in, in, range_start_addr,
			   hw_start_addr + (page_idx * PAGE_SIZE));
		MLX5_SET(alloc_memic_in, in, range_size, num_pages * PAGE_SIZE);
		MLX5_SET(alloc_memic_in, in, memic_size, length);

		ret = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
		if (ret) {
			spin_lock(&dev->priv.memic_lock);
			bitmap_clear(dev->priv.memic_alloc_pages,
				     page_idx, num_pages);
			spin_unlock(&dev->priv.memic_lock);

			if (ret == -EAGAIN) {
				page_idx++;
				continue;
			}

			mlx5_core_dbg(dev, "alloc_memic error %d\n",
				      ret);

			return ret;
		}

		*addr = pci_resource_start(dev->pdev, 0) +
			MLX5_GET64(alloc_memic_out, out, memic_start_addr);
		mlx5_core_dbg(dev, "alloc_memic address 0x%llx\n",
				*addr);
		return ret;
	} while (page_idx < num_memic_hw_pages);

	return ret;
}
EXPORT_SYMBOL_GPL(mlx5_core_alloc_memic);

int mlx5_core_dealloc_memic(struct mlx5_core_dev *dev, u64 addr, u64 length)
{
	u64 hw_start_addr = MLX5_CAP64_DEVICE_MEM(dev, memic_bar_start_addr);
	u32 num_pages = DIV_ROUND_UP(length, PAGE_SIZE);
	u32 out[MLX5_ST_SZ_DW(dealloc_memic_out)] = {0};
	u32 in[MLX5_ST_SZ_DW(dealloc_memic_in)] = {0};
	u64 start_page_idx;
	int ret;

	addr -= pci_resource_start(dev->pdev, 0);
	start_page_idx = (addr - hw_start_addr) >> PAGE_SHIFT;

	mlx5_core_dbg(dev, "dealloc_memic freeing %d memic pages from 0x%llx\n",
		      num_pages, addr);

	MLX5_SET(dealloc_memic_in, in, opcode, MLX5_CMD_OP_DEALLOC_MEMIC);
	MLX5_SET64(dealloc_memic_in, in, memic_start_addr, addr);
	MLX5_SET(dealloc_memic_in, in, memic_size, length);

	ret =  mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));

	if (!ret) {
		spin_lock(&dev->priv.memic_lock);
		bitmap_clear(dev->priv.memic_alloc_pages,
			     start_page_idx, num_pages);
		spin_unlock(&dev->priv.memic_lock);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(mlx5_core_dealloc_memic);
