/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Cisco Systems.  All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies. All rights reserved.
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

#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/export.h>
#include <linux/hugetlb.h>
#include <linux/slab.h>
#include <rdma/ib_umem_odp.h>

#include "uverbs.h"

static struct ib_umem *peer_umem_get(struct ib_peer_memory_client *ib_peer_mem,
				     struct ib_umem *umem, unsigned long addr,
				     int dmasync, unsigned long peer_mem_flags)
{
	int ret;
	const struct peer_memory_client *peer_mem = ib_peer_mem->peer_mem;
	struct invalidation_ctx *invalidation_ctx = NULL;

	umem->ib_peer_mem = ib_peer_mem;
	if (peer_mem_flags & IB_PEER_MEM_INVAL_SUPP) {
		ret = ib_peer_create_invalidation_ctx(ib_peer_mem, umem, &invalidation_ctx);
		if (ret)
			goto end;
	}

	/*
	 * We always request write permissions to the pages, to force breaking of any CoW
	 * during the registration of the MR. For read-only MRs we use the "force" flag to
	 * indicate that CoW breaking is required but the registration should not fail if
	 * referencing read-only areas.
	 */
	ret = peer_mem->get_pages(addr, umem->length,
				  1, !umem->writable,
				  &umem->sg_head,
				  umem->peer_mem_client_context,
				  invalidation_ctx ?
				  invalidation_ctx->context_ticket : 0);
	if (ret)
		goto out;

	umem->page_shift = ilog2(peer_mem->get_page_size
				 (umem->peer_mem_client_context));
	if (BIT(umem->page_shift) <= 0)
		goto put_pages;

	ret = peer_mem->dma_map(&umem->sg_head,
				umem->peer_mem_client_context,
				umem->context->device->dma_device,
				dmasync,
				&umem->nmap);
	if (ret)
		goto put_pages;

	atomic64_add(umem->nmap, &ib_peer_mem->stats.num_reg_pages);
	atomic64_add(umem->nmap * BIT(umem->page_shift), &ib_peer_mem->stats.num_reg_bytes);
	atomic64_inc(&ib_peer_mem->stats.num_alloc_mrs);
	return umem;

put_pages:
	peer_mem->put_pages(&umem->sg_head, umem->peer_mem_client_context);
out:
	if (invalidation_ctx)
		ib_peer_destroy_invalidation_ctx(ib_peer_mem, invalidation_ctx);
end:
	ib_put_peer_client(ib_peer_mem, umem->peer_mem_client_context);
	kfree(umem);
	return ERR_PTR(ret);
}

static void peer_umem_release(struct ib_umem *umem)
{
	struct ib_peer_memory_client *ib_peer_mem = umem->ib_peer_mem;
	const struct peer_memory_client *peer_mem = ib_peer_mem->peer_mem;
	struct invalidation_ctx *invalidation_ctx = umem->invalidation_ctx;

	if (invalidation_ctx)
		ib_peer_destroy_invalidation_ctx(ib_peer_mem, invalidation_ctx);

	peer_mem->dma_unmap(&umem->sg_head,
			    umem->peer_mem_client_context,
			    umem->context->device->dma_device);
	peer_mem->put_pages(&umem->sg_head,
			    umem->peer_mem_client_context);
	atomic64_add(umem->nmap, &ib_peer_mem->stats.num_dereg_pages);
	atomic64_add(umem->nmap * BIT(umem->page_shift), &ib_peer_mem->stats.num_dereg_bytes);
	atomic64_inc(&ib_peer_mem->stats.num_dealloc_mrs);
	ib_put_peer_client(ib_peer_mem, umem->peer_mem_client_context);
	kfree(umem);
}

static void __ib_umem_release(struct ib_device *dev, struct ib_umem *umem, int dirty)
{
	struct scatterlist *sg;
	struct page *page;
	int i;

	if (umem->nmap > 0)
		ib_dma_unmap_sg(dev, umem->sg_head.sgl,
				umem->npages,
				DMA_BIDIRECTIONAL);

	for_each_sg(umem->sg_head.sgl, sg, umem->npages, i) {

		page = sg_page(sg);
		if (!PageDirty(page) && umem->writable && dirty)
			set_page_dirty_lock(page);
		put_page(page);
	}

	sg_free_table(&umem->sg_head);
}

int ib_umem_activate_invalidation_notifier(struct ib_umem *umem,
					   umem_invalidate_func_t func,
					   void *cookie)
{
	struct invalidation_ctx *invalidation_ctx = umem->invalidation_ctx;
	int ret = 0;

	mutex_lock(&umem->ib_peer_mem->lock);
	if (invalidation_ctx->peer_invalidated) {
		pr_err("ib_umem_activate_invalidation_notifier: pages were invalidated by peer\n");
		ret = -EINVAL;
		goto end;
	}
	invalidation_ctx->func = func;
	invalidation_ctx->cookie = cookie;
	/* from that point any pending invalidations can be called */
end:
	mutex_unlock(&umem->ib_peer_mem->lock);
	return ret;
}
EXPORT_SYMBOL(ib_umem_activate_invalidation_notifier);

static int ib_client_umem_get(struct ib_ucontext *context, unsigned long addr,
			      size_t size, unsigned long peer_mem_flags,
			      struct ib_umem *umem, int dmasync)
{
	struct ib_peer_memory_client *peer_mem_client;

	peer_mem_client = ib_get_peer_client(context, addr, size,
					     peer_mem_flags,
					     &umem->peer_mem_client_context);
	if (peer_mem_client) {
		umem->hugetlb = 0;
		peer_umem_get(peer_mem_client, umem, addr,
			      dmasync, peer_mem_flags);
		return 0;
	}

	return -ENOMEM;
}

/**
 * ib_umem_get - Pin and DMA map userspace memory.
 *
 * If access flags indicate ODP memory, avoid pinning. Instead, stores
 * the mm for future page fault handling in conjunction with MMU notifiers.
 *
 * @context: userspace context to pin memory for
 * @addr: userspace virtual address to start at
 * @size: length of region to pin
 * @access: IB_ACCESS_xxx flags for memory being pinned
 * @dmasync: flush in-flight DMA when the memory region is written
 * @peer_mem_flags: IB_PEER_MEM_xxx flags for memory being used
 */
struct ib_umem *ib_umem_get(struct ib_ucontext *context, unsigned long addr,
			       size_t size, int access, int dmasync,
			       unsigned long peer_mem_flags)
{
	struct ib_umem *umem;
	struct page **page_list;
	struct vm_area_struct **vma_list;
	unsigned long lock_limit;
	unsigned long new_pinned;
	unsigned long cur_base;
	struct mm_struct *mm;
	unsigned long npages;
	int ret;
	int i;
	unsigned long dma_attrs = 0;
	struct scatterlist *sg, *sg_list_start;
	unsigned int gup_flags = FOLL_WRITE;

	if (dmasync)
		dma_attrs |= DMA_ATTR_WRITE_BARRIER;

	/*
	 * If the combination of the addr and size requested for this memory
	 * region causes an integer overflow, return error.
	 */
	if (((addr + size) < addr) ||
	    PAGE_ALIGN(addr + size) < (addr + size)) {
		pr_err("%s: integer overflow, size=%zu\n", __func__, size);
 		return ERR_PTR(-EINVAL);
	}

	if (!can_do_mlock()) {
		pr_err("%s: no mlock permission\n", __func__);
 		return ERR_PTR(-EPERM);
	}

	if (access & IB_ACCESS_ON_DEMAND) {
		umem = kzalloc(sizeof(struct ib_umem_odp), GFP_KERNEL);
		if (!umem)
			return ERR_PTR(-ENOMEM);
		umem->is_odp = 1;
	} else {
		umem = kzalloc(sizeof(*umem), GFP_KERNEL);
		if (!umem)
			return ERR_PTR(-ENOMEM);
	}

	umem->context    = context;
	umem->length     = size;
	umem->address    = addr;
	umem->page_shift = PAGE_SHIFT;
	umem->writable   = ib_access_writable(access);
	umem->owning_mm = mm = current->mm;
	mmgrab(mm);

	/* For known peer context move directly to peer registration handling */
	if (context->peer_mem_private_data &&
	    (peer_mem_flags & IB_PEER_MEM_ALLOW)) {
		ret = ib_client_umem_get(context, addr, size,
					 peer_mem_flags, umem, dmasync);
		if (!ret)
			return umem;
	}

	if (access & IB_ACCESS_ON_DEMAND) {
		ret = ib_umem_odp_get(to_ib_umem_odp(umem), access);
		if (ret)
			goto umem_kfree;
		return umem;
	}

	/* We assume the memory is from hugetlb until proved otherwise */
	umem->hugetlb   = 1;

	page_list = (struct page **) __get_free_page(GFP_KERNEL);
	if (!page_list) {
		ret = -ENOMEM;
		goto umem_kfree;
	}

	/*
	 * if we can't alloc the vma_list, it's not so bad;
	 * just assume the memory is not hugetlb memory
	 */
	vma_list = (struct vm_area_struct **) __get_free_page(GFP_KERNEL);
	if (!vma_list)
		umem->hugetlb = 0;

	npages = ib_umem_num_pages(umem);
	if (npages == 0 || npages > UINT_MAX) {
		pr_debug("%s: npages(%lu) isn't in the range 1..%u\n", __func__,
		       npages, UINT_MAX);
		ret = -EINVAL;
		goto out;
	}

	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

	down_write(&mm->mmap_sem);
	if (check_add_overflow(mm->pinned_vm, npages, &new_pinned) ||
	    (new_pinned > lock_limit && !capable(CAP_IPC_LOCK))) {
		up_write(&mm->mmap_sem);
		pr_debug("%s: requested to lock(%lu) while limit is(%lu)\n",
		       __func__, new_pinned, lock_limit);
		ret = -ENOMEM;
		goto out;
	}
	mm->pinned_vm = new_pinned;
	up_write(&mm->mmap_sem);

	cur_base = addr & PAGE_MASK;

	ret = sg_alloc_table(&umem->sg_head, npages, GFP_KERNEL);
	if (ret) {
		pr_debug("%s: failed to allocate sg table, npages=%lu\n",
		       __func__, npages);
		goto vma;
	}

	if (!umem->writable)
		gup_flags |= FOLL_FORCE;

	sg_list_start = umem->sg_head.sgl;

	while (npages) {
		down_read(&mm->mmap_sem);
		ret = get_user_pages_longterm(cur_base,
				     min_t(unsigned long, npages,
					   PAGE_SIZE / sizeof (struct page *)),
				     gup_flags, page_list, vma_list);
		if (ret < 0) {
			pr_debug("%s: failed to get user pages, nr_pages=%lu, flags=%u\n", __func__,
			       min_t(unsigned long, npages,
				     PAGE_SIZE / sizeof(struct page *)),
			       gup_flags);
			up_read(&mm->mmap_sem);
			goto umem_release;
		}

		umem->npages += ret;
		cur_base += ret * PAGE_SIZE;
		npages   -= ret;

		/* Continue to hold the mmap_sem as vma_list access
		 * needs to be protected.
		 */
		for_each_sg(sg_list_start, sg, ret, i) {
			if (vma_list && !is_vm_hugetlb_page(vma_list[i]))
				umem->hugetlb = 0;

			sg_set_page(sg, page_list[i], PAGE_SIZE, 0);
		}
		up_read(&mm->mmap_sem);

		/* preparing for next loop */
		sg_list_start = sg;
	}

	umem->nmap = ib_dma_map_sg_attrs(context->device,
				  umem->sg_head.sgl,
				  umem->npages,
				  DMA_BIDIRECTIONAL,
				  dma_attrs);

	if (!umem->nmap) {
		pr_err("%s: failed to map scatterlist, npages=%d\n", __func__,
		       umem->npages);
		ret = -ENOMEM;
		goto umem_release;
	}

	ret = 0;
	goto out;

umem_release:
	__ib_umem_release(context->device, umem, 0);
vma:
	down_write(&mm->mmap_sem);
	mm->pinned_vm -= ib_umem_num_pages(umem);
	up_write(&mm->mmap_sem);
out:
	if (vma_list)
		free_page((unsigned long) vma_list);
	free_page((unsigned long) page_list);
	/*
 	 * If the address belongs to peer memory client, then the first
 	 * call to get_user_pages will fail. In this case, try to get
 	 * these pages from the peers.
 	 */
	if (ret < 0) {
		if ((peer_mem_flags & IB_PEER_MEM_ALLOW) && 
		    !context->peer_mem_private_data) {
			ret = ib_client_umem_get(context, addr, size, peer_mem_flags,
						 umem, dmasync);
			if (!ret)
				return umem;
		}
	}
umem_kfree:
	if (ret) {
		mmdrop(umem->owning_mm);
		kfree(umem);
	}
	return ret ? ERR_PTR(ret) : umem;
}
EXPORT_SYMBOL(ib_umem_get);

static void __ib_umem_release_tail(struct ib_umem *umem)
{
	mmdrop(umem->owning_mm);
	if (umem->is_odp)
		kfree(to_ib_umem_odp(umem));
	else
		kfree(umem);
}

static void ib_umem_release_defer(struct work_struct *work)
{
	struct ib_umem *umem = container_of(work, struct ib_umem, work);

	down_write(&umem->owning_mm->mmap_sem);
	umem->owning_mm->pinned_vm -= ib_umem_num_pages(umem);
	up_write(&umem->owning_mm->mmap_sem);

	__ib_umem_release_tail(umem);
}

/**
 * ib_umem_release - release memory pinned with ib_umem_get
 * @umem: umem struct to release
 */
void ib_umem_release(struct ib_umem *umem)
{
	struct ib_ucontext *context = umem->context;

	if (umem->ib_peer_mem) {
		peer_umem_release(umem);
		return;
	}

	if (umem->is_odp) {
		ib_umem_odp_release(to_ib_umem_odp(umem));
		__ib_umem_release_tail(umem);
		return;
	}

	__ib_umem_release(umem->context->device, umem, 1);

	/*
	 * We may be called with the mm's mmap_sem already held.  This
	 * can happen when a userspace munmap() is the call that drops
	 * the last reference to our file and calls our release
	 * method.  If there are memory regions to destroy, we'll end
	 * up here and not be able to take the mmap_sem.  In that case
	 * we defer the vm_locked accounting a workqueue.
	 */
	if (context->closing) {
		if (!down_write_trylock(&umem->owning_mm->mmap_sem)) {
			INIT_WORK(&umem->work, ib_umem_release_defer);
			queue_work(ib_wq, &umem->work);
			return;
		}
	} else {
		down_write(&umem->owning_mm->mmap_sem);
	}
	umem->owning_mm->pinned_vm -= ib_umem_num_pages(umem);
	up_write(&umem->owning_mm->mmap_sem);

	__ib_umem_release_tail(umem);
}
EXPORT_SYMBOL(ib_umem_release);

int ib_umem_page_count(struct ib_umem *umem)
{
	int i;
	int n;
	struct scatterlist *sg;

	if (umem->is_odp)
		return ib_umem_num_pages(umem);

	n = 0;
	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, i)
		n += sg_dma_len(sg) >> umem->page_shift;

	return n;
}
EXPORT_SYMBOL(ib_umem_page_count);

/*
 * Copy from the given ib_umem's pages to the given buffer.
 *
 * umem - the umem to copy from
 * offset - offset to start copying from
 * dst - destination buffer
 * length - buffer length
 *
 * Returns 0 on success, or an error code.
 */
int ib_umem_copy_from(void *dst, struct ib_umem *umem, size_t offset,
		      size_t length)
{
	size_t end = offset + length;
	int ret;

	if (offset > umem->length || length > umem->length - offset) {
		pr_err("ib_umem_copy_from not in range. offset: %zd umem length: %zd end: %zd\n",
		       offset, umem->length, end);
		return -EINVAL;
	}

	ret = sg_pcopy_to_buffer(umem->sg_head.sgl, umem->npages, dst, length,
				 offset + ib_umem_offset(umem));

	if (ret < 0)
		return ret;
	else if (ret != length)
		return -EINVAL;
	else
		return 0;
}
EXPORT_SYMBOL(ib_umem_copy_from);
