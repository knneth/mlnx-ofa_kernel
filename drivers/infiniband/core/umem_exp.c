/*
 * Copyright (c) 2015 Mellanox Technologies. All rights reserved.
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
#include <linux/sched.h>
#include <linux/export.h>
#include <linux/hugetlb.h>
#include <linux/slab.h>
#include <rdma/ib_umem.h>

#include "uverbs.h"
static void umem_vma_open(struct vm_area_struct *area)
{
	/* Implementation is to prevent high level from merging some
	VMAs in case of unmap/mmap on part of memory area.
	Rlimit is handled as well.
	*/
	unsigned long total_size;
	unsigned long ntotal_pages;

	total_size = area->vm_end - area->vm_start;
	ntotal_pages = PAGE_ALIGN(total_size) >> PAGE_SHIFT;
	/* no locking is needed:
	umem_vma_open is called from vm_open which is always called
	with mm->mmap_sem held for writing.
	*/
	if (current->mm)
		current->mm->pinned_vm += ntotal_pages;
	return;
}

static void umem_vma_close(struct vm_area_struct *area)
{
	/* Implementation is to prevent high level from merging some
	VMAs in case of unmap/mmap on part of memory area.
	Rlimit is handled as well.
	*/
	unsigned long total_size;
	unsigned long ntotal_pages;

	total_size = area->vm_end - area->vm_start;
	ntotal_pages = PAGE_ALIGN(total_size) >> PAGE_SHIFT;
	/* no locking is needed:
	umem_vma_close is called from close which is always called
	with mm->mmap_sem held for writing.
	*/
	if (current->mm)
		current->mm->pinned_vm -= ntotal_pages;
	return;

}

static const struct vm_operations_struct umem_vm_ops = {
	.open = umem_vma_open,
	.close = umem_vma_close
};

int ib_umem_map_to_vma(struct ib_umem *umem,
				struct vm_area_struct *vma)
{

	int ret;
	unsigned long ntotal_pages;
	unsigned long total_size;
	struct page *page;
	unsigned long vma_entry_number = 0;
	int i;
	unsigned long locked;
	unsigned long lock_limit;
	struct scatterlist *sg;

	/* Total size expects to be already page aligned - verifying anyway */
	total_size = vma->vm_end - vma->vm_start;
	/* umem length expexts to be equal to the given vma*/
	if (umem->length != total_size)
		return -EINVAL;

	ntotal_pages = PAGE_ALIGN(total_size) >> PAGE_SHIFT;
	/* ib_umem_map_to_vma is called as part of mmap
	with mm->mmap_sem held for writing.
	No need to lock.
	*/
	locked = ntotal_pages + current->mm->pinned_vm;
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

	if ((locked > lock_limit) && !capable(CAP_IPC_LOCK))
		return -ENOMEM;

	for_each_sg(umem->sg_head.sgl, sg, umem->npages, i) {
		/* We reached end of vma - going out from loop */
		if (vma_entry_number >= ntotal_pages)
			goto end;
		page = sg_page(sg);
		if (PageLRU(page) || PageAnon(page)) {
			/* Above cases are not supported
			    as of page fault issues for that VMA.
			*/
			ret = -ENOSYS;
			goto err_vm_insert;
		}
		ret = vm_insert_page(vma, vma->vm_start +
			(vma_entry_number << PAGE_SHIFT), page);
		if (ret < 0)
			goto err_vm_insert;

		vma_entry_number++;
	}

end:
	/* We expect to have enough pages   */
	if (vma_entry_number >= ntotal_pages) {
		current->mm->pinned_vm = locked;
		vma->vm_ops =  &umem_vm_ops;
		return 0;
	}
	/* Not expected but if we reached here
	    not enough pages were available to be mapped into vma.
	*/
	ret = -EINVAL;
	WARN(1, KERN_WARNING
		"ib_umem_map_to_vma: number of pages mismatched(%lu,%lu)\n",
				vma_entry_number, ntotal_pages);

err_vm_insert:

	zap_vma_ptes(vma, vma->vm_start, total_size);
	return ret;

}
EXPORT_SYMBOL(ib_umem_map_to_vma);
