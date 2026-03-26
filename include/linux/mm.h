#ifndef _COMPAT_LINUX_MM_H
#define _COMPAT_LINUX_MM_H

#include "../../compat/config.h"

#include_next <linux/mm.h>
#include <linux/page_ref.h>

#include <linux/overflow.h>

#ifndef HAVE_NTH_PAGE
#if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
bool page_range_contiguous(const struct page *page, unsigned long nr_pages);
#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
#else
#define nth_page(page,n) ((page) + (n))
#endif
#endif /* HAVE_NTH_PAGE */

#ifndef HAVE_IS_PCI_P2PDMA_PAGE
static inline bool is_pci_p2pdma_page(const struct page *page)
{
        return false;
}

#endif
#endif /* _COMPAT_LINUX_MM_H */
