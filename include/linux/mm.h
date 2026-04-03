#ifndef _COMPAT_LINUX_MM_H
#define _COMPAT_LINUX_MM_H

#include "../../compat/config.h"

#include_next <linux/mm.h>
#include <linux/page_ref.h>

#include <linux/overflow.h>

#ifndef HAVE_IS_PCI_P2PDMA_PAGE
static inline bool is_pci_p2pdma_page(const struct page *page)
{
        return false;
}

#endif
#endif /* _COMPAT_LINUX_MM_H */
