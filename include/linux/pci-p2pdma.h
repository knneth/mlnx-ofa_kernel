#ifndef _COMPAT_LINUX_PCI_P2PDMA_H
#define _COMPAT_LINUX_PCI_P2PDMA_H 1

#include "../../compat/config.h"

#include_next <linux/pci-p2pdma.h>

#ifndef HAVE_PCI_P2PDMA_UNMAP_SG
static inline void pci_p2pdma_unmap_sg(struct device *dev,
		struct scatterlist *sg, int nents, enum dma_data_direction dir)
{
}
#endif

#endif /* _COMPAT_LINUX_PCI_P2PDMA_H */
