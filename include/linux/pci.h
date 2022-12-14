#ifndef _LINUX_PCI_H
#define _LINUX_PCI_H

#include "../../compat/config.h"

#include <linux/version.h>
#include_next <linux/pci.h>

#ifndef HAVE_PCI_PHYSFN
#define pci_physfn LINUX_BACKPORT(pci_physfn)
static inline struct pci_dev *pci_physfn(struct pci_dev *dev)
{
#ifdef CONFIG_PCI_IOV
	if (dev->is_virtfn)
		dev = dev->physfn;
#endif
	return dev;
}
#endif /* HAVE_PCI_PHYSFN */

#ifndef HAVE_PCI_NUM_VF
#define pci_num_vf LINUX_BACKPORT(pci_num_vf)
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18))
int pci_num_vf(struct pci_dev *pdev);
#else
static inline int pci_num_vf(struct pci_dev *pdev)
{
	return 0;
}
#endif
#endif

#ifndef HAVE_PCI_VFS_ASSIGNED
#define pci_vfs_assigned LINUX_BACKPORT(pci_vfs_assigned)
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18))
int pci_vfs_assigned(struct pci_dev *pdev);
#else
static inline int pci_vfs_assigned(struct pci_dev *pdev)
{
	return 0;
}
#endif
#endif

#ifndef HAVE_PCI_SRIOV_GET_TOTALVFS
#define pci_sriov_get_totalvfs LINUX_BACKPORT(pci_sriov_get_totalvfs)
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18))
int pci_sriov_get_totalvfs(struct pci_dev *pdev);
#else
static inline int pci_sriov_get_totalvfs(struct pci_dev *pdev)
{
	return 0;
}
#endif
#endif

#ifndef HAVE_PCI_IRQ_GET_AFFINITY
static inline const struct cpumask *pci_irq_get_affinity(struct pci_dev *pdev,
							 int vec)
{
	return cpu_possible_mask;
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)) || \
    (defined(RHEL_MAJOR) && RHEL_MAJOR -0 == 7 && RHEL_MINOR -0 >= 2)
#ifndef HAVE_PCI_IRQ_GET_NODE
static inline int pci_irq_get_node(struct pci_dev *pdev, int vec)
{
#ifdef CONFIG_PCI_MSI
	const struct cpumask *mask;

	mask = pci_irq_get_affinity(pdev, vec);
	if (mask)
#ifdef CONFIG_HAVE_MEMORYLESS_NODES
		return local_memory_node(cpu_to_node(cpumask_first(mask)));
#else
		return cpu_to_node(cpumask_first(mask));
#endif
	return dev_to_node(&pdev->dev);
#else /* CONFIG_PCI_MSI */
	return first_online_node;
#endif /* CONFIG_PCI_MSI */
}
#endif /* pci_irq_get_node */
#endif

#ifdef CONFIG_PCI
#ifndef HAVE_PCI_REQUEST_MEM_REGIONS
static inline int
pci_request_mem_regions(struct pci_dev *pdev, const char *name)
{
	return pci_request_selected_regions(pdev,
			    pci_select_bars(pdev, IORESOURCE_MEM), name);
}
#endif

#ifndef HAVE_PCI_RELEASE_MEM_REGIONS
static inline void
pci_release_mem_regions(struct pci_dev *pdev)
{
	return pci_release_selected_regions(pdev,
			    pci_select_bars(pdev, IORESOURCE_MEM));
}
#endif
#endif /* CONFIG_PCI */

#endif /* _LINUX_PCI_H */
