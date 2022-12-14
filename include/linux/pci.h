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

#endif /* _LINUX_PCI_H */
