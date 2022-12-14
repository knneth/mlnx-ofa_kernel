#ifndef _COMPAT_LINUX_PCI_H
#define _COMPAT_LINUX_PCI_H

#include "../../compat/config.h"

#include <linux/version.h>
#include_next <linux/pci.h>

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

#define pcie_link_speed LINUX_BACKPORT(pcie_link_speed)
extern const unsigned char pcie_link_speed[];

#ifndef HAVE_PCIE_GET_MINIMUM_LINK
#define pcie_get_minimum_link LINUX_BACKPORT(pcie_get_minimum_link)
int pcie_get_minimum_link(struct pci_dev *dev, enum pci_bus_speed *speed,
			  enum pcie_link_width *width);
#endif

#ifndef HAVE_PCIE_PRINT_LINK_STATUS
#define pcie_bandwidth_available LINUX_BACKPORT(pcie_bandwidth_available)
u32 pcie_bandwidth_available(struct pci_dev *dev, struct pci_dev **limiting_dev,
			     enum pci_bus_speed *speed,
			     enum pcie_link_width *width);
#define pcie_print_link_status LINUX_BACKPORT(pcie_print_link_status)
void pcie_print_link_status(struct pci_dev *dev);
#define pcie_get_speed_cap LINUX_BACKPORT(pcie_get_speed_cap)
enum pci_bus_speed pcie_get_speed_cap(struct pci_dev *dev);
#endif

#ifndef PCIE_SPEED2MBS_ENC
/* PCIe speed to Mb/s reduced by encoding overhead */
#define PCIE_SPEED2MBS_ENC(speed) \
	((speed) == PCIE_SPEED_16_0GT ? 16000*128/130 : \
	 (speed) == PCIE_SPEED_8_0GT  ?  8000*128/130 : \
	 (speed) == PCIE_SPEED_5_0GT  ?  5000*8/10 : \
	 (speed) == PCIE_SPEED_2_5GT  ?  2500*8/10 : \
	 0)
#endif

#ifndef PCIE_SPEED2STR
/* PCIe link information */
#define PCIE_SPEED2STR(speed) \
	((speed) == PCIE_SPEED_16_0GT ? "16 GT/s" : \
	 (speed) == PCIE_SPEED_8_0GT ? "8 GT/s" : \
	 (speed) == PCIE_SPEED_5_0GT ? "5 GT/s" : \
	 (speed) == PCIE_SPEED_2_5GT ? "2.5 GT/s" : \
	 "Unknown speed")
#endif

#ifndef pci_info
#define pci_info(pdev, fmt, arg...)	dev_info(&(pdev)->dev, fmt, ##arg)
#endif

#ifndef HAVE_PCI_ENABLE_ATOMIC_OPS_TO_ROOT
#define pci_enable_atomic_ops_to_root LINUX_BACKPORT(pci_enable_atomic_ops_to_root)
int pci_enable_atomic_ops_to_root(struct pci_dev *dev, u32 comp_caps);
#endif

#ifdef HAVE_NO_LINKSTA_SYSFS
void register_pcie_dev_attr_group(struct pci_dev *pdev);
void unregister_pcie_dev_attr_group(struct pci_dev *pdev);
#else
static inline void register_pcie_dev_attr_group(struct pci_dev *pdev) { }
static inline void unregister_pcie_dev_attr_group(struct pci_dev *pdev) { }
#endif

#if !defined(HAVE_PCIE_ASPM_ENABLED) && defined(HAVE_PM_SUSPEND_VIA_FIRMWARE)
static inline bool pcie_aspm_enabled(struct pci_dev *pdev) { return false; }
#endif

#endif /* _COMPAT_LINUX_PCI_H */
