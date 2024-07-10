#ifndef _COMPAT_LINUX_PCI_H
#define _COMPAT_LINUX_PCI_H

#include "../../compat/config.h"

#include <linux/version.h>
#include_next <linux/pci.h>

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
#endif /* CONFIG_PCI */

#define pcie_link_speed LINUX_BACKPORT(pcie_link_speed)
extern const unsigned char pcie_link_speed[];

#define pcie_get_minimum_link LINUX_BACKPORT(pcie_get_minimum_link)
int pcie_get_minimum_link(struct pci_dev *dev, enum pci_bus_speed *speed,
			  enum pcie_link_width *width);

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

static inline void register_pcie_dev_attr_group(struct pci_dev *pdev) { }
static inline void unregister_pcie_dev_attr_group(struct pci_dev *pdev) { }

#if !defined(HAVE_PCIE_ASPM_ENABLED)
static inline bool pcie_aspm_enabled(struct pci_dev *pdev) { return false; }
#endif
#endif /* _COMPAT_LINUX_PCI_H */
