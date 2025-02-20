#ifndef _COMPAT_LINUX_PCI_H
#define _COMPAT_LINUX_PCI_H

#include "../../compat/config.h"

#include <linux/version.h>
#include_next <linux/pci.h>

#ifndef HAVE_PCI_ENABLE_PTM
#ifdef CONFIG_PCIE_PTM
int pci_enable_ptm(struct pci_dev *dev, u8 *granularity);
#else /* CONFIG_PCIE_PTM */
static inline int pci_enable_ptm(struct pci_dev *dev, u8 *granularity) { return 0; }
#endif
#endif

#ifndef HAVE_PCI_DISABLE_PTM
#ifdef CONFIG_PCIE_PTM
static inline void __pci_disable_ptm(struct pci_dev *dev)
{
	u32 ctrl;
	int ptm;

	if (!pci_is_pcie(dev))
		return;

	ptm = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_PTM);
	if (!ptm)
		return;

	pci_read_config_dword(dev, ptm + PCI_PTM_CTRL, &ctrl);
	ctrl &= ~(PCI_PTM_CTRL_ENABLE | PCI_PTM_CTRL_ROOT);
	pci_write_config_dword(dev, ptm + PCI_PTM_CTRL, ctrl);
}

/**
 * pci_disable_ptm() - Disable Precision Time Measurement
 * @dev: PCI device
 *
 * Disable Precision Time Measurement for @dev.
 */
static inline void pci_disable_ptm(struct pci_dev *dev)
{
	if (dev->ptm_enabled) {
		__pci_disable_ptm(dev);
		dev->ptm_enabled = 0;
	}
}
#else /* CONFIG_PCIE_PTM */
static inline void pci_disable_ptm(struct pci_dev *dev)
{}
#endif /* CONFIG_PCIE_PTM */
#endif /* HAVE_PCI_DISABLE_PTM */

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
