/*
 * Copyright 2012  Luis R. Rodriguez <mcgrof@do-not-panic.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Compatibility file for Linux wireless for kernels 3.7.
 */

#include <linux/workqueue.h>
#include <linux/export.h>
#include <linux/file.h>

#define mod_delayed_work LINUX_BACKPORT(mod_delayed_work)
bool mod_delayed_work(struct workqueue_struct *wq, struct delayed_work *dwork,
		      unsigned long delay)
{
	__cancel_delayed_work(dwork);
	queue_delayed_work(wq, dwork, delay);
	return false;
}
EXPORT_SYMBOL_GPL(mod_delayed_work);

/*
 * Kernels >= 3.7 get their PCI-E Capabilities Register cached
 * via the pci_dev->pcie_flags_reg so for older kernels we have
 * no other option but to read this every single time we need
 * it accessed. If we really cared to improve the efficiency
 * of this we could try to find an unused u16 varible on the
 * pci_dev but if we found it we likely would remove it from
 * the kernel anyway right? Bite me.
 */
#define pcie_flags_reg LINUX_BACKPORT(pcie_flags_reg)
static inline u16 pcie_flags_reg(struct pci_dev *dev)
{
	int pos;
	u16 reg16;

	pos = pci_find_capability(dev, PCI_CAP_ID_EXP);
	if (!pos)
		return 0;

	pci_read_config_word(dev, pos + PCI_EXP_FLAGS, &reg16);

	return reg16;
}

#define pci_pcie_type LINUX_BACKPORT(pci_pcie_type)
static inline int pci_pcie_type(struct pci_dev *dev)
{
	return (pcie_flags_reg(dev) & PCI_EXP_FLAGS_TYPE) >> 4;
}

#define pcie_cap_version LINUX_BACKPORT(pcie_cap_version)
static inline int pcie_cap_version(struct pci_dev *dev)
{
	return pcie_flags_reg(dev) & PCI_EXP_FLAGS_VERS;
}

#define pcie_cap_has_devctl LINUX_BACKPORT(pcie_cap_has_devctl)
static inline bool pcie_cap_has_devctl(const struct pci_dev *dev)
{
	return true;
}

#define pcie_cap_has_lnkctl LINUX_BACKPORT(pcie_cap_has_lnkctl)
static inline bool pcie_cap_has_lnkctl(struct pci_dev *dev)
{
	int type = pci_pcie_type(dev);

	return pcie_cap_version(dev) > 1 ||
	       type == PCI_EXP_TYPE_ROOT_PORT ||
	       type == PCI_EXP_TYPE_ENDPOINT ||
	       type == PCI_EXP_TYPE_LEG_END;
}

#define pcie_cap_has_sltctl LINUX_BACKPORT(pcie_cap_has_sltctl)
static inline bool pcie_cap_has_sltctl(struct pci_dev *dev)
{
	int type = pci_pcie_type(dev);

	return pcie_cap_version(dev) > 1 ||
	       type == PCI_EXP_TYPE_ROOT_PORT ||
	       (type == PCI_EXP_TYPE_DOWNSTREAM &&
		pcie_flags_reg(dev) & PCI_EXP_FLAGS_SLOT);
}

#define pcie_cap_has_rtctl LINUX_BACKPORT(pcie_cap_has_rtctl)
static inline bool pcie_cap_has_rtctl(struct pci_dev *dev)
{
	int type = pci_pcie_type(dev);

	return pcie_cap_version(dev) > 1 ||
	       type == PCI_EXP_TYPE_ROOT_PORT ||
	       type == PCI_EXP_TYPE_RC_EC;
}

#define pcie_capability_reg_implemented LINUX_BACKPORT(pcie_capability_reg_implemented)
static bool pcie_capability_reg_implemented(struct pci_dev *dev, int pos)
{
	if (!pci_is_pcie(dev))
		return false;

	switch (pos) {
	case PCI_EXP_FLAGS_TYPE:
		return true;
	case PCI_EXP_DEVCAP:
	case PCI_EXP_DEVCTL:
	case PCI_EXP_DEVSTA:
		return pcie_cap_has_devctl(dev);
	case PCI_EXP_LNKCAP:
	case PCI_EXP_LNKCTL:
	case PCI_EXP_LNKSTA:
		return pcie_cap_has_lnkctl(dev);
	case PCI_EXP_SLTCAP:
	case PCI_EXP_SLTCTL:
	case PCI_EXP_SLTSTA:
		return pcie_cap_has_sltctl(dev);
	case PCI_EXP_RTCTL:
	case PCI_EXP_RTCAP:
	case PCI_EXP_RTSTA:
		return pcie_cap_has_rtctl(dev);
	case PCI_EXP_DEVCAP2:
	case PCI_EXP_DEVCTL2:
	case PCI_EXP_LNKCAP2:
	case PCI_EXP_LNKCTL2:
	case PCI_EXP_LNKSTA2:
		return pcie_cap_version(dev) > 1;
	default:
		return false;
	}
}

/*
 * Note that these accessor functions are only for the "PCI Express
 * Capability" (see PCIe spec r3.0, sec 7.8).  They do not apply to the
 * other "PCI Express Extended Capabilities" (AER, VC, ACS, MFVC, etc.)
 */
#define pcie_capability_read_word LINUX_BACKPORT(pcie_capability_read_word)
int pcie_capability_read_word(struct pci_dev *dev, int pos, u16 *val)
{
	int ret;

	*val = 0;
	if (pos & 1)
		return -EINVAL;

	if (pcie_capability_reg_implemented(dev, pos)) {
		ret = pci_read_config_word(dev, pci_pcie_cap(dev) + pos, val);
		/*
		 * Reset *val to 0 if pci_read_config_word() fails, it may
		 * have been written as 0xFFFF if hardware error happens
		 * during pci_read_config_word().
		 */
		if (ret)
			*val = 0;
		return ret;
	}

	/*
	 * For Functions that do not implement the Slot Capabilities,
	 * Slot Status, and Slot Control registers, these spaces must
	 * be hardwired to 0b, with the exception of the Presence Detect
	 * State bit in the Slot Status register of Downstream Ports,
	 * which must be hardwired to 1b.  (PCIe Base Spec 3.0, sec 7.8)
	 */
	if (pci_is_pcie(dev) && pos == PCI_EXP_SLTSTA &&
		 pci_pcie_type(dev) == PCI_EXP_TYPE_DOWNSTREAM) {
		*val = PCI_EXP_SLTSTA_PDS;
	}

	return 0;
}
EXPORT_SYMBOL(pcie_capability_read_word);

#define pcie_capability_read_dword LINUX_BACKPORT(pcie_capability_read_dword)
int pcie_capability_read_dword(struct pci_dev *dev, int pos, u32 *val)
{
	int ret;

	*val = 0;
	if (pos & 3)
		return -EINVAL;

	if (pcie_capability_reg_implemented(dev, pos)) {
		ret = pci_read_config_dword(dev, pci_pcie_cap(dev) + pos, val);
		/*
		 * Reset *val to 0 if pci_read_config_dword() fails, it may
		 * have been written as 0xFFFFFFFF if hardware error happens
		 * during pci_read_config_dword().
		 */
		if (ret)
			*val = 0;
		return ret;
	}

	if (pci_is_pcie(dev) && pos == PCI_EXP_SLTCTL &&
		 pci_pcie_type(dev) == PCI_EXP_TYPE_DOWNSTREAM) {
		*val = PCI_EXP_SLTSTA_PDS;
	}

	return 0;
}
EXPORT_SYMBOL(pcie_capability_read_dword);

#define pcie_capability_write_word LINUX_BACKPORT(pcie_capability_write_word)
int pcie_capability_write_word(struct pci_dev *dev, int pos, u16 val)
{
	if (pos & 1)
		return -EINVAL;

	if (!pcie_capability_reg_implemented(dev, pos))
		return 0;

	return pci_write_config_word(dev, pci_pcie_cap(dev) + pos, val);
}
EXPORT_SYMBOL(pcie_capability_write_word);

#define pcie_capability_write_dword LINUX_BACKPORT(pcie_capability_write_dword)
int pcie_capability_write_dword(struct pci_dev *dev, int pos, u32 val)
{
	if (pos & 3)
		return -EINVAL;

	if (!pcie_capability_reg_implemented(dev, pos))
		return 0;

	return pci_write_config_dword(dev, pci_pcie_cap(dev) + pos, val);
}
EXPORT_SYMBOL(pcie_capability_write_dword);

#define pcie_capability_clear_and_set_word LINUX_BACKPORT(pcie_capability_clear_and_set_word)
int pcie_capability_clear_and_set_word(struct pci_dev *dev, int pos,
				       u16 clear, u16 set)
{
	int ret;
	u16 val;

	ret = pcie_capability_read_word(dev, pos, &val);
	if (!ret) {
		val &= ~clear;
		val |= set;
		ret = pcie_capability_write_word(dev, pos, val);
	}

	return ret;
}
EXPORT_SYMBOL(pcie_capability_clear_and_set_word);

#define pcie_capability_clear_and_set_dword LINUX_BACKPORT(pcie_capability_clear_and_set_dword)
int pcie_capability_clear_and_set_dword(struct pci_dev *dev, int pos,
					u32 clear, u32 set)
{
	int ret;
	u32 val;

	ret = pcie_capability_read_dword(dev, pos, &val);
	if (!ret) {
		val &= ~clear;
		val |= set;
		ret = pcie_capability_write_dword(dev, pos, val);
	}

	return ret;
}
EXPORT_SYMBOL(pcie_capability_clear_and_set_dword);

/* Actually fget_light is defined in fs/file.c but only 3.7 exports it.
 * Lets export it here.
 */
#define fget_light LINUX_BACKPORT(fget_light)
struct file *fget_light(unsigned int fd, int *fput_needed)
{
	struct file *file;
	struct files_struct *files = current->files;

	*fput_needed = 0;
	if (atomic_read(&files->count) == 1) {
		file = fcheck_files(files, fd);
		if (file && (file->f_mode & FMODE_PATH))
			file = NULL;
	} else {
		rcu_read_lock();
		file = fcheck_files(files, fd);
		if (file) {
			if (!(file->f_mode & FMODE_PATH) &&
			    atomic_long_inc_not_zero(&file->f_count))
				*fput_needed = 1;
			else
				/* Didn't get the reference, someone's freed */
				file = NULL;
		}
		rcu_read_unlock();
	}

	return file;
}
EXPORT_SYMBOL(fget_light);
