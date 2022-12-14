#ifndef LINUX_3_12_COMPAT_H
#define LINUX_3_12_COMPAT_H

#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0))

#include <linux/netdevice.h>

/* Added IFF_SLAVE_NEEDARP for SLES11SP1 Errata kernels where this was replaced
 * by IFF_MASTER_NEEDARP
 */
#ifndef IFF_SLAVE_NEEDARP
#define IFF_SLAVE_NEEDARP 0x40          /* need ARPs for validation     */
#endif

#include <linux/pci.h>

#define debugfs_create_atomic_t LINUX_BACKPORT(debugfs_create_atomic_t)
struct dentry *debugfs_create_atomic_t(const char *name, umode_t mode,
				       struct dentry *parent, atomic_t *value);

#ifndef PTR_ERR_OR_ZERO
#define PTR_ERR_OR_ZERO(p) PTR_RET(p)
#endif

#define MODULE_ALIAS_FS(NAME) MODULE_ALIAS("fs-" NAME)

#define file_inode LINUX_BACKPORT(file_inode)
static inline struct inode *file_inode(struct file *f)
{
	return f->f_dentry->d_inode;
}

#ifndef HAVE_PCIE_LINK_WIDTH
/* These values come from the PCI Express Spec */
enum pcie_link_width {
	PCIE_LNK_WIDTH_RESRV	= 0x00,
	PCIE_LNK_X1		= 0x01,
	PCIE_LNK_X2		= 0x02,
	PCIE_LNK_X4		= 0x04,
	PCIE_LNK_X8		= 0x08,
	PCIE_LNK_X12		= 0x0C,
	PCIE_LNK_X16		= 0x10,
	PCIE_LNK_X32		= 0x20,
	PCIE_LNK_WIDTH_UNKNOWN  = 0xFF,
};
#endif

extern const unsigned char pcie_link_speed[];

#define pcie_get_minimum_link LINUX_BACKPORT(pcie_get_minimum_link)
int pcie_get_minimum_link(struct pci_dev *dev, enum pci_bus_speed *speed,
		enum pcie_link_width *width);
#ifndef HAVE_UDP4_HWCSUM
#define udp4_hwcsum LINUX_BACKPORT(udp4_hwcsum)
void udp4_hwcsum(struct sk_buff *skb, __be32 src, __be32 dst);
#endif
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)) */
#endif /* LINUX_3_12_COMPAT_H */
