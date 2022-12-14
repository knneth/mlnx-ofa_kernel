#ifndef LINUX_3_8_COMPAT_H
#define LINUX_3_8_COMPAT_H

#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))
#include <linux/pci_regs.h>

#ifndef FLOW_MAC_EXT
#define    FLOW_MAC_EXT    0x40000000
#endif

#ifndef PCI_EXP_LNKCAP_SLS_2_5GB
#define  PCI_EXP_LNKCAP_SLS_2_5GB 0x00000001 /* LNKCAP2 SLS Vector bit 0 */
#endif

#ifndef PCI_EXP_LNKCAP_SLS_5_0GB
#define  PCI_EXP_LNKCAP_SLS_5_0GB 0x00000002 /* LNKCAP2 SLS Vector bit 1 */
#endif

#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)) */

#endif /* LINUX_3_8_COMPAT_H */
