#ifndef _COMPAT_LINUX_BLK_MQ_PCI_H
#define _COMPAT_LINUX_BLK_MQ_PCI_H 1

#include "../../compat/config.h"

#ifndef HAVE_BLK_MQ_MAP_HW_QUEUES /* forward port */
#include_next <linux/blk-mq-pci.h>
#endif

#endif	/* _COMPAT_LINUX_BLK_MQ_PCI_H */
