#ifndef LINUX_3_12_COMPAT_H
#define LINUX_3_12_COMPAT_H

#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0))

#include <linux/netdevice.h>

#ifndef HAVE_UDP4_HWCSUM
#define udp4_hwcsum LINUX_BACKPORT(udp4_hwcsum)
void udp4_hwcsum(struct sk_buff *skb, __be32 src, __be32 dst);
#endif

#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)) */
#endif /* LINUX_3_12_COMPAT_H */
