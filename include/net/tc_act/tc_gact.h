#ifndef _COMPAT_NET_TC_ACT_TC_GACT_H
#define _COMPAT_NET_TC_ACT_TC_GACT_H 1

#include "../../../compat/config.h"

#include_next <uapi/linux/pkt_cls.h>
#include_next <net/tc_act/tc_gact.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)) && (LINUX_VERSION_CODE <= KERNEL_VERSION(4,5,7))
#include <linux/tc_act/tc_gact.h>
#endif

#ifndef TC_ACT_GOTO_CHAIN
#define __TC_ACT_EXT(local) ((local) << __TC_ACT_EXT_SHIFT)
#define TC_ACT_GOTO_CHAIN __TC_ACT_EXT(2)
#endif

#ifndef TCA_ACT_GACT
#define TCA_ACT_GACT 5
#endif


#endif	/* _COMPAT_NET_TC_ACT_TC_GACT_H */
