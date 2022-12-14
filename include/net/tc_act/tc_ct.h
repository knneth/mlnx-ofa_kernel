#ifndef _COMPAT_NET_TC_ACT_TC_CT_H
#define _COMPAT_NET_TC_ACT_TC_CT_H 1

#include "../../../compat/config.h"

#include <uapi/linux/tc_act/tc_ct.h>

#ifdef CONFIG_COMPAT_KERNEL_CT
#include_next <net/tc_act/tc_ct.h>
#endif

#ifdef CONFIG_COMPAT_CLS_FLOWER_4_18_MOD
#define CONFIG_COMPAT_ACT_CT
#include <net/tc_act/tc_ct_4_18.h>
#endif

#endif /* _COMPAT_NET_TC_ACT_TC_CT_H */
