#ifndef _COMPAT_UAPI_LINUX_TC_ACT_TC_CT_H
#define _COMPAT_UAPI_LINUX_TC_ACT_TC_CT_H

#include "../../../../compat/config.h"

#ifdef CONFIG_COMPAT_KERNEL_CT
#include_next <uapi/linux/tc_act/tc_ct.h>
#endif

#ifdef CONFIG_COMPAT_CLS_FLOWER_4_18_MOD
#include "tc_ct_4_18.h"
#endif

#ifndef TCA_CT_ACT_CLEAR
#define TCA_CT_ACT_CLEAR        (1 << 2)
#endif

#endif /* _COMPAT_UAPI_LINUX_TC_ACT_TC_CT_H */
