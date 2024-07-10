#ifndef _COMPAT_NET_TC_ACT_TC_PEDIT_H
#define _COMPAT_NET_TC_ACT_TC_PEDIT_H 1

#include "../../../compat/config.h"

#ifndef CONFIG_COMPAT_TCF_PEDIT_MOD
#if defined(HAVE_TCF_PEDIT_TCFP_KEYS_EX) || defined(HAVE_TCF_PEDIT_PARMS_TCFP_KEYS_EX)
#include_next <net/tc_act/tc_pedit.h>
#endif

#else /* CONFIG_COMPAT_TCF_PEDIT_MOD */

#include <net/act_api.h>
#include "uapi/linux/tc_act/tc_pedit.h"

struct tcf_pedit_key_ex {
	enum pedit_header_type htype;
	enum pedit_cmd cmd;
};

struct tcf_pedit {
	struct tc_action	common;
	unsigned char		tcfp_nkeys;
	unsigned char		tcfp_flags;
	struct tc_pedit_key	*tcfp_keys;
	struct tcf_pedit_key_ex	*tcfp_keys_ex;
};

#define to_pedit(a) ((struct tcf_pedit *)a)

#endif /* CONFIG_COMPAT_TCF_PEDIT_MOD */

#if defined(HAVE_TCF_PEDIT_TCFP_KEYS_EX) || defined(HAVE_TCF_PEDIT_PARMS_TCFP_KEYS_EX)

#endif /* HAVE_TCF_PEDIT_TCFP_KEYS_EX || HAVE_TCF_PEDIT_PARMS_TCFP_KEYS_EX */

#endif	/* _COMPAT_NET_TC_ACT_TC_PEDIT_H */
