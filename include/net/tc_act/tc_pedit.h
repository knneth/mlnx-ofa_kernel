#ifndef _COMPAT_NET_TC_ACT_TC_PEDIT_H
#define _COMPAT_NET_TC_ACT_TC_PEDIT_H 1

#include "../../../compat/config.h"

#ifdef HAVE_TCF_PEDIT_TCFP_KEYS_EX
#include_next <net/tc_act/tc_pedit.h>

#ifndef HAVE_TCF_PEDIT_NKEYS
#include <linux/tc_act/tc_pedit.h>


static inline bool is_tcf_pedit(const struct tc_action *a)
{
#ifdef CONFIG_NET_CLS_ACT
	if (a->ops && a->ops->type == TCA_ACT_PEDIT)
		return true;
#endif
	return false;
}

static inline int tcf_pedit_nkeys(const struct tc_action *a)
{
	return to_pedit(a)->tcfp_nkeys;
}

static inline u32 tcf_pedit_htype(const struct tc_action *a, int index)
{
	if (to_pedit(a)->tcfp_keys_ex)
		return to_pedit(a)->tcfp_keys_ex[index].htype;

	return TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK;
}

static inline u32 tcf_pedit_cmd(const struct tc_action *a, int index)
{
	if (to_pedit(a)->tcfp_keys_ex)
		return to_pedit(a)->tcfp_keys_ex[index].cmd;

	return __PEDIT_CMD_MAX;
}

static inline u32 tcf_pedit_mask(const struct tc_action *a, int index)
{
	return to_pedit(a)->tcfp_keys[index].mask;
}

static inline u32 tcf_pedit_val(const struct tc_action *a, int index)
{
	return to_pedit(a)->tcfp_keys[index].val;
}

static inline u32 tcf_pedit_offset(const struct tc_action *a, int index)
{
	return to_pedit(a)->tcfp_keys[index].off;
}

#endif /* HAVE_TCF_PEDIT_NKEYS */

#endif /* HAVE_TCF_PEDIT_TCFP_KEYS_EX */

#endif	/* _COMPAT_NET_TC_ACT_TC_PEDIT_H */
