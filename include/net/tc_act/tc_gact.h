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

#if (!defined(HAVE_IS_TCF_GACT_ACT) && !defined(HAVE_IS_TCF_GACT_ACT_OLD))
static inline bool __is_tcf_gact_act(const struct tc_action *a, int act)
{
#ifdef CONFIG_NET_CLS_ACT
	struct tcf_gact *gact;

	if (a->ops && a->ops->type != TCA_ACT_GACT)
		return false;
#ifdef CONFIG_COMPAT_KERNEL3_10_0_327
	gact = to_gact(a->priv);
#else
	gact = to_gact(a);
#endif
	if (gact->tcf_action == act)
		return true;

#endif
	return false;
}
#endif

#if !defined(HAVE_IS_TCF_GACT_OK)
static inline bool is_tcf_gact_ok(const struct tc_action *a)
{
#ifdef HAVE_IS_TCF_GACT_ACT
	return __is_tcf_gact_act(a, TC_ACT_OK, false);
#else
	return __is_tcf_gact_act(a, TC_ACT_OK);
#endif
}
#endif /* HAVE_IS_TCF_GACT_OK */

#endif	/* _COMPAT_NET_TC_ACT_TC_GACT_H */
