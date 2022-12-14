#ifndef _COMPAT_NET_TC_ACT_TC_MIRRED_H
#define _COMPAT_NET_TC_ACT_TC_MIRRED_H 1

#include "../../../compat/config.h"

#ifdef HAVE_NET_TC_ACT_TC_MIRRED_H
#include_next <net/tc_act/tc_mirred.h>

#if !defined(HAVE_IS_TCF_MIRRED_EGRESS_REDIRECT) && defined(HAVE_IS_TCF_MIRRED_REDIRECT)
#define is_tcf_mirred_egress_redirect is_tcf_mirred_redirect
#define is_tcf_mirred_egress_mirror is_tcf_mirred_mirror
#endif

#endif /* NET_TC_ACT_TC_MIRRED_H */

#endif	/* _COMPAT_NET_TC_ACT_TC_MIRRED_H */
