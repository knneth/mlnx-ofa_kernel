#ifndef _COMPAT_NET_IP_FIB_H
#define _COMPAT_NET_IP_FIB_H 1

#include "../../compat/config.h"

#include_next <net/ip_fib.h>

#if !defined(HAVE_FIB_LOOKUP_EXPORTED) && defined(CONFIG_COMPAT_IS_FIB_LOOKUP_STATIC_AND_EXTERN)
#define fib_lookup LINUX_BACKPORT(fib_lookup)
int fib_lookup(struct net *net, struct flowi4 *flp, struct fib_result *res)
{
	struct fib_lookup_arg arg = {
		.result = res,
		.flags = FIB_LOOKUP_NOREF,
	};
	int err;

	err = fib_rules_lookup(net->ipv4.rules_ops, flowi4_to_flowi(flp), 0, &arg);
	res->r = arg.rule;

	return err;
}
#endif
#endif	/* _COMPAT_NET_IP_FIB_H */
