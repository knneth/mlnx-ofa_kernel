#ifndef _COMPAT_NET_FLOW_DISSECTOR_H
#define _COMPAT_NET_FLOW_DISSECTOR_H

#include "../../compat/config.h"

#include_next <net/flow_dissector.h>

#ifndef HAVE_FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP
#define FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP BIT(3)
#endif

#ifndef HAVE_FLOW_DISSECTOR_KEY_META
enum {
	FLOW_DISSECTOR_KEY_META = FLOW_DISSECTOR_KEY_MAX, /* struct flow_dissector_key_meta */
	FLOW_DISSECTOR_KEY_CT, /* struct flow_dissector_key_ct */
};

/**
 * struct flow_dissector_key_meta:
 * @ingress_ifindex: ingress ifindex
 * @ingress_iftype: ingress interface type
 */
struct flow_dissector_key_meta {
	int ingress_ifindex;
	u16 ingress_iftype;
};
#endif /* HAVE_FLOW_DISSECTOR_KEY_META */

#endif /* _COMPAT_NET_FLOW_DISSECTOR_H */
