#ifndef _COMPAT_NET_FLOW_DISSECTOR_H
#define _COMPAT_NET_FLOW_DISSECTOR_H

#include "../../compat/config.h"

#include_next <net/flow_dissector.h>

#ifndef HAVE_FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP
#define FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP BIT(3)
#endif


#endif /* _COMPAT_NET_FLOW_DISSECTOR_H */
