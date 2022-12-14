#ifndef COMPAT_LINUX_UAPI_DEVLINK_H
#define COMPAT_LINUX_UAPI_DEVLINK_H

#include "../../../compat/config.h"

#ifndef HAVE_DEVLINK_HAS_ESWITCH_MODE_GET_SET
enum devlink_eswitch_mode {
	DEVLINK_ESWITCH_MODE_LEGACY,
	DEVLINK_ESWITCH_MODE_SWITCHDEV,
};
#endif

#ifndef HAVE_DEVLINK_HAS_ESWITCH_INLINE_MODE_GET_SET
enum devlink_eswitch_inline_mode {
	DEVLINK_ESWITCH_INLINE_MODE_NONE,
	DEVLINK_ESWITCH_INLINE_MODE_LINK,
	DEVLINK_ESWITCH_INLINE_MODE_NETWORK,
	DEVLINK_ESWITCH_INLINE_MODE_TRANSPORT,
};
#endif

#ifndef HAVE_DEVLINK_HAS_ESWITCH_ENCAP_MODE_SET
enum devlink_eswitch_encap_mode {
	DEVLINK_ESWITCH_ENCAP_MODE_NONE,
	DEVLINK_ESWITCH_ENCAP_MODE_BASIC,
};
#endif

enum devlink_eswitch_ipsec_mode {
	DEVLINK_ESWITCH_IPSEC_MODE_NONE,
	DEVLINK_ESWITCH_IPSEC_MODE_FULL,
};

enum devlink_eswitch_steering_mode {
	DEVLINK_ESWITCH_STEERING_MODE_DMFS,
	DEVLINK_ESWITCH_STEERING_MODE_SMFS,
};

enum devlink_eswitch_vport_match_mode {
	DEVLINK_ESWITCH_VPORT_MATCH_MODE_METADATA,
	DEVLINK_ESWITCH_VPORT_MATCH_MODE_LEGACY,
};

#ifndef HAVE_DEVLINK_PORT_FLAVOUR
enum devlink_port_flavour {
	DEVLINK_PORT_FLAVOUR_PHYSICAL,
};
#endif

#ifdef HAVE_DEVLINK_H
#include_next <uapi/linux/devlink.h>

#ifndef HAVE_DEVLINK_PORT_FLAVOUR_VIRTUAL
enum devlink_port_flavour_virtual {
	DEVLINK_PORT_FLAVOUR_VIRTUAL = 0, /* Any virtual port facing the user (Define it to be equal to DEVLINK_PORT_FLAVOUR_PHYSICAL vlaue). */
};
#endif

#else /* HAVE_DEVLINK_H */

#endif /* HAVE_DEVLINK_H */

#endif /* COMPAT_LINUX_UAPI_DEVLINK_H */
