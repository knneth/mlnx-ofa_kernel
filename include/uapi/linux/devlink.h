#ifndef _COMPAT_UAPI_LINUX_DEVLINK_H
#define _COMPAT_UAPI_LINUX_DEVLINK_H

#include "../../../compat/config.h"

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

enum devlink_eswitch_lag_port_select_mode {
	DEVLINK_ESWITCH_LAG_PORT_SELECT_MODE_QUEUE_AFFINITY,
	DEVLINK_ESWITCH_LAG_PORT_SELECT_MODE_HASH,
	DEVLINK_ESWITCH_LAG_PORT_SELECT_MODE_MULTIPORT_ESW,
};

#include_next <uapi/linux/devlink.h>

#ifndef HAVE_DEVLINK_PORT_FLAVOUR_VIRTUAL
enum devlink_port_flavour_virtual {
	DEVLINK_PORT_FLAVOUR_VIRTUAL = 0, /* Any virtual port facing the user (Define it to be equal to DEVLINK_PORT_FLAVOUR_PHYSICAL vlaue). */
};
#endif

#ifndef HAVE_DEVLINK_PORT_FN_STATE
enum devlink_port_fn_state {
	DEVLINK_PORT_FN_STATE_INACTIVE,
	DEVLINK_PORT_FN_STATE_ACTIVE,
};
#endif

#ifndef HAVE_DEVLINK_PORT_FN_OPSTATE
enum devlink_port_fn_opstate {
	DEVLINK_PORT_FN_OPSTATE_DETACHED,
	DEVLINK_PORT_FN_OPSTATE_ATTACHED,
};
#endif

#ifndef HAVE_DEVLINK_PORT_FLAVOUR_PCI_SF
#define DEVLINK_PORT_FLAVOUR_PCI_SF  7
#endif

#endif /* _COMPAT_UAPI_LINUX_DEVLINK_H */
