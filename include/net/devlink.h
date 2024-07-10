#ifndef _COMPAT_NET_DEVLINK_H
#define _COMPAT_NET_DEVLINK_H

#include "../../compat/config.h"

#include_next <net/devlink.h>

#ifndef DEVLINK_INFO_VERSION_GENERIC_FW
#define DEVLINK_INFO_VERSION_GENERIC_FW         "fw"
#endif

#ifndef HAVE_DEVLINK_PORT_NEW_ATTRS_STRUCT
struct devlink_port_new_attrs {
	enum devlink_port_flavour flavour;
	unsigned int port_index;
	u32 controller;
	u32 sfnum;
	u16 pfnum;
	u8 port_index_valid:1,
		controller_valid:1,
		sfnum_valid:1;
	};
#endif

#ifndef HAVE_DEVLINK_NET
static inline struct net *devlink_net(const struct devlink *devlink)
{
	return &init_net;
}
#endif

#if !defined(HAVE_DEVLINK_DRIVERINIT_VAL) && !defined(HAVE_DEVL_PARAM_DRIVERINIT_VALUE_GET)
#define __DEVLINK_PARAM_MAX_STRING_VALUE 32
enum devlink_param_type {
	DEVLINK_PARAM_TYPE_U8,
	DEVLINK_PARAM_TYPE_U16,
	DEVLINK_PARAM_TYPE_U32,
	DEVLINK_PARAM_TYPE_STRING,
	DEVLINK_PARAM_TYPE_BOOL,
};

union devlink_param_value {
	u8 vu8;
	u16 vu16;
	u32 vu32;
	char vstr[__DEVLINK_PARAM_MAX_STRING_VALUE];
	bool vbool;
};

extern unsigned int esw_offloads_num_big_groups;

static inline int
devlink_param_driverinit_value_get(struct devlink *devlink, u32 param_id,
				   union devlink_param_value *init_val)
{
	/* if param_id is MLX5_DEVLINK_PARAM_ID_ESW_LARGE_GROUP_NUM */
	if (param_id == DEVLINK_PARAM_GENERIC_ID_MAX + 2)
		init_val->vu32 = esw_offloads_num_big_groups;
	else
		return -EOPNOTSUPP;

	return 0;
}

struct devlink_param_gset_ctx {
	union devlink_param_value val;
	enum devlink_param_cmode cmode;
};

#endif /* HAVE_DEVLINK_DRIVERINIT_VAL */
#endif /* _COMPAT_NET_DEVLINK_H */
