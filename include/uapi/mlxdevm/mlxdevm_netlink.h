/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies Ltd */

#ifndef _COMPAT_UAPI_MLXDEVM_MLXDEVM_NETLINK_H
#define _COMPAT_UAPI_MLXDEVM_MLXDEVM_NETLINK_H

#include "../../../compat/config.h"

#define MLXDEVM_GENL_NAME "mlxdevm"
#define MLXDEVM_GENL_VERSION 0x1

enum mlxdevm_command {
	MLXDEVM_CMD_UNSPEC =	0,

	MLXDEVM_CMD_DEV_GET =	1,		/* can dump */
	MLXDEVM_CMD_DEV_NEW =	3,

	MLXDEVM_CMD_PORT_GET =	5,		/* can dump */
	MLXDEVM_CMD_PORT_SET =	6,
	MLXDEVM_CMD_PORT_NEW =	7,
	MLXDEVM_CMD_PORT_DEL =	8,

	MLXDEVM_CMD_PARAM_GET =	38,		/* can dump */
	MLXDEVM_CMD_PARAM_SET =	39,
	MLXDEVM_CMD_PARAM_NEW =	40,
	MLXDEVM_CMD_PARAM_DEL =	41,

	/* All upstream devlink commands must be added before with the exact
	 * value as that of upstream without fail.
	 * All devm specific must start after MLXDEVM_CMD_EXT_START.
	 * Do not ever change the values. Only add at the end. Never in the
	 * middle.
	 */
	MLXDEVM_CMD_EXT_START = 160,

	MLXDEVM_CMD_EXT_CAP_SET,
	MLXDEVM_CMD_EXT_RATE_NEW,
	MLXDEVM_CMD_EXT_RATE_DEL,
	MLXDEVM_CMD_EXT_RATE_GET,		/* can dump */
	MLXDEVM_CMD_EXT_RATE_SET,
	__MLXDEVM_CMD_MAX,
	MLXDEVM_CMD_MAX = __MLXDEVM_CMD_MAX - 1
};

enum mlxdevm_port_type {
	MLXDEVM_PORT_TYPE_NOTSET =	0,
	MLXDEVM_PORT_TYPE_AUTO =	1,
	MLXDEVM_PORT_TYPE_ETH =		2,
	MLXDEVM_PORT_TYPE_IB =		3,
};

enum mlxdevm_rate_type {
	MLXDEVM_RATE_EXT_TYPE_NODE = 160,
	MLXDEVM_RATE_EXT_TYPE_LEAF,
};

enum mlxdevm_attr {
	MLXDEVM_ATTR_UNSPEC =			0,

	/* bus name (optional) + dev name together make the parent device handle */
	MLXDEVM_ATTR_DEV_BUS_NAME =		1,	/* string */
	MLXDEVM_ATTR_DEV_NAME =			2,	/* string */

	MLXDEVM_ATTR_PORT_INDEX =		3,	/* u32 */
	MLXDEVM_ATTR_PORT_TYPE =		4,	/* u16 */
	MLXDEVM_ATTR_PORT_NETDEV_IFINDEX =	6,	/* u32 */
	MLXDEVM_ATTR_PORT_NETDEV_NAME =		7,	/* string */
	MLXDEVM_ATTR_PORT_IBDEV_NAME =		8,	/* string */
	MLXDEVM_ATTR_PORT_FLAVOUR =		77,	/* u16 */
	MLXDEVM_ATTR_PORT_NUMBER =		78,	/* u32 */
	MLXDEVM_ATTR_PORT_FUNCTION =		145,	/* nested */
	MLXDEVM_ATTR_PORT_EXTERNAL =		149,	/* u8 */
	MLXDEVM_ATTR_PORT_CONTROLLER_NUMBER =	150,	/* u32 */
	MLXDEVM_ATTR_PORT_PCI_PF_NUMBER =	127,	/* u16 */
	MLXDEVM_ATTR_PORT_PCI_SF_NUMBER =	164,	/* u32 */

	MLXDEVM_ATTR_PARAM =			80,	/* nested */
	MLXDEVM_ATTR_PARAM_NAME =		81,	/* string */
	MLXDEVM_ATTR_PARAM_GENERIC =		82,	/* flag */
	MLXDEVM_ATTR_PARAM_TYPE =		83,	/* u8 */
	MLXDEVM_ATTR_PARAM_VALUES_LIST =	84,	/* nested */
	MLXDEVM_ATTR_PARAM_VALUE =		85,	/* nested */
	MLXDEVM_ATTR_PARAM_VALUE_DATA =		86,	/* dynamic */
	MLXDEVM_ATTR_PARAM_VALUE_CMODE =	87,	/* u8 */

	/* All upstream devlink attributes must be added before with the exact
	 * value as that of upstream without fail.
	 * All devm specific must start after MLXDEVM_ATTR_EXT_START.
	 * Do not ever change the values. Only add at the end. Never in the
	 * middle.
	 */
	MLXDEVM_ATTR_EXT_START =		8192,

	MLXDEVM_ATTR_EXT_PORT_FN_CAP,			/* nested */
	MLXDEVM_ATTR_EXT_RATE_TYPE,			/* u16 */
	MLXDEVM_ATTR_EXT_RATE_NODE_NAME,		/* string */
	MLXDEVM_ATTR_EXT_PAD,
	MLXDEVM_ATTR_EXT_RATE_TX_SHARE,			/* u64 */
	MLXDEVM_ATTR_EXT_RATE_TX_MAX,			/* u64 */
	MLXDEVM_ATTR_EXT_RATE_PARENT_NODE_NAME,		/* string */
	MLXDEVM_ATTR_EXT_PARAM_ARRAY_TYPE,              /* u8 */

	__MLXDEVM_ATTR_MAX,
	MLXDEVM_ATTR_MAX = __MLXDEVM_ATTR_MAX - 1
};

enum mlxdevm_port_fn_attr {
	MLXDEVM_PORT_FUNCTION_ATTR_UNSPEC =	0,
	MLXDEVM_PORT_FUNCTION_ATTR_HW_ADDR =	1,	/* binary */
	MLXDEVM_PORT_FN_ATTR_STATE =		2,	/* u8 */
	MLXDEVM_PORT_FN_ATTR_OPSTATE =		3,	/* u8 */

	/* All upstream devlink port function attributes must be added before
	 * with the exact value as that of upstream without fail.
	 * All devm specific must start after MLXDEVM_PORT_FN_ATTR_EXT_START.
	 * Do not ever change the values. Only add at the end. Never in the
	 * middle.
	 */
	MLXDEVM_PORT_FUNCTION_ATTR_EXT_START =	160,

	MLXDEVM_PORT_FN_ATTR_EXT_CAP_ROCE,		/* u8 */
	MLXDEVM_PORT_FN_ATTR_EXT_CAP_UC_LIST,		/* u32 */

	__MLXDEVM_PORT_FUNCTION_ATTR_MAX,
	MLXDEVM_PORT_FUNCTION_ATTR_MAX = __MLXDEVM_PORT_FUNCTION_ATTR_MAX - 1
};

enum mlxdevm_port_fn_state {
	MLXDEVM_PORT_FN_STATE_INACTIVE =	0,
	MLXDEVM_PORT_FN_STATE_ACTIVE =		1,
};

enum mlxdevm_port_flavour {
	MLXDEVM_PORT_FLAVOUR_PHYSICAL = 0, /* Any kind of a port physically
					    * facing the user.
					    */
	MLXDEVM_PORT_FLAVOUR_CPU =	1, /* CPU port */
	MLXDEVM_PORT_FLAVOUR_DSA =	2, /* Distributed switch architecture
					    * interconnect port.
					    */
	MLXDEVM_PORT_FLAVOUR_PCI_PF =	3, /* Represents eswitch port for
					    * the PCI PF. It is an internal
					    * port that faces the PCI PF.
					    */
	MLXDEVM_PORT_FLAVOUR_PCI_VF =	4, /* Represents eswitch port
					    * for the PCI VF. It is an internal
					    * port that faces the PCI VF.
					    */
	MLXDEVM_PORT_FLAVOUR_VIRTUAL =	5, /* Any virtual port facing the user. */
	MLXDEVM_PORT_FLAVOUR_UNUSED =	6, /* Port which exists in the switch, but
					    * is not used in any way.
					    */
	MLXDEVM_PORT_FLAVOUR_PCI_SF =	7, /* Represents eswitch port
					    * for the PCI SF. It is an internal
					    * port that faces the PCI SF.
					    */
};

enum mlxdevm_port_fn_cap_roce {
	MLXDEVM_PORT_FN_CAP_ROCE_DISABLE =	0,
	MLXDEVM_PORT_FN_CAP_ROCE_ENABLE =	1,
};

enum mlxdevm_param_cmode {
	MLXDEVM_PARAM_CMODE_RUNTIME =		0,
	MLXDEVM_PARAM_CMODE_DRIVERINIT =	1,
	MLXDEVM_PARAM_CMODE_PERMANENT =		2,

	/* Add new configuration modes above */
	__MLXDEVM_PARAM_CMODE_MAX =		3,
	MLXDEVM_PARAM_CMODE_MAX = __MLXDEVM_PARAM_CMODE_MAX - 1
};

enum mlxdevm_param_fw_load_policy_value {
	MLXDEVM_PARAM_FW_LOAD_POLICY_VALUE_DRIVER =	0,
	MLXDEVM_PARAM_FW_LOAD_POLICY_VALUE_FLASH =	1,
	MLXDEVM_PARAM_FW_LOAD_POLICY_VALUE_DISK =	2,
	MLXDEVM_PARAM_FW_LOAD_POLICY_VALUE_UNKNOWN =	3,
};

enum mlxdevm_param_reset_dev_on_drv_probe_value {
	MLXDEVM_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_UNKNOWN =	0,
	MLXDEVM_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_ALWAYS =	1,
	MLXDEVM_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_NEVER =	2,
	MLXDEVM_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_DISK =	3,
};

/**
 * enum mlxdevm_port_fn_opstate - indicates operational state of the function
 * @MLXDEVM_PORT_FN_OPSTATE_ATTACHED: Driver is attached to the function.
 * For graceful tear down of the function, after inactivation of the
 * function, user should wait for operational state to turn DETACHED.
 * @MLXDEVM_PORT_FN_OPSTATE_DETACHED: Driver is detached from the function.
 * It is safe to delete the port.
 */
enum mlxdevm_port_fn_opstate {
	MLXDEVM_PORT_FN_OPSTATE_DETACHED =	0,
	MLXDEVM_PORT_FN_OPSTATE_ATTACHED =	1,
};
#endif /* _COMPAT_UAPI_MLXDEVM_MLXDEVM_NETLINK_H */
