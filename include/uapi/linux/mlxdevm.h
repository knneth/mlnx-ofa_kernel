/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * include/uapi/linux/devlink.h - Network physical device Netlink interface
 * Copyright (c) 2016 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2016 Jiri Pirko <jiri@mellanox.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _COMPAT_UAPI_LINUX_MLXDEVM_H
#define _COMPAT_UAPI_LINUX_MLXDEVM_H

#include "../../../compat/config.h"
#include <linux/const.h>

#define MLXDEVM_GENL_NAME "mlxdevm"
#define MLXDEVM_GENL_VERSION 0x1
#define MLXDEVM_GENL_MCGRP_CONFIG_NAME "config"

enum mlxdevm_command {
	/* don't change the order or add anything between, this is ABI! */
	MLXDEVM_CMD_UNSPEC,

	MLXDEVM_CMD_GET,		/* can dump */
	MLXDEVM_CMD_SET,
	MLXDEVM_CMD_NEW,
	MLXDEVM_CMD_DEL,

	MLXDEVM_CMD_PORT_GET,		/* can dump */
	MLXDEVM_CMD_PORT_SET,
	MLXDEVM_CMD_PORT_NEW,
	MLXDEVM_CMD_PORT_DEL,

	MLXDEVM_CMD_PORT_SPLIT,
	MLXDEVM_CMD_PORT_UNSPLIT,

	MLXDEVM_CMD_SB_GET,		/* can dump */
	MLXDEVM_CMD_SB_SET,
	MLXDEVM_CMD_SB_NEW,
	MLXDEVM_CMD_SB_DEL,

	MLXDEVM_CMD_SB_POOL_GET,	/* can dump */
	MLXDEVM_CMD_SB_POOL_SET,
	MLXDEVM_CMD_SB_POOL_NEW,
	MLXDEVM_CMD_SB_POOL_DEL,

	MLXDEVM_CMD_SB_PORT_POOL_GET,	/* can dump */
	MLXDEVM_CMD_SB_PORT_POOL_SET,
	MLXDEVM_CMD_SB_PORT_POOL_NEW,
	MLXDEVM_CMD_SB_PORT_POOL_DEL,

	MLXDEVM_CMD_SB_TC_POOL_BIND_GET,	/* can dump */
	MLXDEVM_CMD_SB_TC_POOL_BIND_SET,
	MLXDEVM_CMD_SB_TC_POOL_BIND_NEW,
	MLXDEVM_CMD_SB_TC_POOL_BIND_DEL,

	/* Shared buffer occupancy monitoring commands */
	MLXDEVM_CMD_SB_OCC_SNAPSHOT,
	MLXDEVM_CMD_SB_OCC_MAX_CLEAR,

	MLXDEVM_CMD_ESWITCH_GET,
#define MLXDEVM_CMD_ESWITCH_MODE_GET /* obsolete, never use this! */ \
	MLXDEVM_CMD_ESWITCH_GET

	MLXDEVM_CMD_ESWITCH_SET,
#define MLXDEVM_CMD_ESWITCH_MODE_SET /* obsolete, never use this! */ \
	MLXDEVM_CMD_ESWITCH_SET

	MLXDEVM_CMD_DPIPE_TABLE_GET,
	MLXDEVM_CMD_DPIPE_ENTRIES_GET,
	MLXDEVM_CMD_DPIPE_HEADERS_GET,
	MLXDEVM_CMD_DPIPE_TABLE_COUNTERS_SET,
	MLXDEVM_CMD_RESOURCE_SET,
	MLXDEVM_CMD_RESOURCE_DUMP,

	/* Hot driver reload, makes configuration changes take place. The
	 * devlink instance is not released during the process.
	 */
	MLXDEVM_CMD_RELOAD,

	MLXDEVM_CMD_PARAM_GET,		/* can dump */
	MLXDEVM_CMD_PARAM_SET,
	MLXDEVM_CMD_PARAM_NEW,
	MLXDEVM_CMD_PARAM_DEL,

	MLXDEVM_CMD_REGION_GET,
	MLXDEVM_CMD_REGION_SET,
	MLXDEVM_CMD_REGION_NEW,
	MLXDEVM_CMD_REGION_DEL,
	MLXDEVM_CMD_REGION_READ,

	MLXDEVM_CMD_PORT_PARAM_GET,	/* can dump */
	MLXDEVM_CMD_PORT_PARAM_SET,
	MLXDEVM_CMD_PORT_PARAM_NEW,
	MLXDEVM_CMD_PORT_PARAM_DEL,

	MLXDEVM_CMD_INFO_GET,		/* can dump */

	MLXDEVM_CMD_HEALTH_REPORTER_GET,
	MLXDEVM_CMD_HEALTH_REPORTER_SET,
	MLXDEVM_CMD_HEALTH_REPORTER_RECOVER,
	MLXDEVM_CMD_HEALTH_REPORTER_DIAGNOSE,
	MLXDEVM_CMD_HEALTH_REPORTER_DUMP_GET,
	MLXDEVM_CMD_HEALTH_REPORTER_DUMP_CLEAR,

	MLXDEVM_CMD_FLASH_UPDATE,
	MLXDEVM_CMD_FLASH_UPDATE_END,		/* notification only */
	MLXDEVM_CMD_FLASH_UPDATE_STATUS,	/* notification only */

	MLXDEVM_CMD_TRAP_GET,		/* can dump */
	MLXDEVM_CMD_TRAP_SET,
	MLXDEVM_CMD_TRAP_NEW,
	MLXDEVM_CMD_TRAP_DEL,

	MLXDEVM_CMD_TRAP_GROUP_GET,	/* can dump */
	MLXDEVM_CMD_TRAP_GROUP_SET,
	MLXDEVM_CMD_TRAP_GROUP_NEW,
	MLXDEVM_CMD_TRAP_GROUP_DEL,

	MLXDEVM_CMD_TRAP_POLICER_GET,	/* can dump */
	MLXDEVM_CMD_TRAP_POLICER_SET,
	MLXDEVM_CMD_TRAP_POLICER_NEW,
	MLXDEVM_CMD_TRAP_POLICER_DEL,

	MLXDEVM_CMD_HEALTH_REPORTER_TEST,

	MLXDEVM_CMD_RATE_GET,		/* can dump */
	MLXDEVM_CMD_RATE_SET,
	MLXDEVM_CMD_RATE_NEW,
	MLXDEVM_CMD_RATE_DEL,

	MLXDEVM_CMD_LINECARD_GET,		/* can dump */
	MLXDEVM_CMD_LINECARD_SET,
	MLXDEVM_CMD_LINECARD_NEW,
	MLXDEVM_CMD_LINECARD_DEL,

	MLXDEVM_CMD_SELFTESTS_GET,	/* can dump */
	MLXDEVM_CMD_SELFTESTS_RUN,

	MLXDEVM_CMD_NOTIFY_FILTER_SET,

	/* add new commands above here */
	__MLXDEVM_CMD_MAX,
	MLXDEVM_CMD_MAX = __MLXDEVM_CMD_MAX - 1
};

enum mlxdevm_port_type {
	MLXDEVM_PORT_TYPE_NOTSET,
	MLXDEVM_PORT_TYPE_AUTO,
	MLXDEVM_PORT_TYPE_ETH,
	MLXDEVM_PORT_TYPE_IB,
};

enum mlxdevm_sb_pool_type {
	MLXDEVM_SB_POOL_TYPE_INGRESS,
	MLXDEVM_SB_POOL_TYPE_EGRESS,
};

/* static threshold - limiting the maximum number of bytes.
 * dynamic threshold - limiting the maximum number of bytes
 *   based on the currently available free space in the shared buffer pool.
 *   In this mode, the maximum quota is calculated based
 *   on the following formula:
 *     max_quota = alpha / (1 + alpha) * Free_Buffer
 *   While Free_Buffer is the amount of none-occupied buffer associated to
 *   the relevant pool.
 *   The value range which can be passed is 0-20 and serves
 *   for computation of alpha by following formula:
 *     alpha = 2 ^ (passed_value - 10)
 */

enum mlxdevm_sb_threshold_type {
	MLXDEVM_SB_THRESHOLD_TYPE_STATIC,
	MLXDEVM_SB_THRESHOLD_TYPE_DYNAMIC,
};
#if 0

#define DEVLINK_SB_THRESHOLD_TO_ALPHA_MAX 20

enum devlink_eswitch_mode {
	DEVLINK_ESWITCH_MODE_LEGACY,
	DEVLINK_ESWITCH_MODE_SWITCHDEV,
};

enum devlink_eswitch_inline_mode {
	DEVLINK_ESWITCH_INLINE_MODE_NONE,
	DEVLINK_ESWITCH_INLINE_MODE_LINK,
	DEVLINK_ESWITCH_INLINE_MODE_NETWORK,
	DEVLINK_ESWITCH_INLINE_MODE_TRANSPORT,
};
#endif

enum mlxdevm_eswitch_encap_mode {
	MLXDEVM_ESWITCH_ENCAP_MODE_NONE,
	MLXDEVM_ESWITCH_ENCAP_MODE_BASIC,
};

enum mlxdevm_port_flavour {
	MLXDEVM_PORT_FLAVOUR_PHYSICAL, /* Any kind of a port physically
					* facing the user.
					*/
	MLXDEVM_PORT_FLAVOUR_CPU, /* CPU port */
	MLXDEVM_PORT_FLAVOUR_DSA, /* Distributed switch architecture
				   * interconnect port.
				   */
	MLXDEVM_PORT_FLAVOUR_PCI_PF, /* Represents eswitch port for
				      * the PCI PF. It is an internal
				      * port that faces the PCI PF.
				      */
	MLXDEVM_PORT_FLAVOUR_PCI_VF, /* Represents eswitch port
				      * for the PCI VF. It is an internal
				      * port that faces the PCI VF.
				      */
	MLXDEVM_PORT_FLAVOUR_VIRTUAL, /* Any virtual port facing the user. */
	MLXDEVM_PORT_FLAVOUR_UNUSED, /* Port which exists in the switch, but
				      * is not used in any way.
				      */
	MLXDEVM_PORT_FLAVOUR_PCI_SF, /* Represents eswitch port
				      * for the PCI SF. It is an internal
				      * port that faces the PCI SF.
				      */
};

enum mlxdevm_rate_type {
	MLXDEVM_RATE_TYPE_LEAF,
	MLXDEVM_RATE_TYPE_NODE,
};

enum mlxdevm_param_cmode {
	MLXDEVM_PARAM_CMODE_RUNTIME,
	MLXDEVM_PARAM_CMODE_DRIVERINIT,
	MLXDEVM_PARAM_CMODE_PERMANENT,

	/* Add new configuration modes above */
	__MLXDEVM_PARAM_CMODE_MAX,
	MLXDEVM_PARAM_CMODE_MAX = __MLXDEVM_PARAM_CMODE_MAX - 1
};
#if 0

enum devlink_param_fw_load_policy_value {
	DEVLINK_PARAM_FW_LOAD_POLICY_VALUE_DRIVER,
	DEVLINK_PARAM_FW_LOAD_POLICY_VALUE_FLASH,
	DEVLINK_PARAM_FW_LOAD_POLICY_VALUE_DISK,
	DEVLINK_PARAM_FW_LOAD_POLICY_VALUE_UNKNOWN,
};

enum devlink_param_reset_dev_on_drv_probe_value {
	DEVLINK_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_UNKNOWN,
	DEVLINK_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_ALWAYS,
	DEVLINK_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_NEVER,
	DEVLINK_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_DISK,
};

enum {
	DEVLINK_ATTR_STATS_RX_PACKETS,		/* u64 */
	DEVLINK_ATTR_STATS_RX_BYTES,		/* u64 */
	DEVLINK_ATTR_STATS_RX_DROPPED,		/* u64 */

	__DEVLINK_ATTR_STATS_MAX,
	DEVLINK_ATTR_STATS_MAX = __DEVLINK_ATTR_STATS_MAX - 1
};

/* Specify what sections of a flash component can be overwritten when
 * performing an update. Overwriting of firmware binary sections is always
 * implicitly assumed to be allowed.
 *
 * Each section must be documented in
 * Documentation/networking/devlink/devlink-flash.rst
 *
 */
enum devlink_flash_overwrite {
	DEVLINK_FLASH_OVERWRITE_SETTINGS_BIT,
	DEVLINK_FLASH_OVERWRITE_IDENTIFIERS_BIT,

	__DEVLINK_FLASH_OVERWRITE_MAX_BIT,
	DEVLINK_FLASH_OVERWRITE_MAX_BIT = __DEVLINK_FLASH_OVERWRITE_MAX_BIT - 1
};

#define DEVLINK_FLASH_OVERWRITE_SETTINGS _BITUL(DEVLINK_FLASH_OVERWRITE_SETTINGS_BIT)
#define DEVLINK_FLASH_OVERWRITE_IDENTIFIERS _BITUL(DEVLINK_FLASH_OVERWRITE_IDENTIFIERS_BIT)

#define DEVLINK_SUPPORTED_FLASH_OVERWRITE_SECTIONS \
	(_BITUL(__DEVLINK_FLASH_OVERWRITE_MAX_BIT) - 1)

enum devlink_attr_selftest_id {
	DEVLINK_ATTR_SELFTEST_ID_UNSPEC,
	DEVLINK_ATTR_SELFTEST_ID_FLASH,	/* flag */

	__DEVLINK_ATTR_SELFTEST_ID_MAX,
	DEVLINK_ATTR_SELFTEST_ID_MAX = __DEVLINK_ATTR_SELFTEST_ID_MAX - 1
};

enum devlink_selftest_status {
	DEVLINK_SELFTEST_STATUS_SKIP,
	DEVLINK_SELFTEST_STATUS_PASS,
	DEVLINK_SELFTEST_STATUS_FAIL
};

enum devlink_attr_selftest_result {
	DEVLINK_ATTR_SELFTEST_RESULT_UNSPEC,
	DEVLINK_ATTR_SELFTEST_RESULT,		/* nested */
	DEVLINK_ATTR_SELFTEST_RESULT_ID,	/* u32, enum devlink_attr_selftest_id */
	DEVLINK_ATTR_SELFTEST_RESULT_STATUS,	/* u8, enum devlink_selftest_status */

	__DEVLINK_ATTR_SELFTEST_RESULT_MAX,
	DEVLINK_ATTR_SELFTEST_RESULT_MAX = __DEVLINK_ATTR_SELFTEST_RESULT_MAX - 1
};
#endif

/**
 * enum mlxdevm_trap_action - Packet trap action.
 * @MLXDEVM_TRAP_ACTION_DROP: Packet is dropped by the device and a copy is not
 *                            sent to the CPU.
 * @MLXDEVM_TRAP_ACTION_TRAP: The sole copy of the packet is sent to the CPU.
 * @MLXDEVM_TRAP_ACTION_MIRROR: Packet is forwarded by the device and a copy is
 *                              sent to the CPU.
 */
enum mlxdevm_trap_action {
	MLXDEVM_TRAP_ACTION_DROP,
	MLXDEVM_TRAP_ACTION_TRAP,
	MLXDEVM_TRAP_ACTION_MIRROR,
};

/**
 * enum devlink_trap_type - Packet trap type.
 * @MLXDEVM_TRAP_TYPE_DROP: Trap reason is a drop. Trapped packets are only
 *                          processed by devlink and not injected to the
 *                          kernel's Rx path.
 * @MLXDEVM_TRAP_TYPE_EXCEPTION: Trap reason is an exception. Packet was not
 *                               forwarded as intended due to an exception
 *                               (e.g., missing neighbour entry) and trapped to
 *                               control plane for resolution. Trapped packets
 *                               are processed by devlink and injected to
 *                               the kernel's Rx path.
 * @MLXDEVM_TRAP_TYPE_CONTROL: Packet was trapped because it is required for
 *                             the correct functioning of the control plane.
 *                             For example, an ARP request packet. Trapped
 *                             packets are injected to the kernel's Rx path,
 *                             but not reported to drop monitor.
 */
enum mlxdevm_trap_type {
	MLXDEVM_TRAP_TYPE_DROP,
	MLXDEVM_TRAP_TYPE_EXCEPTION,
	MLXDEVM_TRAP_TYPE_CONTROL,
};
#if 0

enum {
	/* Trap can report input port as metadata */
	DEVLINK_ATTR_TRAP_METADATA_TYPE_IN_PORT,
	/* Trap can report flow action cookie as metadata */
	DEVLINK_ATTR_TRAP_METADATA_TYPE_FA_COOKIE,
};

#endif
enum mlxdevm_reload_action {
	MLXDEVM_RELOAD_ACTION_UNSPEC,
	MLXDEVM_RELOAD_ACTION_DRIVER_REINIT,	/* Driver entities re-instantiation */
	MLXDEVM_RELOAD_ACTION_FW_ACTIVATE,	/* FW activate */

	/* Add new reload actions above */
	__MLXDEVM_RELOAD_ACTION_MAX,
	MLXDEVM_RELOAD_ACTION_MAX = __MLXDEVM_RELOAD_ACTION_MAX - 1
};

enum mlxdevm_reload_limit {
	MLXDEVM_RELOAD_LIMIT_UNSPEC,	/* unspecified, no constraints */
	MLXDEVM_RELOAD_LIMIT_NO_RESET,	/* No reset allowed, no down time allowed,
					 * no link flap and no configuration is lost.
					 */

	/* Add new reload limit above */
	__MLXDEVM_RELOAD_LIMIT_MAX,
	MLXDEVM_RELOAD_LIMIT_MAX = __MLXDEVM_RELOAD_LIMIT_MAX - 1
};
#if 0

#define DEVLINK_RELOAD_LIMITS_VALID_MASK (_BITUL(__DEVLINK_RELOAD_LIMIT_MAX) - 1)
#endif

enum mlxdevm_linecard_state {
	MLXDEVM_LINECARD_STATE_UNSPEC,
	MLXDEVM_LINECARD_STATE_UNPROVISIONED,
	MLXDEVM_LINECARD_STATE_UNPROVISIONING,
	MLXDEVM_LINECARD_STATE_PROVISIONING,
	MLXDEVM_LINECARD_STATE_PROVISIONING_FAILED,
	MLXDEVM_LINECARD_STATE_PROVISIONED,
	MLXDEVM_LINECARD_STATE_ACTIVE,

	__MLXDEVM_LINECARD_STATE_MAX,
	MLXDEVM_LINECARD_STATE_MAX = __MLXDEVM_LINECARD_STATE_MAX - 1
};

enum mlxdevm_attr {
	/* don't change the order or add anything between, this is ABI! */
	MLXDEVM_ATTR_UNSPEC,

	/* bus name + dev name together are a handle for devlink entity */
	MLXDEVM_ATTR_BUS_NAME,			/* string */
	MLXDEVM_ATTR_DEV_NAME,			/* string */

	MLXDEVM_ATTR_PORT_INDEX,		/* u32 */
	MLXDEVM_ATTR_PORT_TYPE,			/* u16 */
	MLXDEVM_ATTR_PORT_DESIRED_TYPE,		/* u16 */
	MLXDEVM_ATTR_PORT_NETDEV_IFINDEX,	/* u32 */
	MLXDEVM_ATTR_PORT_NETDEV_NAME,		/* string */
	MLXDEVM_ATTR_PORT_IBDEV_NAME,		/* string */
	MLXDEVM_ATTR_PORT_SPLIT_COUNT,		/* u32 */
	MLXDEVM_ATTR_PORT_SPLIT_GROUP,		/* u32 */
	MLXDEVM_ATTR_SB_INDEX,			/* u32 */
	MLXDEVM_ATTR_SB_SIZE,			/* u32 */
	MLXDEVM_ATTR_SB_INGRESS_POOL_COUNT,	/* u16 */
	MLXDEVM_ATTR_SB_EGRESS_POOL_COUNT,	/* u16 */
	MLXDEVM_ATTR_SB_INGRESS_TC_COUNT,	/* u16 */
	MLXDEVM_ATTR_SB_EGRESS_TC_COUNT,	/* u16 */
	MLXDEVM_ATTR_SB_POOL_INDEX,		/* u16 */
	MLXDEVM_ATTR_SB_POOL_TYPE,		/* u8 */
	MLXDEVM_ATTR_SB_POOL_SIZE,		/* u32 */
	MLXDEVM_ATTR_SB_POOL_THRESHOLD_TYPE,	/* u8 */
	MLXDEVM_ATTR_SB_THRESHOLD,		/* u32 */
	MLXDEVM_ATTR_SB_TC_INDEX,		/* u16 */
	MLXDEVM_ATTR_SB_OCC_CUR,		/* u32 */
	MLXDEVM_ATTR_SB_OCC_MAX,		/* u32 */
	MLXDEVM_ATTR_ESWITCH_MODE,		/* u16 */
	MLXDEVM_ATTR_ESWITCH_INLINE_MODE,	/* u8 */

	MLXDEVM_ATTR_DPIPE_TABLES,		/* nested */
	MLXDEVM_ATTR_DPIPE_TABLE,		/* nested */
	MLXDEVM_ATTR_DPIPE_TABLE_NAME,		/* string */
	MLXDEVM_ATTR_DPIPE_TABLE_SIZE,		/* u64 */
	MLXDEVM_ATTR_DPIPE_TABLE_MATCHES,	/* nested */
	MLXDEVM_ATTR_DPIPE_TABLE_ACTIONS,	/* nested */
	MLXDEVM_ATTR_DPIPE_TABLE_COUNTERS_ENABLED,	/* u8 */

	MLXDEVM_ATTR_DPIPE_ENTRIES,		/* nested */
	MLXDEVM_ATTR_DPIPE_ENTRY,		/* nested */
	MLXDEVM_ATTR_DPIPE_ENTRY_INDEX,		/* u64 */
	MLXDEVM_ATTR_DPIPE_ENTRY_MATCH_VALUES,	/* nested */
	MLXDEVM_ATTR_DPIPE_ENTRY_ACTION_VALUES,	/* nested */
	MLXDEVM_ATTR_DPIPE_ENTRY_COUNTER,	/* u64 */

	MLXDEVM_ATTR_DPIPE_MATCH,		/* nested */
	MLXDEVM_ATTR_DPIPE_MATCH_VALUE,		/* nested */
	MLXDEVM_ATTR_DPIPE_MATCH_TYPE,		/* u32 */

	MLXDEVM_ATTR_DPIPE_ACTION,		/* nested */
	MLXDEVM_ATTR_DPIPE_ACTION_VALUE,	/* nested */
	MLXDEVM_ATTR_DPIPE_ACTION_TYPE,		/* u32 */

	MLXDEVM_ATTR_DPIPE_VALUE,
	MLXDEVM_ATTR_DPIPE_VALUE_MASK,
	MLXDEVM_ATTR_DPIPE_VALUE_MAPPING,	/* u32 */

	MLXDEVM_ATTR_DPIPE_HEADERS,		/* nested */
	MLXDEVM_ATTR_DPIPE_HEADER,		/* nested */
	MLXDEVM_ATTR_DPIPE_HEADER_NAME,		/* string */
	MLXDEVM_ATTR_DPIPE_HEADER_ID,		/* u32 */
	MLXDEVM_ATTR_DPIPE_HEADER_FIELDS,	/* nested */
	MLXDEVM_ATTR_DPIPE_HEADER_GLOBAL,	/* u8 */
	MLXDEVM_ATTR_DPIPE_HEADER_INDEX,	/* u32 */

	MLXDEVM_ATTR_DPIPE_FIELD,		/* nested */
	MLXDEVM_ATTR_DPIPE_FIELD_NAME,		/* string */
	MLXDEVM_ATTR_DPIPE_FIELD_ID,		/* u32 */
	MLXDEVM_ATTR_DPIPE_FIELD_BITWIDTH,	/* u32 */
	MLXDEVM_ATTR_DPIPE_FIELD_MAPPING_TYPE,	/* u32 */

	MLXDEVM_ATTR_PAD,

	MLXDEVM_ATTR_ESWITCH_ENCAP_MODE,	/* u8 */
	MLXDEVM_ATTR_RESOURCE_LIST,		/* nested */
	MLXDEVM_ATTR_RESOURCE,			/* nested */
	MLXDEVM_ATTR_RESOURCE_NAME,		/* string */
	MLXDEVM_ATTR_RESOURCE_ID,		/* u64 */
	MLXDEVM_ATTR_RESOURCE_SIZE,		/* u64 */
	MLXDEVM_ATTR_RESOURCE_SIZE_NEW,		/* u64 */
	MLXDEVM_ATTR_RESOURCE_SIZE_VALID,	/* u8 */
	MLXDEVM_ATTR_RESOURCE_SIZE_MIN,		/* u64 */
	MLXDEVM_ATTR_RESOURCE_SIZE_MAX,		/* u64 */
	MLXDEVM_ATTR_RESOURCE_SIZE_GRAN,        /* u64 */
	MLXDEVM_ATTR_RESOURCE_UNIT,		/* u8 */
	MLXDEVM_ATTR_RESOURCE_OCC,		/* u64 */
	MLXDEVM_ATTR_DPIPE_TABLE_RESOURCE_ID,	/* u64 */
	MLXDEVM_ATTR_DPIPE_TABLE_RESOURCE_UNITS,/* u64 */

	MLXDEVM_ATTR_PORT_FLAVOUR,		/* u16 */
	MLXDEVM_ATTR_PORT_NUMBER,		/* u32 */
	MLXDEVM_ATTR_PORT_SPLIT_SUBPORT_NUMBER,	/* u32 */

	MLXDEVM_ATTR_PARAM,			/* nested */
	MLXDEVM_ATTR_PARAM_NAME,		/* string */
	MLXDEVM_ATTR_PARAM_GENERIC,		/* flag */
	MLXDEVM_ATTR_PARAM_TYPE,		/* u8 */
	MLXDEVM_ATTR_PARAM_VALUES_LIST,		/* nested */
	MLXDEVM_ATTR_PARAM_VALUE,		/* nested */
	MLXDEVM_ATTR_PARAM_VALUE_DATA,		/* dynamic */
	MLXDEVM_ATTR_PARAM_VALUE_CMODE,		/* u8 */

	MLXDEVM_ATTR_REGION_NAME,               /* string */
	MLXDEVM_ATTR_REGION_SIZE,               /* u64 */
	MLXDEVM_ATTR_REGION_SNAPSHOTS,          /* nested */
	MLXDEVM_ATTR_REGION_SNAPSHOT,           /* nested */
	MLXDEVM_ATTR_REGION_SNAPSHOT_ID,        /* u32 */

	MLXDEVM_ATTR_REGION_CHUNKS,             /* nested */
	MLXDEVM_ATTR_REGION_CHUNK,              /* nested */
	MLXDEVM_ATTR_REGION_CHUNK_DATA,         /* binary */
	MLXDEVM_ATTR_REGION_CHUNK_ADDR,         /* u64 */
	MLXDEVM_ATTR_REGION_CHUNK_LEN,          /* u64 */

	MLXDEVM_ATTR_INFO_DRIVER_NAME,		/* string */
	MLXDEVM_ATTR_INFO_SERIAL_NUMBER,	/* string */
	MLXDEVM_ATTR_INFO_VERSION_FIXED,	/* nested */
	MLXDEVM_ATTR_INFO_VERSION_RUNNING,	/* nested */
	MLXDEVM_ATTR_INFO_VERSION_STORED,	/* nested */
	MLXDEVM_ATTR_INFO_VERSION_NAME,		/* string */
	MLXDEVM_ATTR_INFO_VERSION_VALUE,	/* string */

	MLXDEVM_ATTR_SB_POOL_CELL_SIZE,		/* u32 */

	MLXDEVM_ATTR_FMSG,			/* nested */
	MLXDEVM_ATTR_FMSG_OBJ_NEST_START,	/* flag */
	MLXDEVM_ATTR_FMSG_PAIR_NEST_START,	/* flag */
	MLXDEVM_ATTR_FMSG_ARR_NEST_START,	/* flag */
	MLXDEVM_ATTR_FMSG_NEST_END,		/* flag */
	MLXDEVM_ATTR_FMSG_OBJ_NAME,		/* string */
	MLXDEVM_ATTR_FMSG_OBJ_VALUE_TYPE,	/* u8 */
	MLXDEVM_ATTR_FMSG_OBJ_VALUE_DATA,	/* dynamic */

	MLXDEVM_ATTR_HEALTH_REPORTER,			/* nested */
	MLXDEVM_ATTR_HEALTH_REPORTER_NAME,		/* string */
	MLXDEVM_ATTR_HEALTH_REPORTER_STATE,		/* u8 */
	MLXDEVM_ATTR_HEALTH_REPORTER_ERR_COUNT,		/* u64 */
	MLXDEVM_ATTR_HEALTH_REPORTER_RECOVER_COUNT,	/* u64 */
	MLXDEVM_ATTR_HEALTH_REPORTER_DUMP_TS,		/* u64 */
	MLXDEVM_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD,	/* u64 */
	MLXDEVM_ATTR_HEALTH_REPORTER_AUTO_RECOVER,	/* u8 */

	MLXDEVM_ATTR_FLASH_UPDATE_FILE_NAME,	/* string */
	MLXDEVM_ATTR_FLASH_UPDATE_COMPONENT,	/* string */
	MLXDEVM_ATTR_FLASH_UPDATE_STATUS_MSG,	/* string */
	MLXDEVM_ATTR_FLASH_UPDATE_STATUS_DONE,	/* u64 */
	MLXDEVM_ATTR_FLASH_UPDATE_STATUS_TOTAL,	/* u64 */

	MLXDEVM_ATTR_PORT_PCI_PF_NUMBER,	/* u16 */
	MLXDEVM_ATTR_PORT_PCI_VF_NUMBER,	/* u16 */

	MLXDEVM_ATTR_STATS,				/* nested */

	MLXDEVM_ATTR_TRAP_NAME,				/* string */
	/* enum devlink_trap_action */
	MLXDEVM_ATTR_TRAP_ACTION,			/* u8 */
	/* enum devlink_trap_type */
	MLXDEVM_ATTR_TRAP_TYPE,				/* u8 */
	MLXDEVM_ATTR_TRAP_GENERIC,			/* flag */
	MLXDEVM_ATTR_TRAP_METADATA,			/* nested */
	MLXDEVM_ATTR_TRAP_GROUP_NAME,			/* string */

	MLXDEVM_ATTR_RELOAD_FAILED,			/* u8 0 or 1 */

	MLXDEVM_ATTR_HEALTH_REPORTER_DUMP_TS_NS,	/* u64 */

	MLXDEVM_ATTR_NETNS_FD,			/* u32 */
	MLXDEVM_ATTR_NETNS_PID,			/* u32 */
	MLXDEVM_ATTR_NETNS_ID,			/* u32 */

	MLXDEVM_ATTR_HEALTH_REPORTER_AUTO_DUMP,	/* u8 */

	MLXDEVM_ATTR_TRAP_POLICER_ID,			/* u32 */
	MLXDEVM_ATTR_TRAP_POLICER_RATE,			/* u64 */
	MLXDEVM_ATTR_TRAP_POLICER_BURST,		/* u64 */

	MLXDEVM_ATTR_PORT_FUNCTION,			/* nested */

	MLXDEVM_ATTR_INFO_BOARD_SERIAL_NUMBER,	/* string */

	MLXDEVM_ATTR_PORT_LANES,			/* u32 */
	MLXDEVM_ATTR_PORT_SPLITTABLE,			/* u8 */

	MLXDEVM_ATTR_PORT_EXTERNAL,		/* u8 */
	MLXDEVM_ATTR_PORT_CONTROLLER_NUMBER,	/* u32 */

	MLXDEVM_ATTR_FLASH_UPDATE_STATUS_TIMEOUT,	/* u64 */
	MLXDEVM_ATTR_FLASH_UPDATE_OVERWRITE_MASK,	/* bitfield32 */

	MLXDEVM_ATTR_RELOAD_ACTION,		/* u8 */
	MLXDEVM_ATTR_RELOAD_ACTIONS_PERFORMED,	/* bitfield32 */
	MLXDEVM_ATTR_RELOAD_LIMITS,		/* bitfield32 */

	MLXDEVM_ATTR_DEV_STATS,			/* nested */
	MLXDEVM_ATTR_RELOAD_STATS,		/* nested */
	MLXDEVM_ATTR_RELOAD_STATS_ENTRY,	/* nested */
	MLXDEVM_ATTR_RELOAD_STATS_LIMIT,	/* u8 */
	MLXDEVM_ATTR_RELOAD_STATS_VALUE,	/* u32 */
	MLXDEVM_ATTR_REMOTE_RELOAD_STATS,	/* nested */
	MLXDEVM_ATTR_RELOAD_ACTION_INFO,        /* nested */
	MLXDEVM_ATTR_RELOAD_ACTION_STATS,       /* nested */

	MLXDEVM_ATTR_PORT_PCI_SF_NUMBER,	/* u32 */

	MLXDEVM_ATTR_RATE_TYPE,			/* u16 */
	MLXDEVM_ATTR_RATE_TX_SHARE,		/* u64 */
	MLXDEVM_ATTR_RATE_TX_MAX,		/* u64 */
	MLXDEVM_ATTR_RATE_NODE_NAME,		/* string */
	MLXDEVM_ATTR_RATE_PARENT_NODE_NAME,	/* string */

	MLXDEVM_ATTR_REGION_MAX_SNAPSHOTS,	/* u32 */

	MLXDEVM_ATTR_LINECARD_INDEX,		/* u32 */
	MLXDEVM_ATTR_LINECARD_STATE,		/* u8 */
	MLXDEVM_ATTR_LINECARD_TYPE,		/* string */
	MLXDEVM_ATTR_LINECARD_SUPPORTED_TYPES,	/* nested */

	MLXDEVM_ATTR_NESTED_MLXDEVM,		/* nested */

	MLXDEVM_ATTR_SELFTESTS,			/* nested */

	MLXDEVM_ATTR_RATE_TX_PRIORITY,		/* u32 */
	MLXDEVM_ATTR_RATE_TX_WEIGHT,		/* u32 */

	MLXDEVM_ATTR_REGION_DIRECT,		/* flag */

	/* Add new attributes above here, update the spec in
	 * Documentation/netlink/specs/devlink.yaml and re-generate
	 * net/devlink/netlink_gen.c.
	 */

	MLXDEVM_ATTR_EXT_PARAM_ARRAY_TYPE = 8192,	/* u8 */

	__MLXDEVM_ATTR_MAX,
	MLXDEVM_ATTR_MAX = __MLXDEVM_ATTR_MAX - 1
};

/* Mapping between internal resource described by the field and system
 * structure
 */
enum mlxdevm_dpipe_field_mapping_type {
	MLXDEVM_DPIPE_FIELD_MAPPING_TYPE_NONE,
	MLXDEVM_DPIPE_FIELD_MAPPING_TYPE_IFINDEX,
};
#if 0

/* Match type - specify the type of the match */
enum devlink_dpipe_match_type {
	DEVLINK_DPIPE_MATCH_TYPE_FIELD_EXACT,
};

/* Action type - specify the action type */
enum devlink_dpipe_action_type {
	DEVLINK_DPIPE_ACTION_TYPE_FIELD_MODIFY,
};

enum devlink_dpipe_field_ethernet_id {
	DEVLINK_DPIPE_FIELD_ETHERNET_DST_MAC,
};

enum devlink_dpipe_field_ipv4_id {
	DEVLINK_DPIPE_FIELD_IPV4_DST_IP,
};

enum devlink_dpipe_field_ipv6_id {
	DEVLINK_DPIPE_FIELD_IPV6_DST_IP,
};

enum devlink_dpipe_header_id {
	DEVLINK_DPIPE_HEADER_ETHERNET,
	DEVLINK_DPIPE_HEADER_IPV4,
	DEVLINK_DPIPE_HEADER_IPV6,
};

enum devlink_resource_unit {
	DEVLINK_RESOURCE_UNIT_ENTRY,
};
#endif

enum mlxdevm_port_fn_attr_cap {
	MLXDEVM_PORT_FN_ATTR_CAP_ROCE_BIT,
	MLXDEVM_PORT_FN_ATTR_CAP_MIGRATABLE_BIT,
	MLXDEVM_PORT_FN_ATTR_CAP_IPSEC_CRYPTO_BIT,
	MLXDEVM_PORT_FN_ATTR_CAP_IPSEC_PACKET_BIT,

	/* Add new caps above */
	__MLXDEVM_PORT_FN_ATTR_CAPS_MAX,
};

#define MLXDEVM_PORT_FN_CAP_ROCE _BITUL(MLXDEVM_PORT_FN_ATTR_CAP_ROCE_BIT)
#define MLXDEVM_PORT_FN_CAP_MIGRATABLE \
	_BITUL(MLXDEVM_PORT_FN_ATTR_CAP_MIGRATABLE_BIT)
#define MLXDEVM_PORT_FN_CAP_IPSEC_CRYPTO _BITUL(MLXDEVM_PORT_FN_ATTR_CAP_IPSEC_CRYPTO_BIT)
#define MLXDEVM_PORT_FN_CAP_IPSEC_PACKET _BITUL(MLXDEVM_PORT_FN_ATTR_CAP_IPSEC_PACKET_BIT)

enum mlxdevm_port_function_attr {
	MLXDEVM_PORT_FUNCTION_ATTR_UNSPEC,
	MLXDEVM_PORT_FUNCTION_ATTR_HW_ADDR,	/* binary */
	MLXDEVM_PORT_FN_ATTR_STATE,	/* u8 */
	MLXDEVM_PORT_FN_ATTR_OPSTATE,	/* u8 */
	MLXDEVM_PORT_FN_ATTR_CAPS,	/* bitfield32 */
	MLXDEVM_PORT_FN_ATTR_MLXDEVM,	/* nested */
	MLXDEVM_PORT_FN_ATTR_MAX_IO_EQS,	/* u32 */

	MLXDEVM_PORT_FN_ATTR_EXT_TRUST_STATE = 161, /* u8 */
	MLXDEVM_PORT_FN_ATTR_EXT_UC_LIST,	/* u32 */

	__MLXDEVM_PORT_FUNCTION_ATTR_MAX,
	MLXDEVM_PORT_FUNCTION_ATTR_MAX = __MLXDEVM_PORT_FUNCTION_ATTR_MAX - 1
};

enum mlxdevm_port_fn_state {
	MLXDEVM_PORT_FN_STATE_INACTIVE,
	MLXDEVM_PORT_FN_STATE_ACTIVE,
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
	MLXDEVM_PORT_FN_OPSTATE_DETACHED,
	MLXDEVM_PORT_FN_OPSTATE_ATTACHED,
};

#endif /* _COMPAT_UAPI_LINUX_MLXDEVM_H */
