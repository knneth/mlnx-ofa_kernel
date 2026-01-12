/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * include/net/devlink.h - Network physical device Netlink interface
 * Copyright (c) 2016 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2016 Jiri Pirko <jiri@mellanox.com>
 */
#ifndef _NET_MLXDEVM_H_
#define _NET_MLXDEVM_H_

#include "../../compat/config.h"

#include <linux/device.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/refcount.h>
#include <net/net_namespace.h>
#include <net/flow_offload.h>
#include <uapi/linux/mlxdevm.h>
#include <linux/xarray.h>
#include <linux/firmware.h>

#ifdef HAVE_BLOCKED_DEVLINK_CODE
struct devlink;
struct devlink_linecard;
#endif

struct mlxdevm_port_phys_attrs {
	u32 port_number; /* Same value as "split group".
			  * A physical port which is visible to the user
			  * for a given port flavour.
			  */
	u32 split_subport_number; /* If the port is split, this is the number of subport. */
};

/**
 * struct mlxdevm_port_pci_pf_attrs - mlxdevm port's PCI PF attributes
 * @controller: Associated controller number
 * @pf: associated PCI function number for the devlink port instance
 * @external: when set, indicates if a port is for an external controller
 */
struct mlxdevm_port_pci_pf_attrs {
	u32 controller;
	u16 pf;
	u8 external:1;
};

/**
 * struct mlxdevm_port_pci_vf_attrs - mlxdevm port's PCI VF attributes
 * @controller: Associated controller number
 * @pf: associated PCI function number for the mlxdevm port instance
 * @vf: associated PCI VF number of a PF for the mlxdevm port instance;
 *	VF number starts from 0 for the first PCI virtual function
 * @external: when set, indicates if a port is for an external controller
 */
struct mlxdevm_port_pci_vf_attrs {
	u32 controller;
	u16 pf;
	u16 vf;
	u8 external:1;
};

/**
 * struct mlxdevm_port_pci_sf_attrs - mlxdevm port's PCI SF attributes
 * @controller: Associated controller number
 * @sf: associated SF number of a PF for the mlxdevm port instance
 * @pf: associated PCI function number for the mlxdevm port instance
 * @external: when set, indicates if a port is for an external controller
 */
struct mlxdevm_port_pci_sf_attrs {
	u32 controller;
	u32 sf;
	u16 pf;
	u8 external:1;
};

/**
 * struct mlxdevm_port_attrs - mlxdevm port object
 * @flavour: flavour of the port
 * @split: indicates if this is split port
 * @splittable: indicates if the port can be split.
 * @lanes: maximum number of lanes the port supports. 0 value is not passed to netlink.
 * @switch_id: if the port is part of switch, this is buffer with ID, otherwise this is NULL
 * @phys: physical port attributes
 * @pci_pf: PCI PF port attributes
 * @pci_vf: PCI VF port attributes
 * @pci_sf: PCI SF port attributes
 */
struct mlxdevm_port_attrs {
	u8 split:1,
	   splittable:1;
	u32 lanes;
	enum mlxdevm_port_flavour flavour;
	struct netdev_phys_item_id switch_id;
	union {
		struct mlxdevm_port_phys_attrs phys;
		struct mlxdevm_port_pci_pf_attrs pci_pf;
		struct mlxdevm_port_pci_vf_attrs pci_vf;
		struct mlxdevm_port_pci_sf_attrs pci_sf;
	};
};

struct mlxdevm_rate {
	struct list_head list;
	enum mlxdevm_rate_type type;
	struct mlxdevm *mlxdevm;
	void *priv;
	u64 tx_share;
	u64 tx_max;

	struct mlxdevm_rate *parent;
	union {
		struct mlxdevm_port *mlxdevm_port;
		struct {
			char *name;
			refcount_t refcnt;
		};
	};

	u32 tx_priority;
	u32 tx_weight;

	u32 tc_bw[MLXDEVM_RATE_TCS_MAX];
};

struct mlxdevm_port {
	struct list_head list;
	struct list_head region_list;
	struct mlxdevm *mlxdevm;
	struct devlink_port *dl_port;
	const struct mlxdevm_port_ops *ops;
	unsigned int index;
	spinlock_t type_lock; /* Protects type and type_eth/ib
			       * structures consistency.
			       */
	enum mlxdevm_port_type type;
	enum mlxdevm_port_type desired_type;
	union {
		struct {
			struct net_device *netdev;
			int ifindex;
			char ifname[IFNAMSIZ];
		} type_eth;
		struct {
			struct ib_device *ibdev;
		} type_ib;
	};
	struct mlxdevm_port_attrs attrs;
	u8 attrs_set:1,
	   switch_port:1,
	   registered:1,
	   initialized:1;
	struct delayed_work type_warn_dw;
	struct list_head reporter_list;

	struct mlxdevm_rate *mlxdevm_rate;
	struct mlxdevm_linecard *linecard;
	u32 rel_index;
};

struct mlxdevm_port_new_attrs {
	enum mlxdevm_port_flavour flavour;
	unsigned int port_index;
	u32 controller;
	u32 sfnum;
	u16 pfnum;
	u8 port_index_valid:1,
	   controller_valid:1,
	   sfnum_valid:1;
};

struct mlxdevm_port_fn_ext_uc_list {
	u32 max_uc_list;
	u8 uc_list_cap_valid:1;
};

/**
 * struct mlxdevm_linecard_ops - Linecard operations
 * @provision: callback to provision the linecard slot with certain
 *	       type of linecard. As a result of this operation,
 *	       driver is expected to eventually (could be after
 *	       the function call returns) call one of:
 *	       mlxdevm_linecard_provision_set()
 *	       mlxdevm_linecard_provision_fail()
 * @unprovision: callback to unprovision the linecard slot. As a result
 *		 of this operation, driver is expected to eventually
 *		 (could be after the function call returns) call
 *	         mlxdevm_linecard_provision_clear()
 *	         mlxdevm_linecard_provision_fail()
 * @same_provision: callback to ask the driver if linecard is already
 *                  provisioned in the same way user asks this linecard to be
 *                  provisioned.
 * @types_count: callback to get number of supported types
 * @types_get: callback to get next type in list
 */
struct mlxdevm_linecard_ops {
	int (*provision)(struct mlxdevm_linecard *linecard, void *priv,
			 const char *type, const void *type_priv,
			 struct netlink_ext_ack *extack);
	int (*unprovision)(struct mlxdevm_linecard *linecard, void *priv,
			   struct netlink_ext_ack *extack);
	bool (*same_provision)(struct mlxdevm_linecard *linecard, void *priv,
			       const char *type, const void *type_priv);
	unsigned int (*types_count)(struct mlxdevm_linecard *linecard,
				    void *priv);
	void (*types_get)(struct mlxdevm_linecard *linecard,
			  void *priv, unsigned int index, const char **type,
			  const void **type_priv);
};

struct mlxdevm_sb_pool_info {
	enum mlxdevm_sb_pool_type pool_type;
	u32 size;
	enum mlxdevm_sb_threshold_type threshold_type;
	u32 cell_size;
};

/**
 * struct mlxdevm_dpipe_field - dpipe field object
 * @name: field name
 * @id: index inside the headers field array
 * @bitwidth: bitwidth
 * @mapping_type: mapping type
 */
struct mlxdevm_dpipe_field {
	const char *name;
	unsigned int id;
	unsigned int bitwidth;
	enum mlxdevm_dpipe_field_mapping_type mapping_type;
};

/**
 * struct mlxdevm_dpipe_header - dpipe header object
 * @name: header name
 * @id: index, global/local determined by global bit
 * @fields: fields
 * @fields_count: number of fields
 * @global: indicates if header is shared like most protocol header
 *	    or driver specific
 */
struct mlxdevm_dpipe_header {
	const char *name;
	unsigned int id;
	struct mlxdevm_dpipe_field *fields;
	unsigned int fields_count;
	bool global;
};
#ifdef HAVE_BLOCKED_DEVLINK_CODE
/**
 * struct devlink_dpipe_match - represents match operation
 * @type: type of match
 * @header_index: header index (packets can have several headers of same
 *		  type like in case of tunnels)
 * @header: header
 * @field_id: field index
 */
struct devlink_dpipe_match {
	enum devlink_dpipe_match_type type;
	unsigned int header_index;
	struct devlink_dpipe_header *header;
	unsigned int field_id;
};

/**
 * struct devlink_dpipe_action - represents action operation
 * @type: type of action
 * @header_index: header index (packets can have several headers of same
 *		  type like in case of tunnels)
 * @header: header
 * @field_id: field index
 */
struct devlink_dpipe_action {
	enum devlink_dpipe_action_type type;
	unsigned int header_index;
	struct devlink_dpipe_header *header;
	unsigned int field_id;
};

/**
 * struct devlink_dpipe_value - represents value of match/action
 * @action: action
 * @match: match
 * @mapping_value: in case the field has some mapping this value
 *                 specified the mapping value
 * @mapping_valid: specify if mapping value is valid
 * @value_size: value size
 * @value: value
 * @mask: bit mask
 */
struct devlink_dpipe_value {
	union {
		struct devlink_dpipe_action *action;
		struct devlink_dpipe_match *match;
	};
	unsigned int mapping_value;
	bool mapping_valid;
	unsigned int value_size;
	void *value;
	void *mask;
};

/**
 * struct devlink_dpipe_entry - table entry object
 * @index: index of the entry in the table
 * @match_values: match values
 * @match_values_count: count of matches tuples
 * @action_values: actions values
 * @action_values_count: count of actions values
 * @counter: value of counter
 * @counter_valid: Specify if value is valid from hardware
 */
struct devlink_dpipe_entry {
	u64 index;
	struct devlink_dpipe_value *match_values;
	unsigned int match_values_count;
	struct devlink_dpipe_value *action_values;
	unsigned int action_values_count;
	u64 counter;
	bool counter_valid;
};
#endif

/**
 * struct mlxdevm_dpipe_dump_ctx - context provided to driver in order
 *				   to dump
 * @info: info
 * @cmd: mlxdevm command
 * @skb: skb
 * @nest: top attribute
 * @hdr: hdr
 */
struct mlxdevm_dpipe_dump_ctx {
	struct genl_info *info;
	enum mlxdevm_command cmd;
	struct sk_buff *skb;
	struct nlattr *nest;
	void *hdr;
};

struct mlxdevm_dpipe_table_ops;

/**
 * struct mlxdevm_dpipe_table - table object
 * @priv: private
 * @name: table name
 * @counters_enabled: indicates if counters are active
 * @counter_control_extern: indicates if counter control is in dpipe or
 *			    external tool
 * @resource_valid: Indicate that the resource id is valid
 * @resource_id: relative resource this table is related to
 * @resource_units: number of resource's unit consumed per table's entry
 * @table_ops: table operations
 * @rcu: rcu
 */
struct mlxdevm_dpipe_table {
	void *priv;
	/* private: */
	struct list_head list;
	/* public: */
	const char *name;
	bool counters_enabled;
	bool counter_control_extern;
	bool resource_valid;
	u64 resource_id;
	u64 resource_units;
	const struct mlxdevm_dpipe_table_ops *table_ops;
	struct rcu_head rcu;
};

/**
 * struct mlxdevm_dpipe_table_ops - dpipe_table ops
 * @actions_dump: dumps all tables actions
 * @matches_dump: dumps all tables matches
 * @entries_dump: dumps all active entries in the table
 * @counters_set_update:  when changing the counter status hardware sync
 *			  maybe needed to allocate/free counter related
 *			  resources
 * @size_get: get size
 */
struct mlxdevm_dpipe_table_ops {
	int (*actions_dump)(void *priv, struct sk_buff *skb);
	int (*matches_dump)(void *priv, struct sk_buff *skb);
	int (*entries_dump)(void *priv, bool counters_enabled,
			    struct mlxdevm_dpipe_dump_ctx *dump_ctx);
	int (*counters_set_update)(void *priv, bool enable);
	u64 (*size_get)(void *priv);
};

/**
 * struct mlxdevm_dpipe_headers - dpipe headers
 * @headers: header array can be shared (global bit) or driver specific
 * @headers_count: count of headers
 */
struct mlxdevm_dpipe_headers {
	struct mlxdevm_dpipe_header **headers;
	unsigned int headers_count;
};

/**
 * struct mlxdevm_resource_size_params - resource's size parameters
 * @size_min: minimum size which can be set
 * @size_max: maximum size which can be set
 * @size_granularity: size granularity
 * @unit: resource's basic unit
 */
struct mlxdevm_resource_size_params {
	u64 size_min;
	u64 size_max;
	u64 size_granularity;
	enum mlxdevm_resource_unit unit;
};

static inline void
mlxdevm_resource_size_params_init(struct mlxdevm_resource_size_params *size_params,
				  u64 size_min, u64 size_max,
				  u64 size_granularity,
				  enum mlxdevm_resource_unit unit)
{
	size_params->size_min = size_min;
	size_params->size_max = size_max;
	size_params->size_granularity = size_granularity;
	size_params->unit = unit;
}

typedef u64 mlxdevm_resource_occ_get_t(void *priv);

#define MLXDEVM_RESOURCE_ID_PARENT_TOP 0
#ifdef HAVE_BLOCKED_DEVLINK_CODE

#define DEVLINK_RESOURCE_GENERIC_NAME_PORTS "physical_ports"

#endif
#define __MLXDEVM_PARAM_MAX_STRING_VALUE 32
#define __MLXDEVM_PARAM_ARRAY_MAX_DATA 64
enum mlxdevm_param_type {
	MLXDEVM_PARAM_TYPE_U8,
	MLXDEVM_PARAM_TYPE_U16,
	MLXDEVM_PARAM_TYPE_U32,
	MLXDEVM_PARAM_TYPE_STRING,
	MLXDEVM_PARAM_TYPE_BOOL,
	MLXDEVM_PARAM_TYPE_ARRAY_U16,
};

struct mlxdevm_param_array_entry {
	u8 type;
	size_t array_len;
	u16 data[__MLXDEVM_PARAM_ARRAY_MAX_DATA];
};

union mlxdevm_param_value {
	u8 vu8;
	u16 vu16;
	u32 vu32;
	char vstr[__MLXDEVM_PARAM_MAX_STRING_VALUE];
	bool vbool;
	struct mlxdevm_param_array_entry vu16arr;
};

struct mlxdevm_param_gset_ctx {
	union mlxdevm_param_value val;
	enum mlxdevm_param_cmode cmode;
};

/**
 * struct mlxdevm_flash_notify - mlxdevm dev flash notify data
 * @status_msg: current status string
 * @component: firmware component being updated
 * @done: amount of work completed of total amount
 * @total: amount of work expected to be done
 * @timeout: expected max timeout in seconds
 *
 * These are values to be given to userland to be displayed in order
 * to show current activity in a firmware update process.
 */
struct mlxdevm_flash_notify {
	const char *status_msg;
	const char *component;
	unsigned long done;
	unsigned long total;
	unsigned long timeout;
};

/**
 * struct mlxdevm_param - mlxdevm configuration parameter data
 * @id: mlxdevm parameter id number
 * @name: name of the parameter
 * @generic: indicates if the parameter is generic or driver specific
 * @type: parameter type
 * @supported_cmodes: bitmap of supported configuration modes
 * @get: get parameter value, used for runtime and permanent
 *       configuration modes
 * @set: set parameter value, used for runtime and permanent
 *       configuration modes
 * @validate: validate input value is applicable (within value range, etc.)
 *
 * This struct should be used by the driver to fill the data for
 * a parameter it registers.
 */
struct mlxdevm_param {
	u32 id;
	const char *name;
	bool generic;
	enum mlxdevm_param_type type;
	unsigned long supported_cmodes;
	int (*get)(struct mlxdevm *mlxdevm, u32 id,
		   struct mlxdevm_param_gset_ctx *ctx);
	int (*set)(struct mlxdevm *mlxdevm, u32 id,
		   struct mlxdevm_param_gset_ctx *ctx,
		   struct netlink_ext_ack *extack);
	int (*validate)(struct mlxdevm *mlxdevm, u32 id,
			union mlxdevm_param_value val,
			struct netlink_ext_ack *extack);
};

struct mlxdevm_param_item {
	struct list_head list;
	const struct mlxdevm_param *param;
	union mlxdevm_param_value driverinit_value;
	bool driverinit_value_valid;
	union mlxdevm_param_value driverinit_value_new; /* Not reachable
							 * until reload.
							 */
	bool driverinit_value_new_valid;
};

enum mlxdevm_param_generic_id {
	MLXDEVM_PARAM_GENERIC_ID_INT_ERR_RESET,
	MLXDEVM_PARAM_GENERIC_ID_MAX_MACS,
	MLXDEVM_PARAM_GENERIC_ID_ENABLE_SRIOV,
	MLXDEVM_PARAM_GENERIC_ID_REGION_SNAPSHOT,
	MLXDEVM_PARAM_GENERIC_ID_IGNORE_ARI,
	MLXDEVM_PARAM_GENERIC_ID_MSIX_VEC_PER_PF_MAX,
	MLXDEVM_PARAM_GENERIC_ID_MSIX_VEC_PER_PF_MIN,
	MLXDEVM_PARAM_GENERIC_ID_FW_LOAD_POLICY,
	MLXDEVM_PARAM_GENERIC_ID_RESET_DEV_ON_DRV_PROBE,
	MLXDEVM_PARAM_GENERIC_ID_ENABLE_ROCE,
	MLXDEVM_PARAM_GENERIC_ID_ENABLE_REMOTE_DEV_RESET,
	MLXDEVM_PARAM_GENERIC_ID_ENABLE_ETH,
	MLXDEVM_PARAM_GENERIC_ID_ENABLE_RDMA,
	MLXDEVM_PARAM_GENERIC_ID_ENABLE_VNET,
	MLXDEVM_PARAM_GENERIC_ID_ENABLE_IWARP,
	MLXDEVM_PARAM_GENERIC_ID_IO_EQ_SIZE,
	MLXDEVM_PARAM_GENERIC_ID_EVENT_EQ_SIZE,

	/* add new param generic ids above here*/
	__MLXDEVM_PARAM_GENERIC_ID_MAX,
	MLXDEVM_PARAM_GENERIC_ID_MAX = __MLXDEVM_PARAM_GENERIC_ID_MAX - 1,
};

#define MLXDEVM_PARAM_GENERIC_INT_ERR_RESET_NAME "internal_error_reset"
#define MLXDEVM_PARAM_GENERIC_INT_ERR_RESET_TYPE MLXDEVM_PARAM_TYPE_BOOL

#define MLXDEVM_PARAM_GENERIC_MAX_MACS_NAME "max_macs"
#define MLXDEVM_PARAM_GENERIC_MAX_MACS_TYPE MLXDEVM_PARAM_TYPE_U32

#define MLXDEVM_PARAM_GENERIC_ENABLE_SRIOV_NAME "enable_sriov"
#define MLXDEVM_PARAM_GENERIC_ENABLE_SRIOV_TYPE MLXDEVM_PARAM_TYPE_BOOL

#define MLXDEVM_PARAM_GENERIC_REGION_SNAPSHOT_NAME "region_snapshot_enable"
#define MLXDEVM_PARAM_GENERIC_REGION_SNAPSHOT_TYPE MLXDEVM_PARAM_TYPE_BOOL

#define MLXDEVM_PARAM_GENERIC_IGNORE_ARI_NAME "ignore_ari"
#define MLXDEVM_PARAM_GENERIC_IGNORE_ARI_TYPE MLXDEVM_PARAM_TYPE_BOOL

#define MLXDEVM_PARAM_GENERIC_MSIX_VEC_PER_PF_MAX_NAME "msix_vec_per_pf_max"
#define MLXDEVM_PARAM_GENERIC_MSIX_VEC_PER_PF_MAX_TYPE MLXDEVM_PARAM_TYPE_U32

#define MLXDEVM_PARAM_GENERIC_MSIX_VEC_PER_PF_MIN_NAME "msix_vec_per_pf_min"
#define MLXDEVM_PARAM_GENERIC_MSIX_VEC_PER_PF_MIN_TYPE MLXDEVM_PARAM_TYPE_U32

#define MLXDEVM_PARAM_GENERIC_FW_LOAD_POLICY_NAME "fw_load_policy"
#define MLXDEVM_PARAM_GENERIC_FW_LOAD_POLICY_TYPE MLXDEVM_PARAM_TYPE_U8

#define MLXDEVM_PARAM_GENERIC_RESET_DEV_ON_DRV_PROBE_NAME \
	"reset_dev_on_drv_probe"
#define MLXDEVM_PARAM_GENERIC_RESET_DEV_ON_DRV_PROBE_TYPE MLXDEVM_PARAM_TYPE_U8

#define MLXDEVM_PARAM_GENERIC_ENABLE_ROCE_NAME "enable_roce"
#define MLXDEVM_PARAM_GENERIC_ENABLE_ROCE_TYPE MLXDEVM_PARAM_TYPE_BOOL

#define MLXDEVM_PARAM_GENERIC_ENABLE_REMOTE_DEV_RESET_NAME "enable_remote_dev_reset"
#define MLXDEVM_PARAM_GENERIC_ENABLE_REMOTE_DEV_RESET_TYPE MLXDEVM_PARAM_TYPE_BOOL

#define MLXDEVM_PARAM_GENERIC_ENABLE_ETH_NAME "enable_eth"
#define MLXDEVM_PARAM_GENERIC_ENABLE_ETH_TYPE MLXDEVM_PARAM_TYPE_BOOL

#define MLXDEVM_PARAM_GENERIC_ENABLE_RDMA_NAME "enable_rdma"
#define MLXDEVM_PARAM_GENERIC_ENABLE_RDMA_TYPE MLXDEVM_PARAM_TYPE_BOOL

#define MLXDEVM_PARAM_GENERIC_ENABLE_VNET_NAME "enable_vnet"
#define MLXDEVM_PARAM_GENERIC_ENABLE_VNET_TYPE MLXDEVM_PARAM_TYPE_BOOL

#define MLXDEVM_PARAM_GENERIC_ENABLE_IWARP_NAME "enable_iwarp"
#define MLXDEVM_PARAM_GENERIC_ENABLE_IWARP_TYPE MLXDEVM_PARAM_TYPE_BOOL

#define MLXDEVM_PARAM_GENERIC_IO_EQ_SIZE_NAME "io_eq_size"
#define MLXDEVM_PARAM_GENERIC_IO_EQ_SIZE_TYPE MLXDEVM_PARAM_TYPE_U32

#define MLXDEVM_PARAM_GENERIC_EVENT_EQ_SIZE_NAME "event_eq_size"
#define MLXDEVM_PARAM_GENERIC_EVENT_EQ_SIZE_TYPE MLXDEVM_PARAM_TYPE_U32

#define MLXDEVM_PARAM_GENERIC(_id, _cmodes, _get, _set, _validate)	\
{									\
	.id = MLXDEVM_PARAM_GENERIC_ID_##_id,				\
	.name = MLXDEVM_PARAM_GENERIC_##_id##_NAME,			\
	.type = MLXDEVM_PARAM_GENERIC_##_id##_TYPE,			\
	.generic = true,						\
	.supported_cmodes = _cmodes,					\
	.get = _get,							\
	.set = _set,							\
	.validate = _validate,						\
}

#define MLXDEVM_PARAM_DRIVER(_id, _name, _type, _cmodes, _get, _set, _validate)	\
{									\
	.id = _id,							\
	.name = _name,							\
	.type = _type,							\
	.supported_cmodes = _cmodes,					\
	.get = _get,							\
	.set = _set,							\
	.validate = _validate,						\
}
#ifdef HAVE_BLOCKED_DEVLINK_CODE
/* Identifier of board design */
#define DEVLINK_INFO_VERSION_GENERIC_BOARD_ID	"board.id"
/* Revision of board design */
#define DEVLINK_INFO_VERSION_GENERIC_BOARD_REV	"board.rev"
/* Maker of the board */
#define DEVLINK_INFO_VERSION_GENERIC_BOARD_MANUFACTURE	"board.manufacture"
/* Part number of the board and its components */
#define DEVLINK_INFO_VERSION_GENERIC_BOARD_PART_NUMBER	"board.part_number"

/* Part number, identifier of asic design */
#define DEVLINK_INFO_VERSION_GENERIC_ASIC_ID	"asic.id"
/* Revision of asic design */
#define DEVLINK_INFO_VERSION_GENERIC_ASIC_REV	"asic.rev"

/* Overall FW version */
#define DEVLINK_INFO_VERSION_GENERIC_FW		"fw"
/* Control processor FW version */
#define DEVLINK_INFO_VERSION_GENERIC_FW_MGMT	"fw.mgmt"
/* FW interface specification version */
#define DEVLINK_INFO_VERSION_GENERIC_FW_MGMT_API	"fw.mgmt.api"
/* Data path microcode controlling high-speed packet processing */
#define DEVLINK_INFO_VERSION_GENERIC_FW_APP	"fw.app"
/* UNDI software version */
#define DEVLINK_INFO_VERSION_GENERIC_FW_UNDI	"fw.undi"
/* NCSI support/handler version */
#define DEVLINK_INFO_VERSION_GENERIC_FW_NCSI	"fw.ncsi"
/* FW parameter set id */
#define DEVLINK_INFO_VERSION_GENERIC_FW_PSID	"fw.psid"
/* RoCE FW version */
#define DEVLINK_INFO_VERSION_GENERIC_FW_ROCE	"fw.roce"
/* Firmware bundle identifier */
#define DEVLINK_INFO_VERSION_GENERIC_FW_BUNDLE_ID	"fw.bundle_id"
/* Bootloader */
#define DEVLINK_INFO_VERSION_GENERIC_FW_BOOTLOADER	"fw.bootloader"
#endif

/**
 * struct mlxdevm_flash_update_params - Flash Update parameters
 * @fw: pointer to the firmware data to update from
 * @component: the flash component to update
 * @overwrite_mask: which types of flash update are supported (may be %0)
 *
 * With the exception of fw, drivers must opt-in to parameters by
 * setting the appropriate bit in the supported_flash_update_params field in
 * their mlxdevm_ops structure.
 */
struct mlxdevm_flash_update_params {
	const struct firmware *fw;
	const char *component;
	u32 overwrite_mask;
};

#define MLXDEVM_SUPPORT_FLASH_UPDATE_OVERWRITE_MASK	BIT(0)
#ifdef HAVE_BLOCKED_DEVLINK_CODE

struct devlink_region;
#endif
struct mlxdevm_info_req;
#ifdef HAVE_BLOCKED_DEVLINK_CODE

/**
 * struct devlink_region_ops - Region operations
 * @name: region name
 * @destructor: callback used to free snapshot memory when deleting
 * @snapshot: callback to request an immediate snapshot. On success,
 *            the data variable must be updated to point to the snapshot data.
 *            The function will be called while the devlink instance lock is
 *            held.
 * @read: callback to directly read a portion of the region. On success,
 *        the data pointer will be updated with the contents of the
 *        requested portion of the region. The function will be called
 *        while the devlink instance lock is held.
 * @priv: Pointer to driver private data for the region operation
 */
struct devlink_region_ops {
	const char *name;
	void (*destructor)(const void *data);
	int (*snapshot)(struct devlink *devlink,
			const struct devlink_region_ops *ops,
			struct netlink_ext_ack *extack,
			u8 **data);
	int (*read)(struct devlink *devlink,
		    const struct devlink_region_ops *ops,
		    struct netlink_ext_ack *extack,
		    u64 offset, u32 size, u8 *data);
	void *priv;
};

/**
 * struct devlink_port_region_ops - Region operations for a port
 * @name: region name
 * @destructor: callback used to free snapshot memory when deleting
 * @snapshot: callback to request an immediate snapshot. On success,
 *            the data variable must be updated to point to the snapshot data.
 *            The function will be called while the devlink instance lock is
 *            held.
 * @read: callback to directly read a portion of the region. On success,
 *        the data pointer will be updated with the contents of the
 *        requested portion of the region. The function will be called
 *        while the devlink instance lock is held.
 * @priv: Pointer to driver private data for the region operation
 */
struct devlink_port_region_ops {
	const char *name;
	void (*destructor)(const void *data);
	int (*snapshot)(struct devlink_port *port,
			const struct devlink_port_region_ops *ops,
			struct netlink_ext_ack *extack,
			u8 **data);
	int (*read)(struct devlink_port *port,
		    const struct devlink_port_region_ops *ops,
		    struct netlink_ext_ack *extack,
		    u64 offset, u32 size, u8 *data);
	void *priv;
};

struct devlink_fmsg;
struct devlink_health_reporter;

enum devlink_health_reporter_state {
	DEVLINK_HEALTH_REPORTER_STATE_HEALTHY,
	DEVLINK_HEALTH_REPORTER_STATE_ERROR,
};

/**
 * struct devlink_health_reporter_ops - Reporter operations
 * @name: reporter name
 * @recover: callback to recover from reported error
 *           if priv_ctx is NULL, run a full recover
 * @dump: callback to dump an object
 *        if priv_ctx is NULL, run a full dump
 * @diagnose: callback to diagnose the current status
 * @test: callback to trigger a test event
 */

struct devlink_health_reporter_ops {
	char *name;
	int (*recover)(struct devlink_health_reporter *reporter,
		       void *priv_ctx, struct netlink_ext_ack *extack);
	int (*dump)(struct devlink_health_reporter *reporter,
		    struct devlink_fmsg *fmsg, void *priv_ctx,
		    struct netlink_ext_ack *extack);
	int (*diagnose)(struct devlink_health_reporter *reporter,
			struct devlink_fmsg *fmsg,
			struct netlink_ext_ack *extack);
	int (*test)(struct devlink_health_reporter *reporter,
		    struct netlink_ext_ack *extack);
};

/**
 * struct devlink_trap_metadata - Packet trap metadata.
 * @trap_name: Trap name.
 * @trap_group_name: Trap group name.
 * @input_dev: Input netdevice.
 * @dev_tracker: refcount tracker for @input_dev.
 * @fa_cookie: Flow action user cookie.
 * @trap_type: Trap type.
 */
struct devlink_trap_metadata {
	const char *trap_name;
	const char *trap_group_name;

	struct net_device *input_dev;
	netdevice_tracker dev_tracker;

	const struct flow_action_cookie *fa_cookie;
	enum devlink_trap_type trap_type;
};
#endif

/**
 * struct mlxdevm_trap_policer - Immutable packet trap policer attributes.
 * @id: Policer identifier.
 * @init_rate: Initial rate in packets / sec.
 * @init_burst: Initial burst size in packets.
 * @max_rate: Maximum rate.
 * @min_rate: Minimum rate.
 * @max_burst: Maximum burst size.
 * @min_burst: Minimum burst size.
 *
 * Describes immutable attributes of packet trap policers that drivers register
 * with mlxdevm.
 */
struct mlxdevm_trap_policer {
	u32 id;
	u64 init_rate;
	u64 init_burst;
	u64 max_rate;
	u64 min_rate;
	u64 max_burst;
	u64 min_burst;
};

/**
 * struct mlxdevm_trap_group - Immutable packet trap group attributes.
 * @name: Trap group name.
 * @id: Trap group identifier.
 * @generic: Whether the trap group is generic or not.
 * @init_policer_id: Initial policer identifier.
 *
 * Describes immutable attributes of packet trap groups that drivers register
 * with mlxdevm.
 */
struct mlxdevm_trap_group {
	const char *name;
	u16 id;
	bool generic;
	u32 init_policer_id;
};

#define MLXDEVM_TRAP_METADATA_TYPE_F_IN_PORT	BIT(0)
#define MLXDEVM_TRAP_METADATA_TYPE_F_FA_COOKIE	BIT(1)

/**
 * struct mlxdevm_trap - Immutable packet trap attributes.
 * @type: Trap type.
 * @init_action: Initial trap action.
 * @generic: Whether the trap is generic or not.
 * @id: Trap identifier.
 * @name: Trap name.
 * @init_group_id: Initial group identifier.
 * @metadata_cap: Metadata types that can be provided by the trap.
 *
 * Describes immutable attributes of packet traps that drivers register with
 * mlxdevm.
 */
struct mlxdevm_trap {
	enum mlxdevm_trap_type type;
	enum mlxdevm_trap_action init_action;
	bool generic;
	u16 id;
	const char *name;
	u16 init_group_id;
	u32 metadata_cap;
};

/* All traps must be documented in
 * Documentation/networking/mlxdevm/mlxdevm-trap.rst
 */
enum mlxdevm_trap_generic_id {
	MLXDEVM_TRAP_GENERIC_ID_SMAC_MC,
	MLXDEVM_TRAP_GENERIC_ID_VLAN_TAG_MISMATCH,
	MLXDEVM_TRAP_GENERIC_ID_INGRESS_VLAN_FILTER,
	MLXDEVM_TRAP_GENERIC_ID_INGRESS_STP_FILTER,
	MLXDEVM_TRAP_GENERIC_ID_EMPTY_TX_LIST,
	MLXDEVM_TRAP_GENERIC_ID_PORT_LOOPBACK_FILTER,
	MLXDEVM_TRAP_GENERIC_ID_BLACKHOLE_ROUTE,
	MLXDEVM_TRAP_GENERIC_ID_TTL_ERROR,
	MLXDEVM_TRAP_GENERIC_ID_TAIL_DROP,
	MLXDEVM_TRAP_GENERIC_ID_NON_IP_PACKET,
	MLXDEVM_TRAP_GENERIC_ID_UC_DIP_MC_DMAC,
	MLXDEVM_TRAP_GENERIC_ID_DIP_LB,
	MLXDEVM_TRAP_GENERIC_ID_SIP_MC,
	MLXDEVM_TRAP_GENERIC_ID_SIP_LB,
	MLXDEVM_TRAP_GENERIC_ID_CORRUPTED_IP_HDR,
	MLXDEVM_TRAP_GENERIC_ID_IPV4_SIP_BC,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_MC_DIP_RESERVED_SCOPE,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_MC_DIP_INTERFACE_LOCAL_SCOPE,
	MLXDEVM_TRAP_GENERIC_ID_MTU_ERROR,
	MLXDEVM_TRAP_GENERIC_ID_UNRESOLVED_NEIGH,
	MLXDEVM_TRAP_GENERIC_ID_RPF,
	MLXDEVM_TRAP_GENERIC_ID_REJECT_ROUTE,
	MLXDEVM_TRAP_GENERIC_ID_IPV4_LPM_UNICAST_MISS,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_LPM_UNICAST_MISS,
	MLXDEVM_TRAP_GENERIC_ID_NON_ROUTABLE,
	MLXDEVM_TRAP_GENERIC_ID_DECAP_ERROR,
	MLXDEVM_TRAP_GENERIC_ID_OVERLAY_SMAC_MC,
	MLXDEVM_TRAP_GENERIC_ID_INGRESS_FLOW_ACTION_DROP,
	MLXDEVM_TRAP_GENERIC_ID_EGRESS_FLOW_ACTION_DROP,
	MLXDEVM_TRAP_GENERIC_ID_STP,
	MLXDEVM_TRAP_GENERIC_ID_LACP,
	MLXDEVM_TRAP_GENERIC_ID_LLDP,
	MLXDEVM_TRAP_GENERIC_ID_IGMP_QUERY,
	MLXDEVM_TRAP_GENERIC_ID_IGMP_V1_REPORT,
	MLXDEVM_TRAP_GENERIC_ID_IGMP_V2_REPORT,
	MLXDEVM_TRAP_GENERIC_ID_IGMP_V3_REPORT,
	MLXDEVM_TRAP_GENERIC_ID_IGMP_V2_LEAVE,
	MLXDEVM_TRAP_GENERIC_ID_MLD_QUERY,
	MLXDEVM_TRAP_GENERIC_ID_MLD_V1_REPORT,
	MLXDEVM_TRAP_GENERIC_ID_MLD_V2_REPORT,
	MLXDEVM_TRAP_GENERIC_ID_MLD_V1_DONE,
	MLXDEVM_TRAP_GENERIC_ID_IPV4_DHCP,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_DHCP,
	MLXDEVM_TRAP_GENERIC_ID_ARP_REQUEST,
	MLXDEVM_TRAP_GENERIC_ID_ARP_RESPONSE,
	MLXDEVM_TRAP_GENERIC_ID_ARP_OVERLAY,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_NEIGH_SOLICIT,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_NEIGH_ADVERT,
	MLXDEVM_TRAP_GENERIC_ID_IPV4_BFD,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_BFD,
	MLXDEVM_TRAP_GENERIC_ID_IPV4_OSPF,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_OSPF,
	MLXDEVM_TRAP_GENERIC_ID_IPV4_BGP,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_BGP,
	MLXDEVM_TRAP_GENERIC_ID_IPV4_VRRP,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_VRRP,
	MLXDEVM_TRAP_GENERIC_ID_IPV4_PIM,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_PIM,
	MLXDEVM_TRAP_GENERIC_ID_UC_LB,
	MLXDEVM_TRAP_GENERIC_ID_LOCAL_ROUTE,
	MLXDEVM_TRAP_GENERIC_ID_EXTERNAL_ROUTE,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_UC_DIP_LINK_LOCAL_SCOPE,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_DIP_ALL_NODES,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_DIP_ALL_ROUTERS,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_ROUTER_SOLICIT,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_ROUTER_ADVERT,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_REDIRECT,
	MLXDEVM_TRAP_GENERIC_ID_IPV4_ROUTER_ALERT,
	MLXDEVM_TRAP_GENERIC_ID_IPV6_ROUTER_ALERT,
	MLXDEVM_TRAP_GENERIC_ID_PTP_EVENT,
	MLXDEVM_TRAP_GENERIC_ID_PTP_GENERAL,
	MLXDEVM_TRAP_GENERIC_ID_FLOW_ACTION_SAMPLE,
	MLXDEVM_TRAP_GENERIC_ID_FLOW_ACTION_TRAP,
	MLXDEVM_TRAP_GENERIC_ID_EARLY_DROP,
	MLXDEVM_TRAP_GENERIC_ID_VXLAN_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_LLC_SNAP_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_VLAN_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_PPPOE_PPP_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_MPLS_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_ARP_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_IP_1_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_IP_N_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_GRE_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_UDP_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_TCP_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_IPSEC_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_SCTP_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_DCCP_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_GTP_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_ESP_PARSING,
	MLXDEVM_TRAP_GENERIC_ID_BLACKHOLE_NEXTHOP,
	MLXDEVM_TRAP_GENERIC_ID_DMAC_FILTER,
	MLXDEVM_TRAP_GENERIC_ID_EAPOL,
	MLXDEVM_TRAP_GENERIC_ID_LOCKED_PORT,

	/* Add new generic trap IDs above */
	__MLXDEVM_TRAP_GENERIC_ID_MAX,
	MLXDEVM_TRAP_GENERIC_ID_MAX = __MLXDEVM_TRAP_GENERIC_ID_MAX - 1,
};

/* All trap groups must be documented in
 * Documentation/networking/mlxdevm/mlxdevm-trap.rst
 */
enum mlxdevm_trap_group_generic_id {
	MLXDEVM_TRAP_GROUP_GENERIC_ID_L2_DROPS,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_L3_DROPS,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_L3_EXCEPTIONS,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_BUFFER_DROPS,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_TUNNEL_DROPS,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_ACL_DROPS,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_STP,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_LACP,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_LLDP,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_MC_SNOOPING,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_DHCP,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_NEIGH_DISCOVERY,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_BFD,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_OSPF,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_BGP,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_VRRP,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_PIM,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_UC_LB,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_LOCAL_DELIVERY,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_EXTERNAL_DELIVERY,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_IPV6,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_PTP_EVENT,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_PTP_GENERAL,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_ACL_SAMPLE,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_ACL_TRAP,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_PARSER_ERROR_DROPS,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_EAPOL,

	/* Add new generic trap group IDs above */
	__MLXDEVM_TRAP_GROUP_GENERIC_ID_MAX,
	MLXDEVM_TRAP_GROUP_GENERIC_ID_MAX =
		__MLXDEVM_TRAP_GROUP_GENERIC_ID_MAX - 1,
};

#define MLXDEVM_TRAP_GENERIC_NAME_SMAC_MC \
	"source_mac_is_multicast"
#define MLXDEVM_TRAP_GENERIC_NAME_VLAN_TAG_MISMATCH \
	"vlan_tag_mismatch"
#define MLXDEVM_TRAP_GENERIC_NAME_INGRESS_VLAN_FILTER \
	"ingress_vlan_filter"
#define MLXDEVM_TRAP_GENERIC_NAME_INGRESS_STP_FILTER \
	"ingress_spanning_tree_filter"
#define MLXDEVM_TRAP_GENERIC_NAME_EMPTY_TX_LIST \
	"port_list_is_empty"
#define MLXDEVM_TRAP_GENERIC_NAME_PORT_LOOPBACK_FILTER \
	"port_loopback_filter"
#define MLXDEVM_TRAP_GENERIC_NAME_BLACKHOLE_ROUTE \
	"blackhole_route"
#define MLXDEVM_TRAP_GENERIC_NAME_TTL_ERROR \
	"ttl_value_is_too_small"
#define MLXDEVM_TRAP_GENERIC_NAME_TAIL_DROP \
	"tail_drop"
#define MLXDEVM_TRAP_GENERIC_NAME_NON_IP_PACKET \
	"non_ip"
#define MLXDEVM_TRAP_GENERIC_NAME_UC_DIP_MC_DMAC \
	"uc_dip_over_mc_dmac"
#define MLXDEVM_TRAP_GENERIC_NAME_DIP_LB \
	"dip_is_loopback_address"
#define MLXDEVM_TRAP_GENERIC_NAME_SIP_MC \
	"sip_is_mc"
#define MLXDEVM_TRAP_GENERIC_NAME_SIP_LB \
	"sip_is_loopback_address"
#define MLXDEVM_TRAP_GENERIC_NAME_CORRUPTED_IP_HDR \
	"ip_header_corrupted"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV4_SIP_BC \
	"ipv4_sip_is_limited_bc"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_MC_DIP_RESERVED_SCOPE \
	"ipv6_mc_dip_reserved_scope"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_MC_DIP_INTERFACE_LOCAL_SCOPE \
	"ipv6_mc_dip_interface_local_scope"
#define MLXDEVM_TRAP_GENERIC_NAME_MTU_ERROR \
	"mtu_value_is_too_small"
#define MLXDEVM_TRAP_GENERIC_NAME_UNRESOLVED_NEIGH \
	"unresolved_neigh"
#define MLXDEVM_TRAP_GENERIC_NAME_RPF \
	"mc_reverse_path_forwarding"
#define MLXDEVM_TRAP_GENERIC_NAME_REJECT_ROUTE \
	"reject_route"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV4_LPM_UNICAST_MISS \
	"ipv4_lpm_miss"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_LPM_UNICAST_MISS \
	"ipv6_lpm_miss"
#define MLXDEVM_TRAP_GENERIC_NAME_NON_ROUTABLE \
	"non_routable_packet"
#define MLXDEVM_TRAP_GENERIC_NAME_DECAP_ERROR \
	"decap_error"
#define MLXDEVM_TRAP_GENERIC_NAME_OVERLAY_SMAC_MC \
	"overlay_smac_is_mc"
#define MLXDEVM_TRAP_GENERIC_NAME_INGRESS_FLOW_ACTION_DROP \
	"ingress_flow_action_drop"
#define MLXDEVM_TRAP_GENERIC_NAME_EGRESS_FLOW_ACTION_DROP \
	"egress_flow_action_drop"
#define MLXDEVM_TRAP_GENERIC_NAME_STP \
	"stp"
#define MLXDEVM_TRAP_GENERIC_NAME_LACP \
	"lacp"
#define MLXDEVM_TRAP_GENERIC_NAME_LLDP \
	"lldp"
#define MLXDEVM_TRAP_GENERIC_NAME_IGMP_QUERY \
	"igmp_query"
#define MLXDEVM_TRAP_GENERIC_NAME_IGMP_V1_REPORT \
	"igmp_v1_report"
#define MLXDEVM_TRAP_GENERIC_NAME_IGMP_V2_REPORT \
	"igmp_v2_report"
#define MLXDEVM_TRAP_GENERIC_NAME_IGMP_V3_REPORT \
	"igmp_v3_report"
#define MLXDEVM_TRAP_GENERIC_NAME_IGMP_V2_LEAVE \
	"igmp_v2_leave"
#define MLXDEVM_TRAP_GENERIC_NAME_MLD_QUERY \
	"mld_query"
#define MLXDEVM_TRAP_GENERIC_NAME_MLD_V1_REPORT \
	"mld_v1_report"
#define MLXDEVM_TRAP_GENERIC_NAME_MLD_V2_REPORT \
	"mld_v2_report"
#define MLXDEVM_TRAP_GENERIC_NAME_MLD_V1_DONE \
	"mld_v1_done"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV4_DHCP \
	"ipv4_dhcp"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_DHCP \
	"ipv6_dhcp"
#define MLXDEVM_TRAP_GENERIC_NAME_ARP_REQUEST \
	"arp_request"
#define MLXDEVM_TRAP_GENERIC_NAME_ARP_RESPONSE \
	"arp_response"
#define MLXDEVM_TRAP_GENERIC_NAME_ARP_OVERLAY \
	"arp_overlay"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_NEIGH_SOLICIT \
	"ipv6_neigh_solicit"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_NEIGH_ADVERT \
	"ipv6_neigh_advert"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV4_BFD \
	"ipv4_bfd"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_BFD \
	"ipv6_bfd"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV4_OSPF \
	"ipv4_ospf"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_OSPF \
	"ipv6_ospf"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV4_BGP \
	"ipv4_bgp"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_BGP \
	"ipv6_bgp"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV4_VRRP \
	"ipv4_vrrp"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_VRRP \
	"ipv6_vrrp"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV4_PIM \
	"ipv4_pim"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_PIM \
	"ipv6_pim"
#define MLXDEVM_TRAP_GENERIC_NAME_UC_LB \
	"uc_loopback"
#define MLXDEVM_TRAP_GENERIC_NAME_LOCAL_ROUTE \
	"local_route"
#define MLXDEVM_TRAP_GENERIC_NAME_EXTERNAL_ROUTE \
	"external_route"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_UC_DIP_LINK_LOCAL_SCOPE \
	"ipv6_uc_dip_link_local_scope"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_DIP_ALL_NODES \
	"ipv6_dip_all_nodes"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_DIP_ALL_ROUTERS \
	"ipv6_dip_all_routers"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_ROUTER_SOLICIT \
	"ipv6_router_solicit"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_ROUTER_ADVERT \
	"ipv6_router_advert"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_REDIRECT \
	"ipv6_redirect"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV4_ROUTER_ALERT \
	"ipv4_router_alert"
#define MLXDEVM_TRAP_GENERIC_NAME_IPV6_ROUTER_ALERT \
	"ipv6_router_alert"
#define MLXDEVM_TRAP_GENERIC_NAME_PTP_EVENT \
	"ptp_event"
#define MLXDEVM_TRAP_GENERIC_NAME_PTP_GENERAL \
	"ptp_general"
#define MLXDEVM_TRAP_GENERIC_NAME_FLOW_ACTION_SAMPLE \
	"flow_action_sample"
#define MLXDEVM_TRAP_GENERIC_NAME_FLOW_ACTION_TRAP \
	"flow_action_trap"
#define MLXDEVM_TRAP_GENERIC_NAME_EARLY_DROP \
	"early_drop"
#define MLXDEVM_TRAP_GENERIC_NAME_VXLAN_PARSING \
	"vxlan_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_LLC_SNAP_PARSING \
	"llc_snap_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_VLAN_PARSING \
	"vlan_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_PPPOE_PPP_PARSING \
	"pppoe_ppp_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_MPLS_PARSING \
	"mpls_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_ARP_PARSING \
	"arp_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_IP_1_PARSING \
	"ip_1_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_IP_N_PARSING \
	"ip_n_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_GRE_PARSING \
	"gre_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_UDP_PARSING \
	"udp_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_TCP_PARSING \
	"tcp_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_IPSEC_PARSING \
	"ipsec_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_SCTP_PARSING \
	"sctp_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_DCCP_PARSING \
	"dccp_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_GTP_PARSING \
	"gtp_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_ESP_PARSING \
	"esp_parsing"
#define MLXDEVM_TRAP_GENERIC_NAME_BLACKHOLE_NEXTHOP \
	"blackhole_nexthop"
#define MLXDEVM_TRAP_GENERIC_NAME_DMAC_FILTER \
	"dmac_filter"
#define MLXDEVM_TRAP_GENERIC_NAME_EAPOL \
	"eapol"
#define MLXDEVM_TRAP_GENERIC_NAME_LOCKED_PORT \
	"locked_port"

#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_L2_DROPS \
	"l2_drops"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_L3_DROPS \
	"l3_drops"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_L3_EXCEPTIONS \
	"l3_exceptions"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_BUFFER_DROPS \
	"buffer_drops"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_TUNNEL_DROPS \
	"tunnel_drops"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_ACL_DROPS \
	"acl_drops"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_STP \
	"stp"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_LACP \
	"lacp"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_LLDP \
	"lldp"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_MC_SNOOPING  \
	"mc_snooping"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_DHCP \
	"dhcp"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_NEIGH_DISCOVERY \
	"neigh_discovery"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_BFD \
	"bfd"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_OSPF \
	"ospf"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_BGP \
	"bgp"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_VRRP \
	"vrrp"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_PIM \
	"pim"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_UC_LB \
	"uc_loopback"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_LOCAL_DELIVERY \
	"local_delivery"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_EXTERNAL_DELIVERY \
	"external_delivery"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_IPV6 \
	"ipv6"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_PTP_EVENT \
	"ptp_event"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_PTP_GENERAL \
	"ptp_general"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_ACL_SAMPLE \
	"acl_sample"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_ACL_TRAP \
	"acl_trap"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_PARSER_ERROR_DROPS \
	"parser_error_drops"
#define MLXDEVM_TRAP_GROUP_GENERIC_NAME_EAPOL \
	"eapol"
#ifdef HAVE_BLOCKED_DEVLINK_CODE

#define DEVLINK_TRAP_GENERIC(_type, _init_action, _id, _group_id,	      \
			     _metadata_cap)				      \
	{								      \
		.type = DEVLINK_TRAP_TYPE_##_type,			      \
		.init_action = DEVLINK_TRAP_ACTION_##_init_action,	      \
		.generic = true,					      \
		.id = DEVLINK_TRAP_GENERIC_ID_##_id,			      \
		.name = DEVLINK_TRAP_GENERIC_NAME_##_id,		      \
		.init_group_id = _group_id,				      \
		.metadata_cap = _metadata_cap,				      \
	}
#endif

#define MLXDEVM_TRAP_DRIVER(_type, _init_action, _id, _name, _group_id,	      \
			    _metadata_cap)				      \
	{								      \
		.type = MLXDEVM_TRAP_TYPE_##_type,			      \
		.init_action = MLXDEVM_TRAP_ACTION_##_init_action,	      \
		.generic = false,					      \
		.id = _id,						      \
		.name = _name,						      \
		.init_group_id = _group_id,				      \
		.metadata_cap = _metadata_cap,				      \
	}

#define MLXDEVM_TRAP_GROUP_GENERIC(_id, _policer_id)			      \
	{								      \
		.name = MLXDEVM_TRAP_GROUP_GENERIC_NAME_##_id,		      \
		.id = MLXDEVM_TRAP_GROUP_GENERIC_ID_##_id,		      \
		.generic = true,					      \
		.init_policer_id = _policer_id,				      \
	}
#ifdef HAVE_BLOCKED_DEVLINK_CODE

#define DEVLINK_TRAP_POLICER(_id, _rate, _burst, _max_rate, _min_rate,	      \
			     _max_burst, _min_burst)			      \
	{								      \
		.id = _id,						      \
		.init_rate = _rate,					      \
		.init_burst = _burst,					      \
		.max_rate = _max_rate,					      \
		.min_rate = _min_rate,					      \
		.max_burst = _max_burst,				      \
		.min_burst = _min_burst,				      \
	}

#define devlink_fmsg_put(fmsg, name, value) (			\
	_Generic((value),					\
		bool :		devlink_fmsg_bool_pair_put,	\
		u8 :		devlink_fmsg_u8_pair_put,	\
		u16 :		devlink_fmsg_u32_pair_put,	\
		u32 :		devlink_fmsg_u32_pair_put,	\
		u64 :		devlink_fmsg_u64_pair_put,	\
		int :		devlink_fmsg_u32_pair_put,	\
		char * :	devlink_fmsg_string_pair_put,	\
		const char * :	devlink_fmsg_string_pair_put)	\
	(fmsg, name, (value)))

enum {
	/* device supports reload operations */
	DEVLINK_F_RELOAD = 1UL << 0,
};
#endif

struct mlxdevm_ops {
	/**
	 * @supported_flash_update_params:
	 * mask of parameters supported by the driver's .flash_update
	 * implementation.
	 */
	u32 supported_flash_update_params;
	unsigned long reload_actions;
	unsigned long reload_limits;
	int (*reload_down)(struct mlxdevm *mlxdevm, bool netns_change,
			   enum mlxdevm_reload_action action,
			   enum mlxdevm_reload_limit limit,
			   struct netlink_ext_ack *extack);
	int (*reload_up)(struct mlxdevm *mlxdevm, enum mlxdevm_reload_action action,
			 enum mlxdevm_reload_limit limit, u32 *actions_performed,
			 struct netlink_ext_ack *extack);
	int (*sb_pool_get)(struct mlxdevm *mlxdevm, unsigned int sb_index,
			   u16 pool_index,
			   struct mlxdevm_sb_pool_info *pool_info);
	int (*sb_pool_set)(struct mlxdevm *mlxdevm, unsigned int sb_index,
			   u16 pool_index, u32 size,
			   enum mlxdevm_sb_threshold_type threshold_type,
			   struct netlink_ext_ack *extack);
	int (*sb_port_pool_get)(struct mlxdevm_port *mlxdevm_port,
				unsigned int sb_index, u16 pool_index,
				u32 *p_threshold);
	int (*sb_port_pool_set)(struct mlxdevm_port *mlxdevm_port,
				unsigned int sb_index, u16 pool_index,
				u32 threshold, struct netlink_ext_ack *extack);
	int (*sb_tc_pool_bind_get)(struct mlxdevm_port *mlxdevm_port,
				   unsigned int sb_index,
				   u16 tc_index,
				   enum mlxdevm_sb_pool_type pool_type,
				   u16 *p_pool_index, u32 *p_threshold);
	int (*sb_tc_pool_bind_set)(struct mlxdevm_port *mlxdevm_port,
				   unsigned int sb_index,
				   u16 tc_index,
				   enum mlxdevm_sb_pool_type pool_type,
				   u16 pool_index, u32 threshold,
				   struct netlink_ext_ack *extack);
	int (*sb_occ_snapshot)(struct mlxdevm *mlxdevm,
			       unsigned int sb_index);
	int (*sb_occ_max_clear)(struct mlxdevm *mlxdevm,
				unsigned int sb_index);
	int (*sb_occ_port_pool_get)(struct mlxdevm_port *mlxdevm_port,
				    unsigned int sb_index, u16 pool_index,
				    u32 *p_cur, u32 *p_max);
	int (*sb_occ_tc_port_bind_get)(struct mlxdevm_port *mlxdevm_port,
				       unsigned int sb_index,
				       u16 tc_index,
				       enum mlxdevm_sb_pool_type pool_type,
				       u32 *p_cur, u32 *p_max);

	int (*eswitch_mode_get)(struct mlxdevm *mlxdevm, u16 *p_mode);
	int (*eswitch_mode_set)(struct mlxdevm *mlxdevm, u16 mode,
				struct netlink_ext_ack *extack);
	int (*eswitch_inline_mode_get)(struct mlxdevm *mlxdevm, u8 *p_inline_mode);
	int (*eswitch_inline_mode_set)(struct mlxdevm *mlxdevm, u8 inline_mode,
				       struct netlink_ext_ack *extack);
	int (*eswitch_encap_mode_get)(struct mlxdevm *mlxdevm,
				      enum mlxdevm_eswitch_encap_mode *p_encap_mode);
	int (*eswitch_encap_mode_set)(struct mlxdevm *mlxdevm,
				      enum mlxdevm_eswitch_encap_mode encap_mode,
				      struct netlink_ext_ack *extack);
	int (*info_get)(struct mlxdevm *mlxdevm, struct mlxdevm_info_req *req,
			struct netlink_ext_ack *extack);
	/**
	 * @flash_update: Device flash update function
	 *
	 * Used to perform a flash update for the device. The set of
	 * parameters supported by the driver should be set in
	 * supported_flash_update_params.
	 */
	int (*flash_update)(struct mlxdevm *mlxdevm,
			    struct mlxdevm_flash_update_params *params,
			    struct netlink_ext_ack *extack);
	/**
	 * @trap_init: Trap initialization function.
	 *
	 * Should be used by device drivers to initialize the trap in the
	 * underlying device. Drivers should also store the provided trap
	 * context, so that they could efficiently pass it to
	 * mlxdevm_trap_report() when the trap is triggered.
	 */
	int (*trap_init)(struct mlxdevm *mlxdevm,
			 const struct mlxdevm_trap *trap, void *trap_ctx);
	/**
	 * @trap_fini: Trap de-initialization function.
	 *
	 * Should be used by device drivers to de-initialize the trap in the
	 * underlying device.
	 */
	void (*trap_fini)(struct mlxdevm *mlxdevm,
			  const struct mlxdevm_trap *trap, void *trap_ctx);
	/**
	 * @trap_action_set: Trap action set function.
	 */
	int (*trap_action_set)(struct mlxdevm *mlxdevm,
			       const struct mlxdevm_trap *trap,
			       enum mlxdevm_trap_action action,
			       struct netlink_ext_ack *extack);
	/**
	 * @trap_group_init: Trap group initialization function.
	 *
	 * Should be used by device drivers to initialize the trap group in the
	 * underlying device.
	 */
	int (*trap_group_init)(struct mlxdevm *mlxdevm,
			       const struct mlxdevm_trap_group *group);
	/**
	 * @trap_group_set: Trap group parameters set function.
	 *
	 * Note: @policer can be NULL when a policer is being unbound from
	 * @group.
	 */
	int (*trap_group_set)(struct mlxdevm *mlxdevm,
			      const struct mlxdevm_trap_group *group,
			      const struct mlxdevm_trap_policer *policer,
			      struct netlink_ext_ack *extack);
	/**
	 * @trap_group_action_set: Trap group action set function.
	 *
	 * If this callback is populated, it will take precedence over looping
	 * over all traps in a group and calling .trap_action_set().
	 */
	int (*trap_group_action_set)(struct mlxdevm *mlxdevm,
				     const struct mlxdevm_trap_group *group,
				     enum mlxdevm_trap_action action,
				     struct netlink_ext_ack *extack);
	/**
	 * @trap_drop_counter_get: Trap drop counter get function.
	 *
	 * Should be used by device drivers to report number of packets
	 * that have been dropped, and cannot be passed to the mlxdevm
	 * subsystem by the underlying device.
	 */
	int (*trap_drop_counter_get)(struct mlxdevm *mlxdevm,
				     const struct mlxdevm_trap *trap,
				     u64 *p_drops);
	/**
	 * @trap_policer_init: Trap policer initialization function.
	 *
	 * Should be used by device drivers to initialize the trap policer in
	 * the underlying device.
	 */
	int (*trap_policer_init)(struct mlxdevm *mlxdevm,
				 const struct mlxdevm_trap_policer *policer);
	/**
	 * @trap_policer_fini: Trap policer de-initialization function.
	 *
	 * Should be used by device drivers to de-initialize the trap policer
	 * in the underlying device.
	 */
	void (*trap_policer_fini)(struct mlxdevm *mlxdevm,
				  const struct mlxdevm_trap_policer *policer);
	/**
	 * @trap_policer_set: Trap policer parameters set function.
	 */
	int (*trap_policer_set)(struct mlxdevm *mlxdevm,
				const struct mlxdevm_trap_policer *policer,
				u64 rate, u64 burst,
				struct netlink_ext_ack *extack);
	/**
	 * @trap_policer_counter_get: Trap policer counter get function.
	 *
	 * Should be used by device drivers to report number of packets dropped
	 * by the policer.
	 */
	int (*trap_policer_counter_get)(struct mlxdevm *mlxdevm,
					const struct mlxdevm_trap_policer *policer,
					u64 *p_drops);
	/**
	 * port_new() - Add a new port function of a specified flavor
	 * @mlxdevm: Devlink instance
	 * @attrs: attributes of the new port
	 * @extack: extack for reporting error messages
	 * @mlxdevm_port: pointer to store new mlxdevm port pointer
	 *
	 * Devlink core will call this device driver function upon user request
	 * to create a new port function of a specified flavor and optional
	 * attributes
	 *
	 * Notes:
	 *	- On success, drivers must register a port with mlxdevm core
	 *
	 * Return: 0 on success, negative value otherwise.
	 */
	int (*port_new)(struct mlxdevm *mlxdevm,
			const struct mlxdevm_port_new_attrs *attrs,
			struct netlink_ext_ack *extack,
			unsigned int *new_port_index);

	/**
	 * Rate control callbacks.
	 */
	int (*rate_leaf_tx_share_set)(struct mlxdevm_rate *mlxdevm_rate, void *priv,
				      u64 tx_share, struct netlink_ext_ack *extack);
	int (*rate_leaf_tx_max_set)(struct mlxdevm_rate *mlxdevm_rate, void *priv,
				    u64 tx_max, struct netlink_ext_ack *extack);
	int (*rate_leaf_tx_priority_set)(struct mlxdevm_rate *mlxdevm_rate, void *priv,
					 u32 tx_priority, struct netlink_ext_ack *extack);
	int (*rate_leaf_tx_weight_set)(struct mlxdevm_rate *mlxdevm_rate, void *priv,
				       u32 tx_weight, struct netlink_ext_ack *extack);
	int (*rate_leaf_tc_bw_set)(struct mlxdevm_rate *mlxdevm_rate,
				   void *priv, u32 *tc_bw,
				   struct netlink_ext_ack *extack);
	int (*rate_node_tx_share_set)(struct mlxdevm_rate *mlxdevm_rate, void *priv,
				      u64 tx_share, struct netlink_ext_ack *extack);
	int (*rate_node_tx_max_set)(struct mlxdevm_rate *mlxdevm_rate, void *priv,
				    u64 tx_max, struct netlink_ext_ack *extack);
	int (*rate_node_tx_priority_set)(struct mlxdevm_rate *mlxdevm_rate, void *priv,
					 u32 tx_priority, struct netlink_ext_ack *extack);
	int (*rate_node_tx_weight_set)(struct mlxdevm_rate *mlxdevm_rate, void *priv,
				       u32 tx_weight, struct netlink_ext_ack *extack);
	int (*rate_node_tc_bw_set)(struct mlxdevm_rate *mlxdevm_rate,
				   void *priv, u32 *tc_bw,
				   struct netlink_ext_ack *extack);
	int (*rate_node_new)(struct mlxdevm_rate *rate_node, void **priv,
			     struct netlink_ext_ack *extack);
	int (*rate_node_del)(struct mlxdevm_rate *rate_node, void *priv,
			     struct netlink_ext_ack *extack);
	int (*rate_leaf_parent_set)(struct mlxdevm_rate *child,
				    struct mlxdevm_rate *parent,
				    void *priv_child, void *priv_parent,
				    struct netlink_ext_ack *extack);
	int (*rate_node_parent_set)(struct mlxdevm_rate *child,
				    struct mlxdevm_rate *parent,
				    void *priv_child, void *priv_parent,
				    struct netlink_ext_ack *extack);
	/**
	 * selftests_check() - queries if selftest is supported
	 * @mlxdevm: mlxdevm instance
	 * @id: test index
	 * @extack: extack for reporting error messages
	 *
	 * Return: true if test is supported by the driver
	 */
	bool (*selftest_check)(struct mlxdevm *mlxdevm, unsigned int id,
			       struct netlink_ext_ack *extack);
	/**
	 * selftest_run() - Runs a selftest
	 * @mlxdevm: mlxdevm instance
	 * @id: test index
	 * @extack: extack for reporting error messages
	 *
	 * Return: status of the test
	 */
	enum mlxdevm_selftest_status
	(*selftest_run)(struct mlxdevm *mlxdevm, unsigned int id,
			struct netlink_ext_ack *extack);
};
#ifdef HAVE_BLOCKED_DEVLINK_CODE

void *devlink_priv(struct devlink *devlink);
struct devlink *priv_to_devlink(void *priv);
#endif
struct device *mlxdevm_to_dev(const struct mlxdevm *mlxdevm);

/* Devlink instance explicit locking */
void devm_lock(struct mlxdevm *mlxdevm);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
int devl_trylock(struct devlink *devlink);
#endif
void devm_unlock(struct mlxdevm *mlxdevm);
void devm_assert_locked(struct mlxdevm *mlxdevm);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
bool devl_lock_is_held(struct devlink *devlink);
DEFINE_GUARD(devl, struct devlink *, devl_lock(_T), devl_unlock(_T));

struct ib_device;
#endif

struct net *mlxdevm_net(const struct mlxdevm *mlxdevm);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
/* This call is intended for software devices that can create
 * devlink instances in other namespaces than init_net.
 *
 * Drivers that operate on real HW must use devlink_alloc() instead.
 */
struct devlink *devlink_alloc_ns(const struct devlink_ops *ops,
				 size_t priv_size, struct net *net,
				 struct device *dev);
static inline struct devlink *devlink_alloc(const struct devlink_ops *ops,
					    size_t priv_size,
					    struct device *dev)
{
	return devlink_alloc_ns(ops, priv_size, &init_net, dev);
}
#endif

int devm_register(struct mlxdevm *mlxdevm);
void devm_unregister(struct mlxdevm *mlxdevm);
int mlxdevm_register(struct mlxdevm *mldevm);
void mlxdevm_unregister(struct mlxdevm *mlxdevm);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
void devlink_free(struct devlink *devlink);
#endif

/**
 * struct mlxdevm_port_ops - Port operations
 * @port_split: Callback used to split the port into multiple ones.
 * @port_unsplit: Callback used to unsplit the port group back into
 *		  a single port.
 * @port_type_set: Callback used to set a type of a port.
 * @port_del: Callback used to delete selected port along with related function.
 *	      Devlink core calls this upon user request to delete
 *	      a port previously created by devlink_ops->port_new().
 * @port_fn_hw_addr_get: Callback used to set port function's hardware address.
 *			 Should be used by device drivers to report
 *			 the hardware address of a function managed
 *			 by the devlink port.
 * @port_fn_hw_addr_set: Callback used to set port function's hardware address.
 *			 Should be used by device drivers to set the hardware
 *			 address of a function managed by the devlink port.
 * @port_fn_roce_get: Callback used to get port function's RoCE capability.
 *		      Should be used by device drivers to report
 *		      the current state of RoCE capability of a function
 *		      managed by the devlink port.
 * @port_fn_roce_set: Callback used to set port function's RoCE capability.
 *		      Should be used by device drivers to enable/disable
 *		      RoCE capability of a function managed
 *		      by the devlink port.
 * @port_fn_migratable_get: Callback used to get port function's migratable
 *			    capability. Should be used by device drivers
 *			    to report the current state of migratable capability
 *			    of a function managed by the devlink port.
 * @port_fn_migratable_set: Callback used to set port function's migratable
 *			    capability. Should be used by device drivers
 *			    to enable/disable migratable capability of
 *			    a function managed by the devlink port.
 * @port_fn_state_get: Callback used to get port function's state.
 *		       Should be used by device drivers to report
 *		       the current admin and operational state of a
 *		       function managed by the devlink port.
 * @port_fn_state_set: Callback used to get port function's state.
 *		       Should be used by device drivers set
 *		       the admin state of a function managed
 *		       by the devlink port.
 * @port_fn_ipsec_crypto_get: Callback used to get port function's ipsec_crypto
 *			      capability. Should be used by device drivers
 *			      to report the current state of ipsec_crypto
 *			      capability of a function managed by the devlink
 *			      port.
 * @port_fn_ipsec_crypto_set: Callback used to set port function's ipsec_crypto
 *			      capability. Should be used by device drivers to
 *			      enable/disable ipsec_crypto capability of a
 *			      function managed by the devlink port.
 * @port_fn_ipsec_packet_get: Callback used to get port function's ipsec_packet
 *			      capability. Should be used by device drivers
 *			      to report the current state of ipsec_packet
 *			      capability of a function managed by the devlink
 *			      port.
 * @port_fn_ipsec_packet_set: Callback used to set port function's ipsec_packet
 *			      capability. Should be used by device drivers to
 *			      enable/disable ipsec_packet capability of a
 *			      function managed by the devlink port.
 * @port_fn_max_io_eqs_get: Callback used to get port function's maximum number
 *			    of event queues. Should be used by device drivers to
 *			    report the maximum event queues of a function
 *			    managed by the devlink port.
 * @port_fn_max_io_eqs_set: Callback used to set port function's maximum number
 *			    of event queues. Should be used by device drivers to
 *			    configure maximum number of event queues
 *			    of a function managed by the devlink port.
 *@port_fn_trust_get: Callback used to get port funciton's trust state.
 *		      Should be used by device driver to report the trust mode
 *		      of a function managed by the mlxdevm port.
 *@port_fn_trust_set: Callback used to set port function's trust state.
 *		      Should be used by device drivers to enable/disable
 *		      trust mode of a function managed by the mlxdevm port.
 * @port_fn_ext_uc_list_set: Callback used to set port function's maximum number
 * 			     of uc lists.
 * Note: Driver should return -EOPNOTSUPP if it doesn't support
 * port function (@port_fn_*) handling for a particular port.
 */
struct mlxdevm_port_ops {
	int (*port_split)(struct mlxdevm *mlxdevm, struct mlxdevm_port *port,
			  unsigned int count, struct netlink_ext_ack *extack);
	int (*port_unsplit)(struct mlxdevm *mlxdevm, struct mlxdevm_port *port,
			    struct netlink_ext_ack *extack);
	int (*port_type_set)(struct mlxdevm_port *mlxdevm_port,
			     enum mlxdevm_port_type port_type);
	int (*port_del)(struct mlxdevm *mlxdevm, unsigned int new_port_index,
			struct netlink_ext_ack *extack);
	int (*port_fn_hw_addr_get)(struct mlxdevm_port *port, u8 *hw_addr,
				   int *hw_addr_len,
				   struct netlink_ext_ack *extack);
	int (*port_fn_hw_addr_set)(struct mlxdevm_port *port,
				   const u8 *hw_addr, int hw_addr_len,
				   struct netlink_ext_ack *extack);
	int (*port_fn_roce_get)(struct mlxdevm_port *mlxdevm_port,
				bool *is_enable,
				struct netlink_ext_ack *extack);
	int (*port_fn_roce_set)(struct mlxdevm_port *mlxdevm_port,
				bool enable, struct netlink_ext_ack *extack);
	int (*port_fn_migratable_get)(struct mlxdevm_port *mlxdevm_port,
				      bool *is_enable,
				      struct netlink_ext_ack *extack);
	int (*port_fn_migratable_set)(struct mlxdevm_port *mlxdevm_port,
				      bool enable,
				      struct netlink_ext_ack *extack);
	int (*port_fn_state_get)(struct mlxdevm_port *port,
				 enum mlxdevm_port_fn_state *state,
				 enum mlxdevm_port_fn_opstate *opstate,
				 struct netlink_ext_ack *extack);
	int (*port_fn_state_set)(struct mlxdevm_port *port,
				 enum mlxdevm_port_fn_state state,
				 struct netlink_ext_ack *extack);
	int (*port_fn_ipsec_crypto_get)(struct mlxdevm_port *mlxdevm_port,
					bool *is_enable,
					struct netlink_ext_ack *extack);
	int (*port_fn_ipsec_crypto_set)(struct mlxdevm_port *mlxdevm_port,
					bool enable,
					struct netlink_ext_ack *extack);
	int (*port_fn_ipsec_packet_get)(struct mlxdevm_port *mlxdevm_port,
					bool *is_enable,
					struct netlink_ext_ack *extack);
	int (*port_fn_ipsec_packet_set)(struct mlxdevm_port *mlxdevm_port,
					bool enable,
					struct netlink_ext_ack *extack);
	int (*port_fn_max_io_eqs_get)(struct mlxdevm_port *mlxdevm_port,
				      u32 *max_eqs,
				      struct netlink_ext_ack *extack);
	int (*port_fn_max_io_eqs_set)(struct mlxdevm_port *mlxdevm_port,
				      u32 max_eqs,
				      struct netlink_ext_ack *extack);
	int (*port_fn_trust_get)(struct mlxdevm_port *port,
				 bool *trusted,
				 struct netlink_ext_ack *extack);
	int (*port_fn_trust_set)(struct mlxdevm_port *port,
				 bool trusted,
				 struct netlink_ext_ack *extack);
	int (*port_fn_ext_uc_list_get)(struct mlxdevm_port *port,
				       struct mlxdevm_port_fn_ext_uc_list *uc_list,
				       struct netlink_ext_ack *extack);
	int (*port_fn_ext_uc_list_set)(struct mlxdevm_port *port,
				       struct mlxdevm_port_fn_ext_uc_list *uc_list,
				       struct netlink_ext_ack *extack);
};

void mlxdevm_port_init(struct mlxdevm *mlxdevm,
		       struct mlxdevm_port *mlxdevm_port);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
void devlink_port_fini(struct devlink_port *devlink_port);
#endif

int devm_port_register_with_ops(struct mlxdevm *mlxdevm,
				struct mlxdevm_port *mlxdevm_port,
				unsigned int port_index,
				const struct mlxdevm_port_ops *ops);

static inline int devm_port_register(struct mlxdevm *mlxdevm,
				     struct mlxdevm_port *mlxdevm_port,
				     unsigned int port_index)
{
	return devm_port_register_with_ops(mlxdevm, mlxdevm_port,
					   port_index, NULL);
}

int mlxdevm_port_register_with_ops(struct mlxdevm *mlxdevm,
				   struct mlxdevm_port *mlxdevm_port,
				   unsigned int port_index,
				   const struct mlxdevm_port_ops *ops);

static inline int mlxdevm_port_register(struct mlxdevm *mlxdevm,
					struct mlxdevm_port *mlxdevm_port,
					unsigned int port_index)
{
	return mlxdevm_port_register_with_ops(mlxdevm, mlxdevm_port,
					      port_index, NULL);
}

void devm_port_unregister(struct mlxdevm_port *mlxdevm_port);
void mlxdevm_port_unregister(struct mlxdevm_port *mlxdevm_port);
void mlxdevm_port_type_eth_set(struct mlxdevm_port *mlxdevm_port, struct net_device *netdev);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
void devlink_port_type_ib_set(struct devlink_port *devlink_port,
			      struct ib_device *ibdev);
#endif
void mlxdevm_port_type_clear(struct mlxdevm_port *mlxdevm_port);
void mlxdevm_port_attrs_set(struct mlxdevm_port *mlxdevm_port,
			    struct mlxdevm_port_attrs *mlxdevm_port_attrs);
void mlxdevm_port_attrs_pci_pf_set(struct mlxdevm_port *mlxdevm_port, u32 controller,
				   u16 pf, bool external);
void mlxdevm_port_attrs_pci_vf_set(struct mlxdevm_port *mlxdevm_port, u32 controller,
				   u16 pf, u16 vf, bool external);
void mlxdevm_port_attrs_pci_sf_set(struct mlxdevm_port *mlxdevm_port,
				   u32 controller, u16 pf, u32 sf,
				   bool external);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
int devl_port_fn_devlink_set(struct devlink_port *devlink_port,
			     struct devlink *fn_devlink);
struct devlink_rate *
devl_rate_node_create(struct devlink *devlink, void *priv, char *node_name,
		      struct devlink_rate *parent);
#endif
int
devm_rate_leaf_create(struct mlxdevm_port *mlxdevm_port, void *priv,
		      struct mlxdevm_rate *parent);
void devm_rate_leaf_destroy(struct mlxdevm_port *mlxdevm_port);
void devm_rate_nodes_destroy(struct mlxdevm *mlxdevm);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
void devlink_port_linecard_set(struct devlink_port *devlink_port,
			       struct devlink_linecard *linecard);
struct devlink_linecard *
devl_linecard_create(struct devlink *devlink, unsigned int linecard_index,
		     const struct devlink_linecard_ops *ops, void *priv);
void devl_linecard_destroy(struct devlink_linecard *linecard);
void devlink_linecard_provision_set(struct devlink_linecard *linecard,
				    const char *type);
void devlink_linecard_provision_clear(struct devlink_linecard *linecard);
void devlink_linecard_provision_fail(struct devlink_linecard *linecard);
void devlink_linecard_activate(struct devlink_linecard *linecard);
void devlink_linecard_deactivate(struct devlink_linecard *linecard);
int devlink_linecard_nested_dl_set(struct devlink_linecard *linecard,
				   struct devlink *nested_devlink);
int devl_sb_register(struct devlink *devlink, unsigned int sb_index,
		     u32 size, u16 ingress_pools_count,
		     u16 egress_pools_count, u16 ingress_tc_count,
		     u16 egress_tc_count);
int devlink_sb_register(struct devlink *devlink, unsigned int sb_index,
			u32 size, u16 ingress_pools_count,
			u16 egress_pools_count, u16 ingress_tc_count,
			u16 egress_tc_count);
void devl_sb_unregister(struct devlink *devlink, unsigned int sb_index);
void devlink_sb_unregister(struct devlink *devlink, unsigned int sb_index);
int devl_dpipe_table_register(struct devlink *devlink,
			      const char *table_name,
			      const struct devlink_dpipe_table_ops *table_ops,
			      void *priv, bool counter_control_extern);
void devl_dpipe_table_unregister(struct devlink *devlink,
				 const char *table_name);
void devl_dpipe_headers_register(struct devlink *devlink,
				 struct devlink_dpipe_headers *dpipe_headers);
void devl_dpipe_headers_unregister(struct devlink *devlink);
bool devlink_dpipe_table_counter_enabled(struct devlink *devlink,
					 const char *table_name);
int devlink_dpipe_entry_ctx_prepare(struct devlink_dpipe_dump_ctx *dump_ctx);
int devlink_dpipe_entry_ctx_append(struct devlink_dpipe_dump_ctx *dump_ctx,
				   struct devlink_dpipe_entry *entry);
int devlink_dpipe_entry_ctx_close(struct devlink_dpipe_dump_ctx *dump_ctx);
void devlink_dpipe_entry_clear(struct devlink_dpipe_entry *entry);
int devlink_dpipe_action_put(struct sk_buff *skb,
			     struct devlink_dpipe_action *action);
int devlink_dpipe_match_put(struct sk_buff *skb,
			    struct devlink_dpipe_match *match);
extern struct devlink_dpipe_header devlink_dpipe_header_ethernet;
extern struct devlink_dpipe_header devlink_dpipe_header_ipv4;
extern struct devlink_dpipe_header devlink_dpipe_header_ipv6;
#endif

int devm_resource_register(struct mlxdevm *mlxdevm,
			   const char *resource_name,
			   u64 resource_size,
			   u64 resource_id,
			   u64 parent_resource_id,
			   const struct mlxdevm_resource_size_params *size_params);
void devm_resources_unregister(struct mlxdevm *mlxdevm);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
void devlink_resources_unregister(struct devlink *devlink);
int devl_resource_size_get(struct devlink *devlink,
			   u64 resource_id,
			   u64 *p_resource_size);
int devl_dpipe_table_resource_set(struct devlink *devlink,
				  const char *table_name, u64 resource_id,
				  u64 resource_units);
void devl_resource_occ_get_register(struct devlink *devlink,
				    u64 resource_id,
				    devlink_resource_occ_get_t *occ_get,
				    void *occ_get_priv);
void devl_resource_occ_get_unregister(struct devlink *devlink,
				      u64 resource_id);
#endif
int devm_params_register(struct mlxdevm *mlxdevm,
			 const struct mlxdevm_param *params,
			 size_t params_count);
int mlxdevm_params_register(struct mlxdevm *mlxdevm,
			    const struct mlxdevm_param *params,
			    size_t params_count);
void devm_params_unregister(struct mlxdevm *mlxdevm,
			    const struct mlxdevm_param *params,
			    size_t params_count);
void mlxdevm_params_unregister(struct mlxdevm *mlxdevm,
			       const struct mlxdevm_param *params,
			       size_t params_count);
int devm_param_driverinit_value_get(struct mlxdevm *mlxdevm, u32 param_id,
				    union mlxdevm_param_value *val);
void devm_param_driverinit_value_set(struct mlxdevm *mlxdevm, u32 param_id,
				     union mlxdevm_param_value init_val);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
void devl_param_value_changed(struct devlink *devlink, u32 param_id);
struct devlink_region *devl_region_create(struct devlink *devlink,
					  const struct devlink_region_ops *ops,
					  u32 region_max_snapshots,
					  u64 region_size);
struct devlink_region *
devlink_region_create(struct devlink *devlink,
		      const struct devlink_region_ops *ops,
		      u32 region_max_snapshots, u64 region_size);
struct devlink_region *
devlink_port_region_create(struct devlink_port *port,
			   const struct devlink_port_region_ops *ops,
			   u32 region_max_snapshots, u64 region_size);
void devl_region_destroy(struct devlink_region *region);
void devlink_region_destroy(struct devlink_region *region);
int devlink_region_snapshot_id_get(struct devlink *devlink, u32 *id);
void devlink_region_snapshot_id_put(struct devlink *devlink, u32 id);
int devlink_region_snapshot_create(struct devlink_region *region,
				   u8 *data, u32 snapshot_id);
int devlink_info_serial_number_put(struct devlink_info_req *req,
				   const char *sn);
int devlink_info_board_serial_number_put(struct devlink_info_req *req,
					 const char *bsn);
#endif

enum mlxdevm_info_version_type {
	MLXDEVM_INFO_VERSION_TYPE_NONE,
	MLXDEVM_INFO_VERSION_TYPE_COMPONENT, /* May be used as flash update
					      * component by name.
					      */
};
#ifdef HAVE_BLOCKED_DEVLINK_CODE

int devlink_info_version_fixed_put(struct devlink_info_req *req,
				   const char *version_name,
				   const char *version_value);
int devlink_info_version_stored_put(struct devlink_info_req *req,
				    const char *version_name,
				    const char *version_value);
int devlink_info_version_stored_put_ext(struct devlink_info_req *req,
					const char *version_name,
					const char *version_value,
					enum devlink_info_version_type version_type);
int devlink_info_version_running_put(struct devlink_info_req *req,
				     const char *version_name,
				     const char *version_value);
int devlink_info_version_running_put_ext(struct devlink_info_req *req,
					 const char *version_name,
					 const char *version_value,
					 enum devlink_info_version_type version_type);

void devlink_fmsg_obj_nest_start(struct devlink_fmsg *fmsg);
void devlink_fmsg_obj_nest_end(struct devlink_fmsg *fmsg);

void devlink_fmsg_pair_nest_start(struct devlink_fmsg *fmsg, const char *name);
void devlink_fmsg_pair_nest_end(struct devlink_fmsg *fmsg);

void devlink_fmsg_arr_pair_nest_start(struct devlink_fmsg *fmsg,
				      const char *name);
void devlink_fmsg_arr_pair_nest_end(struct devlink_fmsg *fmsg);
void devlink_fmsg_binary_pair_nest_start(struct devlink_fmsg *fmsg,
					 const char *name);
void devlink_fmsg_binary_pair_nest_end(struct devlink_fmsg *fmsg);

void devlink_fmsg_u32_put(struct devlink_fmsg *fmsg, u32 value);
void devlink_fmsg_string_put(struct devlink_fmsg *fmsg, const char *value);
void devlink_fmsg_binary_put(struct devlink_fmsg *fmsg, const void *value,
			     u16 value_len);

void devlink_fmsg_bool_pair_put(struct devlink_fmsg *fmsg, const char *name,
				bool value);
void devlink_fmsg_u8_pair_put(struct devlink_fmsg *fmsg, const char *name,
			      u8 value);
void devlink_fmsg_u32_pair_put(struct devlink_fmsg *fmsg, const char *name,
			       u32 value);
void devlink_fmsg_u64_pair_put(struct devlink_fmsg *fmsg, const char *name,
			       u64 value);
void devlink_fmsg_string_pair_put(struct devlink_fmsg *fmsg, const char *name,
				  const char *value);
void devlink_fmsg_binary_pair_put(struct devlink_fmsg *fmsg, const char *name,
				  const void *value, u32 value_len);

struct devlink_health_reporter *
devl_port_health_reporter_create(struct devlink_port *port,
				 const struct devlink_health_reporter_ops *ops,
				 u64 graceful_period, void *priv);

struct devlink_health_reporter *
devlink_port_health_reporter_create(struct devlink_port *port,
				    const struct devlink_health_reporter_ops *ops,
				    u64 graceful_period, void *priv);

struct devlink_health_reporter *
devl_health_reporter_create(struct devlink *devlink,
			    const struct devlink_health_reporter_ops *ops,
			    u64 graceful_period, void *priv);

struct devlink_health_reporter *
devlink_health_reporter_create(struct devlink *devlink,
			       const struct devlink_health_reporter_ops *ops,
			       u64 graceful_period, void *priv);

void
devl_health_reporter_destroy(struct devlink_health_reporter *reporter);

void
devlink_health_reporter_destroy(struct devlink_health_reporter *reporter);

void *
devlink_health_reporter_priv(struct devlink_health_reporter *reporter);
int devlink_health_report(struct devlink_health_reporter *reporter,
			  const char *msg, void *priv_ctx);
void
devlink_health_reporter_state_update(struct devlink_health_reporter *reporter,
				     enum devlink_health_reporter_state state);
void
devlink_health_reporter_recovery_done(struct devlink_health_reporter *reporter);

int devl_nested_devlink_set(struct devlink *devlink,
			    struct devlink *nested_devlink);
bool devlink_is_reload_failed(const struct devlink *devlink);
void devlink_remote_reload_actions_performed(struct devlink *devlink,
					     enum devlink_reload_limit limit,
					     u32 actions_performed);

void devlink_flash_update_status_notify(struct devlink *devlink,
					const char *status_msg,
					const char *component,
					unsigned long done,
					unsigned long total);
void devlink_flash_update_timeout_notify(struct devlink *devlink,
					 const char *status_msg,
					 const char *component,
					 unsigned long timeout);
#endif

int devm_traps_register(struct mlxdevm *mlxdevm,
			const struct mlxdevm_trap *traps,
			size_t traps_count, void *priv);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
int devlink_traps_register(struct devlink *devlink,
			   const struct devlink_trap *traps,
			   size_t traps_count, void *priv);
#endif
void devm_traps_unregister(struct mlxdevm *mlxdevm,
			   const struct mlxdevm_trap *traps,
			   size_t traps_count);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
void devlink_traps_unregister(struct devlink *devlink,
			      const struct devlink_trap *traps,
			      size_t traps_count);
void devlink_trap_report(struct devlink *devlink, struct sk_buff *skb,
			 void *trap_ctx, struct devlink_port *in_devlink_port,
			 const struct flow_action_cookie *fa_cookie);
void *devlink_trap_ctx_priv(void *trap_ctx);
#endif
int devm_trap_groups_register(struct mlxdevm *mlxdevm,
			      const struct mlxdevm_trap_group *groups,
			      size_t groups_count);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
int devlink_trap_groups_register(struct devlink *devlink,
				 const struct devlink_trap_group *groups,
				 size_t groups_count);
#endif
void devm_trap_groups_unregister(struct mlxdevm *mlxdevm,
				 const struct mlxdevm_trap_group *groups,
				 size_t groups_count);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
void devlink_trap_groups_unregister(struct devlink *devlink,
				    const struct devlink_trap_group *groups,
				    size_t groups_count);
int
devl_trap_policers_register(struct devlink *devlink,
			    const struct devlink_trap_policer *policers,
			    size_t policers_count);
void
devl_trap_policers_unregister(struct devlink *devlink,
			      const struct devlink_trap_policer *policers,
			      size_t policers_count);
#endif

struct mlxdevm *__must_check mlxdevm_try_get(struct mlxdevm *mlxdevm);
void mlxdevm_put(struct mlxdevm *mlxdevm);
#ifdef HAVE_BLOCKED_DEVLINK_CODE
void devlink_compat_running_version(struct devlink *devlink,
				    char *buf, size_t len);
int devlink_compat_flash_update(struct devlink *devlink, const char *file_name);
int devlink_compat_phys_port_name_get(struct net_device *dev,
				      char *name, size_t len);
int devlink_compat_switch_id_get(struct net_device *dev,
				 struct netdev_phys_item_id *ppid);

int devlink_nl_port_handle_fill(struct sk_buff *msg, struct devlink_port *devlink_port);
size_t devlink_nl_port_handle_size(struct devlink_port *devlink_port);
void devlink_fmsg_dump_skb(struct devlink_fmsg *fmsg, const struct sk_buff *skb);
#endif

#endif /* _NET_DEVLINK_H_ */
