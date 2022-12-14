/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies Ltd */

#ifndef _COMPAT_NET_MLXDEVM_H
#define _COMPAT_NET_MLXDEVM_H

#include "../../compat/config.h"

#include <uapi/mlxdevm/mlxdevm_netlink.h>
#include <linux/rwsem.h>

struct mlxdevm;

#define nla_nest_start_noflag nla_nest_start

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

struct mlxdevm_port_fn_cap {
	enum mlxdevm_port_fn_cap_roce roce;
	u32 max_uc_list;
	u8 roce_cap_valid:1;
	u8 uc_list_cap_valid:1;
};

struct mlxdevm_rate_group {
	struct list_head list;
	char *name;
	u64 tx_max;
	u64 tx_share;
};

/**
 * struct mlxdevm_port_pci_sf_attrs - mlxdevm port's PCI SF attributes
 * @controller: Associated controller number
 * @sf: Associated PCI SF for of the PCI PF for this port.
 * @pf: Associated PCI PF number for this port.
 */
struct mlxdevm_port_pci_sf_attrs {
	u32 controller;
	u32 sf;
	u16 pf;
};

/**
 * struct mlxdevm_port_attrs - mlxdevm port object
 * @flavour: flavour of the port
 * @switch_id: if the port is part of switch, this is buffer with ID, otherwise this is NULL
 * @pci_sf: PCI SF port attributes
 */
struct mlxdevm_port_attrs {
	enum mlxdevm_port_flavour flavour;
	union {
		struct mlxdevm_port_pci_sf_attrs pci_sf;
	};
};

struct mlxdevm_port {
	struct list_head list;
	unsigned int index;
	spinlock_t type_lock; /* Protects type and type_dev
			       * pointer consistency.
			       */
	enum mlxdevm_port_type type;
	struct mlxdevm_port_attrs attrs;
	void *type_dev;
};

struct mlxdevm_ops {
	/**
	 * port_new() - Add a new port function of a specified flavor
	 * @dev: mlxdevm instance
	 * @attrs: attributes of the new port
	 * @extack: extack for reporting error messages
	 * @new_port_index: index of the new port
	 *
	 * Mlxdevm core will call this device driver function upon user request
	 * to create a new port function of a specified flavor and optional
	 * attributes
	 *
	 * Notes:
	 *	- Called without mlxdevm instance lock being held. Drivers must
	 *	  implement own means of synchronization
	 *	- On success, drivers must register a port with mlxdevm core
	 *
	 * Return: 0 on success, negative value otherwise.
	 */
	int (*port_new)(struct mlxdevm *dev,
			const struct mlxdevm_port_new_attrs *attrs,
			struct netlink_ext_ack *extack,
			unsigned int *new_port_index);
	/**
	 * port_del() - Delete a port function
	 * @dev: mlxdevm instance
	 * @port_index: port function index to delete
	 * @extack: extack for reporting error messages
	 *
	 * Mlxdevm core will call this device driver function upon user request
	 * to delete a previously created port function
	 *
	 * Notes:
	 *	- Called without mlxdevm instance lock being held. Drivers must
	 *	  implement own means of synchronization
	 *	- On success, drivers must unregister the corresponding mlxdevm
	 *	  port
	 *
	 * Return: 0 on success, negative value otherwise.
	 */
	int (*port_del)(struct mlxdevm *dev, unsigned int port_index,
			struct netlink_ext_ack *extack);

	/**
	 * @port_fn_hw_addr_get: Port function's hardware address get function.
	 *
	 * Should be used by device drivers to report the hardware address of a function managed
	 * by the mlxdevm port. Driver should return -EOPNOTSUPP if it doesn't support port
	 * function handling for a particular port.
	 *
	 * Note: @extack can be NULL when port notifier queries the port function.
	 */
	int (*port_fn_hw_addr_get)(struct mlxdevm *dev,
				   struct mlxdevm_port *port,
				   u8 *hw_addr, int *hw_addr_len,
				   struct netlink_ext_ack *extack);
	/**
	 * @port_fn_hw_addr_set: Port function's hardware address set function.
	 *
	 * Should be used by device drivers to set the hardware address of a function managed
	 * by the mlxdevm port. Driver should return -EOPNOTSUPP if it doesn't support port
	 * function handling for a particular port.
	 */
	int (*port_fn_hw_addr_set)(struct mlxdevm *dev,
				   struct mlxdevm_port *port,
				   const u8 *hw_addr, int hw_addr_len,
				   struct netlink_ext_ack *extack);
	/**
	 * port_fn_state_get() - Get the state of a port function
	 * @dev: mlxdevm instance
	 * @port: The mlxdevm port
	 * @state: Admin configured state
	 * @opstate: Current operational state
	 * @extack: extack for reporting error messages
	 *
	 * Reports the admin and operational state of a mlxdevm port function
	 *
	 * Return: 0 on success, negative value otherwise.
	 */
	int (*port_fn_state_get)(struct mlxdevm *dev,
				 struct mlxdevm_port *port,
				 enum mlxdevm_port_fn_state *state,
				 enum mlxdevm_port_fn_opstate *opstate,
				 struct netlink_ext_ack *extack);
	/**
	 * port_fn_state_set() - Set the admin state of a port function
	 * @dev: mlxdevm instance
	 * @port: The mlxdevm port
	 * @state: Admin state
	 * @extack: extack for reporting error messages
	 *
	 * Set the admin state of a mlxdevm port function
	 *
	 * Return: 0 on success, negative value otherwise.
	 */
	int (*port_fn_state_set)(struct mlxdevm *dev,
				 struct mlxdevm_port *port,
				 enum mlxdevm_port_fn_state state,
				 struct netlink_ext_ack *extack);
	/**
	 * port_fn_cap_get() - Get the state of capabilities
	 * @devm_dev: mlxdevm instance
	 * @port: The mlxdevm port
	 * @cap: port function capabilited
	 * @extack: extack for reporting error messages
	 *
	 * Get the state of function capability
	 *
	 * Return: 0 on success, negative value otherwise.
	 */
	int (*port_fn_cap_get)(struct mlxdevm *devm_dev,
			       struct mlxdevm_port *port,
			       struct mlxdevm_port_fn_cap *cap,
			       struct netlink_ext_ack *extack);
	/**
	 * port_fn_cap_set() - Set the state of capabilities
	 * @devm_dev: mlxdevm instance
	 * @port: The mlxdevm port
	 * @cap: port function capabilies
	 * @extack: extack for reporting error messages
	 *
	 * Set the state of function capability
	 *
	 * Return: 0 on success, negative value otherwise.
	 */
	int (*port_fn_cap_set)(struct mlxdevm *devm_dev,
			       struct mlxdevm_port *port,
			       const struct mlxdevm_port_fn_cap *cap,
			       struct netlink_ext_ack *extack);

	/**
	 * rate_leaf_get() - Get the tx rate settings of the port function
	 * @dev: mlxdevm instance
	 * @port: The mlxdevm port
	 * @tx_max: rate in Mbps
	 * @tx_share: min tx rate in Mbps
	 * @group: parent group
	 * @extack: extack for reporting error message
	 *
	 * Return: 0 on success, error value otherwise.
	 */
	int (*rate_leaf_get)(struct mlxdevm *dev,
			     struct mlxdevm_port *port,
			     u64 *tx_max, u64 *tx_share, char **group,
			     struct netlink_ext_ack *extack);

	/**
	 * rate_leaf_tx_max_set() - Set max tx rate of the port function
	 * @dev: mlxdevm instance
	 * @port: The mlxdevm port
	 * @tx_max: rate in Mbps
	 * @extack: extack for reporting error message
	 *
	 *
	 * Return: 0 on success, error value otherwise.
	 */
	int (*rate_leaf_tx_max_set)(struct mlxdevm *dev,
				    struct mlxdevm_port *port,
				    u64 tx_max, struct netlink_ext_ack *extack);

	/**
	 * rate_leaf_tx_share_set() - Set tx_share of the port function
	 * @dev: mlxdevm instance
	 * @port: The mlxdevm port
	 * @tx_share: min tx rate in Mbps
	 * @extack: extack for reporting error message
	 *
	 * Return: 0 on success, error value otherwise.
	 */
	int (*rate_leaf_tx_share_set)(struct mlxdevm *dev,
				      struct mlxdevm_port *port,
				      u64 tx_share, struct netlink_ext_ack *extack);


	/**
	 * rate_leaf_group_set() - assign group for the port function
	 * @dev: mlxdevm instance
	 * @port: The mlxdevm port
	 * @group: group name
	 * @extack: extack for reporting error message
	 *
	 * Return: 0 on success, error value otherwise.
	 */
	int (*rate_leaf_group_set)(struct mlxdevm *dev,
				   struct mlxdevm_port *port,
				   const char *group,
				   struct netlink_ext_ack *extack);

	/**
	 * rate_node_tx_max_set() - Set tx_max for the QoS group
	 * @dev: mlxdevm instance
	 * @group: group name
	 * @tx_max: rate in Mbps
	 * @extack: extack for reporting error message
	 *
	 * Return: 0 on success, error value otherwise.
	 */
	int (*rate_node_tx_max_set)(struct mlxdevm *dev,
				    const char *group,
				    u64 tx_max,
				    struct netlink_ext_ack *extack);

	/**
	 * rate_node_tx_share_set() - Set tx_share for the QoS group
	 * @dev: mlxdevm instance
	 * @group: group name
	 * @tx_share: rate in Mbps
	 * @extack: extack for reporting error message
	 *
	 * Return: 0 on success, error value otherwise.
	 */
	int (*rate_node_tx_share_set)(struct mlxdevm *dev, const char *group,
				      u64 tx_share, struct netlink_ext_ack *extack);

	/**
	 * rate_node_new() - Create new QoS group
	 * @dev: mlxdevm instance
	 * @group: group name
	 * @extack: extack for reporting error message
	 *
	 * Return: 0 on success, error value otherwise.
	 */
	int (*rate_node_new)(struct mlxdevm *dev, const char *group,
			     struct netlink_ext_ack *extack);

	/**
	 * rate_node_del() - Delete a QoS group
	 * @dev: mlxdevm instance
	 * @group: group name
	 * @extack: extack for reporting error message
	 *
	 * Return: 0 on success, error value otherwise.
	 */
	int (*rate_node_del)(struct mlxdevm *dev, const char *group,
			     struct netlink_ext_ack *extack);
};

struct mlxdevm {
	struct list_head list;
	struct device *device;
	const struct mlxdevm_ops *ops;
	struct list_head port_list;
	struct list_head param_list;
	struct list_head rate_group_list;
	struct mutex lock;
	struct rw_semaphore port_list_rwsem;	/* Protects port list access */
	struct rw_semaphore rate_group_rwsem;   /* Protects rate group access */
};

#define __MLXDEVM_PARAM_MAX_STRING_VALUE 32
#define __MLXDEVM_PARAM_ARRAY_MAX_DATA 64
enum mlxdevm_param_array_type {
	MLXDEVM_PARAM_ARRAY_TYPE_U16 = 1 << 1,
};

enum mlxdevm_param_type {
	MLXDEVM_PARAM_TYPE_U8 = 0,
	MLXDEVM_PARAM_TYPE_U16 = 1,
	MLXDEVM_PARAM_TYPE_U32 = 2,
	MLXDEVM_PARAM_TYPE_STRING = 3,
	MLXDEVM_PARAM_TYPE_BOOL = 4,
	MLXDEVM_PARAM_TYPE_ARRAY_U16 = 5,
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
 * struct mlxdevm_param - mlxdevm configuration parameter data
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
		   struct mlxdevm_param_gset_ctx *ctx);
	int (*validate)(struct mlxdevm *mlxdevm, u32 id,
			union mlxdevm_param_value val,
			struct netlink_ext_ack *extack);
};

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

struct mlxdevm_param_item {
	struct list_head list;
	const struct mlxdevm_param *param;
	union mlxdevm_param_value driverinit_value;
	bool driverinit_value_valid;
	bool published;
};

int mlxdevm_register(struct mlxdevm *dev);
void mlxdevm_unregister(struct mlxdevm *dev);
int mlxdevm_port_register(struct mlxdevm *dev, struct mlxdevm_port *mlxdevm_port,
			   unsigned int port_index);
void mlxdevm_port_unregister(struct mlxdevm *dev, struct mlxdevm_port *mlxdevm_port);
void mlxdevm_port_type_eth_set(struct mlxdevm_port *port, struct net_device *ndev);
void mlxdevm_port_attr_set(struct mlxdevm_port *port, struct mlxdevm_port_attrs *attrs);

int mlxdevm_params_register(struct mlxdevm *mlxdevm,
			    const struct mlxdevm_param *params,
			    size_t params_count);
void mlxdevm_params_unregister(struct mlxdevm *mlxdevm,
			       const struct mlxdevm_param *params,
			       size_t params_count);
void mlxdevm_params_publish(struct mlxdevm *mlxdevm);
void mlxdevm_params_unpublish(struct mlxdevm *mlxdevm);
int mlxdevm_param_driverinit_value_get(struct mlxdevm *mlxdevm, u32 param_id,
				       union mlxdevm_param_value *init_val);
int mlxdevm_param_driverinit_value_set(struct mlxdevm *mlxdevm, u32 param_id,
				       union mlxdevm_param_value init_val);
void mlxdevm_param_value_changed(struct mlxdevm *mlxdevm, u32 param_id);
void mlxdevm_param_value_str_fill(union mlxdevm_param_value *dst_val,
				  const char *src);

int mlxdevm_rate_group_register(struct mlxdevm *dev, struct mlxdevm_rate_group *group);
void mlxdevm_rate_group_unregister(struct mlxdevm *dev, struct mlxdevm_rate_group *group);

#endif /* _COMPAT_NET_MLXDEVM_H */
