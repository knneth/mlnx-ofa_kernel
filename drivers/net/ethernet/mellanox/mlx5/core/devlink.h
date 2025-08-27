/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2019, Mellanox Technologies */

#ifndef __MLX5_DEVLINK_H__
#define __MLX5_DEVLINK_H__

#include <net/devlink.h>

enum mlx5_devlink_resource_id {
	MLX5_DL_RES_MAX_LOCAL_SFS = 1,
	MLX5_DL_RES_MAX_EXTERNAL_SFS,

	__MLX5_ID_RES_MAX,
	MLX5_ID_RES_MAX = __MLX5_ID_RES_MAX - 1,
};

enum mlx5_devlink_param_id {
	MLX5_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	MLX5_DEVLINK_PARAM_ID_FLOW_STEERING_MODE,
	MLX5_DEVLINK_PARAM_ID_ESW_LARGE_GROUP_NUM,
	MLX5_DEVLINK_PARAM_ID_CT_MAX_OFFLOADED_CONNS,
	MLX5_DEVLINK_PARAM_ID_ESW_PORT_METADATA,
	MLX5_DEVLINK_PARAM_ID_ESW_MULTIPORT,
	MLX5_DEVLINK_PARAM_ID_HAIRPIN_NUM_QUEUES,
	MLX5_DEVLINK_PARAM_ID_HAIRPIN_QUEUE_SIZE,
};

struct mlx5_trap_ctx {
	int id;
	int action;
};

struct mlx5_devlink_trap {
	struct mlx5_trap_ctx trap;
	void *item;
	struct list_head list;
};

struct mlx5_devlink_trap_event_ctx {
	struct mlx5_trap_ctx *trap;
	int err;
};

struct mlx5_core_dev;
void mlx5_devlink_trap_report(struct mlx5_core_dev *dev, int trap_id, struct sk_buff *skb,
			      struct devlink_port *dl_port);
int mlx5_devlink_trap_get_num_active(struct mlx5_core_dev *dev);
int mlx5_devlink_traps_get_action(struct mlx5_core_dev *dev, int trap_id,
				  enum devlink_trap_action *action);
int mlx5_devlink_traps_register(struct devlink *devlink);
void mlx5_devlink_traps_unregister(struct devlink *devlink);

int mlx5_devlink_info_get(struct devlink *devlink, struct devlink_info_req *req,
			  struct netlink_ext_ack *extack);
int mlx5_devlink_flash_update(struct devlink *devlink,
			      struct devlink_flash_update_params *params,
			      struct netlink_ext_ack *extack);

int mlx5_devlink_reload_down(struct devlink *devlink,
			     bool netns_change,
                             enum devlink_reload_action action,
                             enum devlink_reload_limit limit,
                             struct netlink_ext_ack *extack);
int mlx5_devlink_reload_up(struct devlink *devlink,
			   enum devlink_reload_action action,
                           enum devlink_reload_limit limit, u32 *actions_performed,
                           struct netlink_ext_ack *extack);

int mlx5_devlink_trap_init(struct devlink *devlink, const struct devlink_trap *trap,
			   void *trap_ctx);
void mlx5_devlink_trap_fini(struct devlink *devlink, const struct devlink_trap *trap,
			    void *trap_ctx);
int mlx5_devlink_trap_action_set(struct devlink *devlink,
				 const struct devlink_trap *trap,
				 enum devlink_trap_action action,
				 struct netlink_ext_ack *extack);

struct devlink *mlx5_devlink_alloc(struct device *dev);
void mlx5_devlink_free(struct devlink *devlink);
int mlx5_devlink_params_register(struct devlink *devlink);
void mlx5_devlink_params_unregister(struct devlink *devlink);

int mlx5_devlink_enable_roce_validate(struct devlink *devlink, u32 id,
				      union devlink_param_value val,
				      struct netlink_ext_ack *extack);
#ifdef CONFIG_MLX5_ESWITCH
int mlx5_devlink_large_group_num_validate(struct devlink *devlink, u32 id,
					  union devlink_param_value val,
					  struct netlink_ext_ack *extack);
#endif
int mlx5_devlink_eq_depth_validate(struct devlink *devlink, u32 id,
				   union devlink_param_value val,
				   struct netlink_ext_ack *extack);
int mlx5_devlink_ct_max_offloaded_conns_set(struct devlink *devlink, u32 id,
					    struct devlink_param_gset_ctx *ctx,
					    struct netlink_ext_ack *extack);
int mlx5_devlink_ct_max_offloaded_conns_get(struct devlink *devlink, u32 id,
					    struct devlink_param_gset_ctx *ctx);
int mlx5_devlink_hairpin_num_queues_validate(struct devlink *devlink, u32 id,
					     union devlink_param_value val,
					     struct netlink_ext_ack *extack);
int mlx5_devlink_hairpin_queue_size_validate(struct devlink *devlink, u32 id,
					     union devlink_param_value val,
					     struct netlink_ext_ack *extack);
int mlx5_devlink_enable_rdma_validate(struct devlink *devlink, u32 id,
				      union devlink_param_value val,
				      struct netlink_ext_ack *extack);
int mlx5_devlink_max_uc_list_validate(struct devlink *devlink, u32 id,
				      union devlink_param_value val,
				      struct netlink_ext_ack *extack);

static inline bool mlx5_core_is_eth_enabled(struct mlx5_core_dev *dev)
{
	union devlink_param_value val;
	int err;

	err = devl_param_driverinit_value_get(priv_to_devlink(dev),
					      DEVLINK_PARAM_GENERIC_ID_ENABLE_ETH,
					      &val);
	return err ? false : val.vbool;
}

int
mlx5_devlink_ct_labels_mapping_set(struct devlink *devlink, u32 id,
				   struct devlink_param_gset_ctx *ctx);
int
mlx5_devlink_ct_labels_mapping_get(struct devlink *devlink, u32 id,
				   struct devlink_param_gset_ctx *ctx);
#endif /* __MLX5_DEVLINK_H__ */
