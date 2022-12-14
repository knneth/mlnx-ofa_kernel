/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2019 Mellanox Technologies. */

#ifndef __MLX5_LAG_H__
#define __MLX5_LAG_H__

#include "mlx5_core.h"
#include "lag_mp.h"
#include "lag_fs.h"

enum {
	MLX5_LAG_P1,
	MLX5_LAG_P2,
};

enum mlx5_lag_user_pref {
	MLX5_LAG_USER_PREF_MODE_QUEUE_AFFINITY = 1,
	MLX5_LAG_USER_PREF_MODE_HASH,
};

enum {
	MLX5_LAG_FLAG_ROCE   = 1 << 0,
	MLX5_LAG_FLAG_SRIOV  = 1 << 1,
	MLX5_LAG_FLAG_MULTIPATH = 1 << 2,
	MLX5_LAG_FLAG_HASH_BASED = 1 << 3,
};

#define MLX5_LAG_MODE_FLAGS (MLX5_LAG_FLAG_ROCE | MLX5_LAG_FLAG_SRIOV |\
			     MLX5_LAG_FLAG_MULTIPATH | \
			     MLX5_LAG_FLAG_HASH_BASED)

struct lag_func {
	struct mlx5_core_dev *dev;
	struct net_device    *netdev;
	enum mlx5_lag_user_pref user_mode;
};

/* Used for collection of netdev event info. */
struct lag_tracker {
	enum   netdev_lag_hash			hash_type;
	enum   netdev_lag_tx_type           tx_type;
	struct netdev_lag_lower_state_info  netdev_state[MLX5_MAX_PORTS];
	struct net_device *ndev[MLX5_MAX_PORTS];
	unsigned int is_bonded:1;
};

/* LAG data of a ConnectX card.
 * It serves both its phys functions.
 */
struct mlx5_lag {
	u8                        flags;
	bool                      shared_fdb;
	u32			  esw_updating;
	struct kref		  ref;
	u8                        v2p_map[MLX5_MAX_PORTS];
	struct lag_func           pf[MLX5_MAX_PORTS];
	struct lag_tracker        tracker;
	struct workqueue_struct   *wq;
	struct delayed_work       bond_work;
	struct notifier_block     nb;
	struct lag_mp             lag_mp;
	bool create_lag;
	struct mlx5_lag_steering  steering;
};

static inline bool mlx5_lag_is_supported(struct mlx5_core_dev *dev)
{
	if (!MLX5_CAP_GEN(dev, vport_group_manager) ||
	    !MLX5_CAP_GEN(dev, lag_master) ||
	    MLX5_CAP_GEN(dev, num_lag_ports) != MLX5_MAX_PORTS)
		return false;
	return true;
}

static inline struct mlx5_lag *
mlx5_lag_dev_get(struct mlx5_core_dev *dev)
{
	return dev->priv.lag;
}

static inline bool
__mlx5_lag_is_active(struct mlx5_lag *ldev)
{
	return !!(ldev->flags & MLX5_LAG_MODE_FLAGS);
}

void mlx5_lag_infer_tx_affinity_mapping(struct lag_tracker *tracker, u8 *port1,
					u8 *port2);
void mlx5_modify_lag(struct mlx5_lag *ldev,
		     struct lag_tracker *tracker);
int mlx5_activate_lag(struct mlx5_lag *ldev,
		      struct lag_tracker *tracker,
		      u8 flags,
		      bool shared_fdb);
int mlx5_lag_dev_get_netdev_idx(struct mlx5_lag *ldev,
				struct net_device *ndev);
int mlx5_destroy_lag(struct mlx5_lag *ldev);

enum mlx5_lag_user_pref mlx5_lag_get_user_mode(struct mlx5_core_dev *dev);
void mlx5_lag_set_user_mode(struct mlx5_core_dev *dev,
			    enum mlx5_lag_user_pref mode);

#endif /* __MLX5_LAG_H__ */
