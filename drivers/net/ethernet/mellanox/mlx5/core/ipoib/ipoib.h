/*
 * Copyright (c) 2017, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __MLX5E_IPOB_H__
#define __MLX5E_IPOB_H__

#include <linux/mlx5/fs.h>
#include "en.h"

#define MLX5I_MAX_NUM_TC 1

extern const struct ethtool_ops mlx5i_ethtool_ops;

#define MLX5_IB_GRH_BYTES       40
#define MLX5_IPOIB_ENCAP_LEN    4
#define MLX5_IPOIB_PSEUDO_LEN   20
#define MLX5_IPOIB_HARD_LEN     (MLX5_IPOIB_PSEUDO_LEN + MLX5_IPOIB_ENCAP_LEN)

/* ipoib rdma netdev's private data structure */
struct mlx5i_priv {
	struct rdma_netdev rn; /* keep this first */
	struct mlx5_core_qp qp;
	bool   sub_interface;
	u32    qkey;
	u16    pkey_index;
	struct qpn_hash_table *qpn_htbl;
	char  *mlx5e_priv[0];
};

/* Underlay QP control functions */
int mlx5i_create_underlay_qp(struct mlx5_core_dev *mdev, struct mlx5_core_qp *qp);
void mlx5i_destroy_underlay_qp(struct mlx5_core_dev *mdev, struct mlx5_core_qp *qp);
int mlx5i_init_underlay_qp(struct mlx5e_priv *priv);
void mlx5i_uninit_underlay_qp(struct mlx5e_priv *priv);

/* Allocate/Free underlay QPN to netdevice hash table */
int mlx5i_alloc_qpn_to_netdev_ht(struct net_device *netdev);
void mlx5i_free_qpn_to_netdev_ht(struct net_device *netdev);

/* Map/Unmap underlay QPN to netdevice hash table */
int mlx5i_map_qpn_to_netdev(struct net_device *netdev, u32 qpn);
int mlx5i_unmap_qpn_to_netdev(struct net_device *netdev, u32 qpn);

/* Get underlay QPN corresponding net-device */
struct net_device *mlx5i_get_qpn_netdev(struct net_device *netdev, u32 qpn);

/* Shared ndo ops */
int mlx5i_dev_init(struct net_device *dev);
void mlx5i_dev_cleanup(struct net_device *dev);
void mlx5i_tx_timeout(struct net_device *netdev);

/* Default profile functions */
void mlx5i_init(struct mlx5_core_dev *mdev,
		struct net_device *netdev,
		const struct mlx5e_profile *profile,
		void *ppriv);

/* Get child nic profile */
const struct mlx5e_profile *mlx5i_child_get_profile(void);

/* Extract mlx5e_priv from IPoIB netdev */
#define mlx5i_epriv(netdev) ((void *)(((struct mlx5i_priv *)netdev_priv(netdev))->mlx5e_priv))

netdev_tx_t mlx5i_sq_xmit(struct mlx5e_txqsq *sq, struct sk_buff *skb,
			  struct mlx5_av *av, u32 dqpn, u32 dqkey);
void mlx5i_handle_rx_cqe(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe);
int mlx5i_get_ts_info(struct net_device *netdev, struct ethtool_ts_info *info);
void mlx5i_get_drvinfo(struct net_device *dev,
		       struct ethtool_drvinfo *drvinfo);
int mlx5i_get_settings(struct net_device *netdev,
		       struct ethtool_cmd *ecmd);
int mlx5i_get_link_ksettings(struct net_device *netdev,
			     struct ethtool_link_ksettings *link_ksettings);
int mlx5i_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);

#endif /* __MLX5E_IPOB_H__ */
