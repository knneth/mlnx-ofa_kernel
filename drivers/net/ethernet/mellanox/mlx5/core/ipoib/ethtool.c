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

#include "en.h"
#include "ipoib.h"

void mlx5i_get_drvinfo(struct net_device *dev,
		       struct ethtool_drvinfo *drvinfo)
{
	struct mlx5e_priv *priv = mlx5i_epriv(dev);

	mlx5e_ethtool_get_drvinfo(priv, drvinfo);
	strlcpy(drvinfo->driver, DRIVER_NAME "[ib_ipoib]",
		sizeof(drvinfo->driver));
}

static void mlx5i_get_strings(struct net_device *dev, u32 stringset, u8 *data)
{
	struct mlx5e_priv *priv  = mlx5i_epriv(dev);

	mlx5e_ethtool_get_strings(priv, stringset, data);
}

static int mlx5i_get_sset_count(struct net_device *dev, int sset)
{
	struct mlx5e_priv *priv = mlx5i_epriv(dev);

	return mlx5e_ethtool_get_sset_count(priv, sset);
}

static void mlx5i_get_ethtool_stats(struct net_device *dev,
				    struct ethtool_stats *stats,
				    u64 *data)
{
	struct mlx5e_priv *priv = mlx5i_epriv(dev);

	mlx5e_ethtool_get_ethtool_stats(priv, stats, data);
}

static int mlx5i_set_ringparam(struct net_device *dev,
			       struct ethtool_ringparam *param)
{
	struct mlx5e_priv *priv = mlx5i_epriv(dev);

	return mlx5e_ethtool_set_ringparam(priv, param);
}

static void mlx5i_get_ringparam(struct net_device *dev,
				struct ethtool_ringparam *param)
{
	struct mlx5e_priv *priv = mlx5i_epriv(dev);

	mlx5e_ethtool_get_ringparam(priv, param);
}

static int mlx5i_set_channels(struct net_device *dev,
			      struct ethtool_channels *ch)
{
	struct mlx5e_priv *priv = mlx5i_epriv(dev);

	return mlx5e_ethtool_set_channels(priv, ch);
}

static void mlx5i_get_channels(struct net_device *dev,
			       struct ethtool_channels *ch)
{
	struct mlx5e_priv *priv = mlx5i_epriv(dev);

	mlx5e_ethtool_get_channels(priv, ch);
}

static int mlx5i_set_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *coal)
{
	struct mlx5e_priv *priv = mlx5i_epriv(netdev);

	return mlx5e_ethtool_set_coalesce(priv, coal);
}

static int mlx5i_get_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *coal)
{
	struct mlx5e_priv *priv = mlx5i_epriv(netdev);

	return mlx5e_ethtool_get_coalesce(priv, coal);
}

int mlx5i_get_ts_info(struct net_device *netdev,
		      struct ethtool_ts_info *info)
{
	struct mlx5e_priv *priv = mlx5i_epriv(netdev);

	return mlx5e_ethtool_get_ts_info(priv, info);
}

static int mlx5i_flash_device(struct net_device *netdev,
			      struct ethtool_flash *flash)
{
	struct mlx5e_priv *priv = mlx5i_epriv(netdev);

	return mlx5e_ethtool_flash_device(priv, flash);
}

enum ib_ptys_width {
	IB_PTYS_WIDTH_1X	= 1 << 0,
	IB_PTYS_WIDTH_2X	= 1 << 1,
	IB_PTYS_WIDTH_4X	= 1 << 2,
	IB_PTYS_WIDTH_8X	= 1 << 3,
	IB_PTYS_WIDTH_12X	= 1 << 4,
};

static inline int ib_ptys_width_enum_to_int(enum ib_ptys_width width)
{
	switch (width) {
	case IB_PTYS_WIDTH_1X:  return  1;
	case IB_PTYS_WIDTH_2X:  return  2;
	case IB_PTYS_WIDTH_4X:  return  4;
	case IB_PTYS_WIDTH_8X:  return  8;
	case IB_PTYS_WIDTH_12X: return 12;
	default:		return -1;
	}
}

static int mlx5i_get_port_settings(struct net_device *netdev,
				   u16 *ib_link_width_oper, u16 *ib_proto_oper)
{
	struct mlx5e_priv *priv    = mlx5i_epriv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 out[MLX5_ST_SZ_DW(ptys_reg)] = {0};
	int ret;

	ret = mlx5_query_port_ptys(mdev, out, sizeof(out), MLX5_PTYS_IB, 1);
	if (ret) {
		netdev_err(netdev, "%s: query port ptys failed: %d\n",
			   __func__, ret);
		return ret;
	}

	*ib_link_width_oper = MLX5_GET(ptys_reg, out, ib_link_width_oper);
	*ib_proto_oper      = MLX5_GET(ptys_reg, out, ib_proto_oper);

	return 0;
}

static int mlx5i_get_speed_settings(u16 ib_link_width_oper, u16 ib_proto_oper,
				    __u8 *duplex, __u8 *port,
				    __u8 *phy_address, __u8 *autoneg)
{
	char *speed = "";
	int rate;/* in deci-Gb/sec */

	*duplex = DUPLEX_FULL;
	*port = PORT_OTHER;/* till define IB port type */
	*phy_address = 255;
	*autoneg = AUTONEG_DISABLE;

	ib_active_speed_enum_to_rate(ib_proto_oper,
				     &rate,
				     &speed);

	rate *= ib_ptys_width_enum_to_int(ib_link_width_oper);
	if (rate < 0)
		rate = -1;

	return rate * 100;
}

int mlx5i_get_settings(struct net_device *netdev,
		       struct ethtool_cmd *ecmd)
{
	u16 ib_link_width_oper;
	u16 ib_proto_oper;
	int ret;
	int rate;/* in deci-Gb/sec */

	ret = mlx5i_get_port_settings(netdev,
				      &ib_link_width_oper,
				      &ib_proto_oper);
	if (ret)
		return ret;

	rate = mlx5i_get_speed_settings(ib_link_width_oper, ib_proto_oper,
					&ecmd->duplex, &ecmd->port,
					&ecmd->phy_address, &ecmd->autoneg);

	ethtool_cmd_speed_set(ecmd, rate);

	return 0;
}

int mlx5i_get_link_ksettings(struct net_device *netdev,
			     struct ethtool_link_ksettings *link_ksettings)
{
	u16 ib_link_width_oper;
	u16 ib_proto_oper;
	int ret;
	int rate;/* in deci-Gb/sec */

	ret = mlx5i_get_port_settings(netdev,
				      &ib_link_width_oper,
				      &ib_proto_oper);
	if (ret)
		return ret;

	ethtool_link_ksettings_zero_link_mode(link_ksettings, supported);
	ethtool_link_ksettings_zero_link_mode(link_ksettings, advertising);

	rate = mlx5i_get_speed_settings(ib_link_width_oper, ib_proto_oper,
					&link_ksettings->base.duplex,
					&link_ksettings->base.port,
					&link_ksettings->base.phy_address,
					&link_ksettings->base.autoneg);

	link_ksettings->base.speed = rate;

	return 0;
}

const struct ethtool_ops mlx5i_ethtool_ops = {
	.get_drvinfo       = mlx5i_get_drvinfo,
	.get_strings       = mlx5i_get_strings,
	.get_sset_count    = mlx5i_get_sset_count,
	.get_ethtool_stats = mlx5i_get_ethtool_stats,
	.get_ringparam     = mlx5i_get_ringparam,
	.set_ringparam     = mlx5i_set_ringparam,
	.flash_device      = mlx5i_flash_device,
	.get_channels      = mlx5i_get_channels,
	.set_channels      = mlx5i_set_channels,
	.get_coalesce      = mlx5i_get_coalesce,
	.set_coalesce      = mlx5i_set_coalesce,
	.get_ts_info       = mlx5i_get_ts_info,
	.get_settings      = mlx5i_get_settings,
	.get_link          = ethtool_op_get_link,
	.get_link_ksettings = mlx5i_get_link_ksettings,
};
