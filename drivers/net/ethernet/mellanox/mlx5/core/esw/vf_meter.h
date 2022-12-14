/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies. */

#ifndef __MLX5_ESW_VF_METERS_H__
#define __MLX5_ESW_VF_METERS_H__

int esw_vf_meter_create_meters(struct mlx5_eswitch *esw);
void esw_vf_meter_destroy_meters(struct mlx5_eswitch *esw);
void esw_vf_meter_ingress_destroy(struct mlx5_vport *vport);
void esw_vf_meter_egress_destroy(struct mlx5_vport *vport);
void esw_vf_meter_destroy_all(struct mlx5_eswitch *esw);

int mlx5_eswitch_set_vf_meter_data(struct mlx5_eswitch *esw, int vport_num,
				   int data_type, int rx_tx, int xps, u64 data);
int mlx5_eswitch_get_vf_meter_data(struct mlx5_eswitch *esw, int vport_num,
				   int data_type, int rx_tx, int xps, u64 *data);

#endif /* __MLX5_ESW_VF_METERS_H__ */
