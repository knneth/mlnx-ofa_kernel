/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2020 Mellanox Technologies. */

#ifndef __MLX5_ESW_FT_H__
#define __MLX5_ESW_FT_H__

#ifdef CONFIG_MLX5_CLS_ACT

struct mlx5_flow_table *esw_indir_tbl_get(struct mlx5_eswitch *esw,
					  struct mlx5_esw_flow_attr *attr,
					  struct mlx5_flow_spec *spec,
					  u16 vport, bool decap);
void esw_indir_tbl_put(struct mlx5_eswitch *esw, struct mlx5_esw_flow_attr *attr,
		       u16 vport, bool decap);

static inline bool
esw_indir_tbl_needed(struct mlx5_eswitch *esw, struct mlx5_esw_flow_attr *attr, u32 action,
		     int j)
{
	return attr->in_rep->vport == MLX5_VPORT_UPLINK &&
		attr->dests[j].rep->vport >= MLX5_VPORT_FIRST_VF &&
		attr->dests[j].rep->vport < MLX5_VPORT_ECPF &&
		esw->dev == attr->dests[j].mdev && attr->ip_version &&
		attr->src_port_rewrite_supported;
}

#else
/* indir API stubs */
static inline struct mlx5_flow_table *
esw_indir_tbl_get(struct mlx5_eswitch *esw,
		  struct mlx5_esw_flow_attr *attr,
		  struct mlx5_flow_spec *spec,
		  u16 vport, bool decap)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void
esw_indir_tbl_put(struct mlx5_eswitch *esw, struct mlx5_esw_flow_attr *attr,
		  u16 vport, bool decap)
{
}

static inline bool
esw_indir_tbl_needed(struct mlx5_eswitch *esw, struct mlx5_esw_flow_attr *attr, u32 action,
		     int j)
{
	return false;
}
#endif

#endif /* __MLX5_ESW_FT_H__ */
