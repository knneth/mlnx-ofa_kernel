/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2020, Mellanox Technologies */

#ifndef	_DR_STE_
#define	_DR_STE_

#include "dr_types.h"
#include "mlx5dr.h"

#define DR_STE_CRC_POLY 0xEDB88320L
#define STE_IPV4 0x1
#define STE_IPV6 0x2
#define STE_TCP 0x1
#define STE_UDP 0x2
#define STE_SPI 0x3
#define IP_VERSION_IPV4 0x4
#define IP_VERSION_IPV6 0x6
#define STE_SVLAN 0x1
#define STE_CVLAN 0x2
#define HDR_LEN_L2_MACS   0xC
#define HDR_LEN_L2_VLAN   0x4
#define HDR_LEN_L2_ETHER  0x2
#define HDR_LEN_L2        (HDR_LEN_L2_MACS + HDR_LEN_L2_ETHER)
#define HDR_LEN_L2_W_VLAN (HDR_LEN_L2 + HDR_LEN_L2_VLAN)
#define NUM_OF_PARSERS    8

enum {
	HDR_MPLS_OFFSET_LABEL	= 12,
	HDR_MPLS_OFFSET_EXP	= 9,
	HDR_MPLS_OFFSET_S_BOS	= 8,
	HDR_MPLS_OFFSET_TTL	= 0,
};

#define DR_STE_SET_BOOL(typ, p, fld, v) MLX5_SET(ste_##typ, p, fld, !!(v))

/* Set to STE a specific value using DR_STE_SET */
#define DR_STE_SET_VAL(lookup_type, tag, t_fname, spec, s_fname, value) do { \
	if ((spec)->s_fname) { \
		MLX5_SET(ste_##lookup_type, tag, t_fname, value); \
		(spec)->s_fname = 0; \
	} \
} while (0)

/* Set to STE spec->s_fname to tag->t_fname set spec->s_fname as used */
#define DR_STE_SET_TAG(lookup_type, tag, t_fname, spec, s_fname) \
	DR_STE_SET_VAL(lookup_type, tag, t_fname, spec, s_fname, spec->s_fname)

/* Set to STE -1 to tag->t_fname and set spec->s_fname as used */
#define DR_STE_SET_ONES(lookup_type, tag, t_fname, spec, s_fname) \
	DR_STE_SET_VAL(lookup_type, tag, t_fname, spec, s_fname, -1)

/* Set to STE -1 to bit_mask->bm_fname and set spec->s_fname as used */
#define DR_STE_SET_MASK(lookup_type, bit_mask, bm_fname, spec, s_fname) \
	DR_STE_SET_VAL(lookup_type, bit_mask, bm_fname, spec, s_fname, -1)

/* Set to STE spec->s_fname to bit_mask->bm_fname and set spec->s_fname as used */
#define DR_STE_SET_MASK_V(lookup_type, bit_mask, bm_fname, spec, s_fname) \
	DR_STE_SET_VAL(lookup_type, bit_mask, bm_fname, spec, s_fname, (spec)->s_fname)

#define DR_STE_SET_TCP_FLAGS(lookup_type, tag, spec) do { \
	MLX5_SET(ste_##lookup_type, tag, tcp_ns, !!((spec)->tcp_flags & (1 << 8))); \
	MLX5_SET(ste_##lookup_type, tag, tcp_cwr, !!((spec)->tcp_flags & (1 << 7))); \
	MLX5_SET(ste_##lookup_type, tag, tcp_ece, !!((spec)->tcp_flags & (1 << 6))); \
	MLX5_SET(ste_##lookup_type, tag, tcp_urg, !!((spec)->tcp_flags & (1 << 5))); \
	MLX5_SET(ste_##lookup_type, tag, tcp_ack, !!((spec)->tcp_flags & (1 << 4))); \
	MLX5_SET(ste_##lookup_type, tag, tcp_psh, !!((spec)->tcp_flags & (1 << 3))); \
	MLX5_SET(ste_##lookup_type, tag, tcp_rst, !!((spec)->tcp_flags & (1 << 2))); \
	MLX5_SET(ste_##lookup_type, tag, tcp_syn, !!((spec)->tcp_flags & (1 << 1))); \
	MLX5_SET(ste_##lookup_type, tag, tcp_fin, !!((spec)->tcp_flags & (1 << 0))); \
} while (0)

#define DR_STE_SET_MPLS(lookup_type, mask, in_out, tag) do { \
	DR_STE_SET_TAG(lookup_type, tag, mpls0_label, mask, \
		       in_out##_first_mpls_label);\
	DR_STE_SET_TAG(lookup_type, tag, mpls0_s_bos, mask, \
		       in_out##_first_mpls_s_bos); \
	DR_STE_SET_TAG(lookup_type, tag, mpls0_exp, mask, \
		       in_out##_first_mpls_exp); \
	DR_STE_SET_TAG(lookup_type, tag, mpls0_ttl, mask, \
		       in_out##_first_mpls_ttl); \
} while (0)

#define DR_STE_IS_OUTER_MPLS_OVER_GRE_SET(_misc) (\
	(_misc)->outer_first_mpls_over_gre_label || \
	(_misc)->outer_first_mpls_over_gre_exp || \
	(_misc)->outer_first_mpls_over_gre_s_bos || \
	(_misc)->outer_first_mpls_over_gre_ttl)
#define DR_STE_IS_OUTER_MPLS_OVER_UDP_SET(_misc) (\
	(_misc)->outer_first_mpls_over_udp_label || \
	(_misc)->outer_first_mpls_over_udp_exp || \
	(_misc)->outer_first_mpls_over_udp_s_bos || \
	(_misc)->outer_first_mpls_over_udp_ttl)

enum dr_ste_action_modify_type_l3 {
	DR_STE_ACTION_MDFY_TYPE_L3_NONE	= 0x0,
	DR_STE_ACTION_MDFY_TYPE_L3_IPV4	= 0x1,
	DR_STE_ACTION_MDFY_TYPE_L3_IPV6	= 0x2,
};

enum dr_ste_action_modify_type_l4 {
	DR_STE_ACTION_MDFY_TYPE_L4_NONE	= 0x0,
	DR_STE_ACTION_MDFY_TYPE_L4_TCP	= 0x1,
	DR_STE_ACTION_MDFY_TYPE_L4_UDP	= 0x2,
};

u16 mlx5dr_ste_conv_bit_to_byte_mask(u8 *bit_mask);

typedef void (*mlx5dr_ste_builder_void_init)(struct mlx5dr_ste_build *sb,
					     struct mlx5dr_match_param *mask);

typedef int (*mlx5dr_ste_builder_int_init)(struct mlx5dr_ste_build *sb,
					   struct mlx5dr_match_param *mask);

static inline u8 *
dr_ste_calc_flex_parser_offset(u8 *tag, u8 parser_id)
{
	/* calculate tag byte offset based on flex parser id */
	return tag + 4 * (3 - (parser_id % 4));
}

struct mlx5dr_ste_ctx {
	/* Builders */
	mlx5dr_ste_builder_void_init build_eth_l2_src_dst_init;
	mlx5dr_ste_builder_void_init build_eth_l3_ipv6_src_init;
	mlx5dr_ste_builder_void_init build_eth_l3_ipv6_dst_init;
	mlx5dr_ste_builder_void_init build_eth_l3_ipv4_5_tuple_init;
	mlx5dr_ste_builder_void_init build_eth_l2_src_init;
	mlx5dr_ste_builder_void_init build_eth_l2_dst_init;
	mlx5dr_ste_builder_void_init build_eth_l2_tnl_init;
	mlx5dr_ste_builder_void_init build_eth_l3_ipv4_misc_init;
	mlx5dr_ste_builder_void_init build_eth_ipv6_l3_l4_init;
	mlx5dr_ste_builder_void_init build_mpls_init;
	mlx5dr_ste_builder_void_init build_tnl_gre_init;
	mlx5dr_ste_builder_void_init build_tnl_mpls_over_gre_init;
	mlx5dr_ste_builder_void_init build_tnl_mpls_over_udp_init;
	mlx5dr_ste_builder_void_init build_icmp_init;
	mlx5dr_ste_builder_void_init build_general_purpose_init;
	mlx5dr_ste_builder_void_init build_eth_l4_misc_init;
	mlx5dr_ste_builder_void_init build_tnl_vxlan_gpe_init;
	mlx5dr_ste_builder_void_init build_tnl_geneve_init;
	mlx5dr_ste_builder_void_init build_tnl_geneve_tlv_option_init;
	mlx5dr_ste_builder_void_init build_register_0_init;
	mlx5dr_ste_builder_void_init build_register_1_init;
	mlx5dr_ste_builder_void_init build_src_gvmi_qpn_init;
	mlx5dr_ste_builder_void_init build_flex_parser_0_init;
	mlx5dr_ste_builder_void_init build_flex_parser_1_init;
	mlx5dr_ste_builder_void_init build_def0_init;
	mlx5dr_ste_builder_void_init build_def6_init;
	mlx5dr_ste_builder_void_init build_def22_init;
	mlx5dr_ste_builder_void_init build_def24_init;
	mlx5dr_ste_builder_void_init build_def25_init;
	mlx5dr_ste_builder_void_init build_def26_init;

	/* Getters and Setters */
	void (*ste_init)(u8 *hw_ste_p, u16 lu_type,
			 bool is_rx, u16 gvmi);
	void (*set_next_lu_type)(u8 *hw_ste_p, u16 lu_type);
	u16 (*get_next_lu_type)(u8 *hw_ste_p);
	void (*set_miss_addr)(u8 *hw_ste_p, u64 miss_addr);
	u64 (*get_miss_addr)(u8 *hw_ste_p);
	void (*set_hit_addr)(u8 *hw_ste_p, u64 icm_addr, u32 ht_size);
	void (*set_byte_mask)(u8 *hw_ste_p, u16 byte_mask);
	u16 (*get_byte_mask)(u8 *hw_ste_p);
	void (*set_ctrl_always_hit_htbl)(u8 *hw_ste, u16 byte_mask,
					 u16 lu_type, u64 icm_addr,
					 u32 num_of_entries, u16 gvmi);
	void (*set_ctrl_always_miss)(u8 *hw_ste, u64 miss_addr, u16 gvmi);

	/* Actions */
	u32 actions_caps;
	void (*set_actions_rx)(struct mlx5dr_domain *dmn,
			       u8 *action_type_set,
			       u8 *hw_ste_arr,
			       struct mlx5dr_ste_actions_attr *attr,
			       u32 *added_stes);
	void (*set_actions_tx)(struct mlx5dr_domain *dmn,
			       u8 *action_type_set,
			       u8 *hw_ste_arr,
			       struct mlx5dr_ste_actions_attr *attr,
			       u32 *added_stes);
	u32 modify_field_arr_sz;
	const struct mlx5dr_ste_action_modify_field *modify_field_arr;
	void (*set_action_set)(u8 *hw_action,
			       u8 hw_field,
			       u8 shifter,
			       u8 length,
			       u32 data);
	void (*set_action_add)(u8 *hw_action,
			       u8 hw_field,
			       u8 shifter,
			       u8 length,
			       u32 data);
	void (*set_action_copy)(u8 *hw_action,
				u8 dst_hw_field,
				u8 dst_shifter,
				u8 dst_len,
				u8 src_hw_field,
				u8 src_shifter);
	int (*set_action_decap_l3_list)(void *data,
					u32 data_sz,
					u8 *hw_action,
					u32 hw_action_sz,
					u16 *used_hw_action_num);
	int (*alloc_modify_hdr_chunk)(struct mlx5dr_action *action,
				      u32 chunck_size);
	void (*dealloc_modify_hdr_chunk)(struct mlx5dr_action *action);

	/* Send */
	void (*prepare_for_postsend)(u8 *hw_ste_p, u32 ste_size);
};

struct mlx5dr_ste_ctx *mlx5dr_ste_get_ctx_v0(void);
struct mlx5dr_ste_ctx *mlx5dr_ste_get_ctx_v1(void);

#endif  /* _DR_STE_ */
