// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2019 Mellanox Technologies. */

#include <linux/types.h>
#include <linux/crc32.h>
#include "dr_ste.h"

#define DR_STE_CALC_DFNR_TYPE(lookup_type, inner) \
	((inner) ? DR_STE_V1_LU_TYPE_##lookup_type##_I : \
		   DR_STE_V1_LU_TYPE_##lookup_type##_O)

enum mlx5dr_ste_v1_entry_format {
	DR_STE_V1_TYPE_BWC_BYTE			= 0x0,
	DR_STE_V1_TYPE_BWC_DW			= 0x1,
	DR_STE_V1_TYPE_MATCH_AND_MASK_BYTE	= 0x2,
	DR_STE_V1_TYPE_MATCH_AND_MASK_DW	= 0x3,
	DR_STE_V1_TYPE_MATCH			= 0x4,

};

/* Lookup type is built from 2B: [ Definer mode 1B ][ Definer index 1B ] */
enum {
	DR_STE_V1_LU_TYPE_NOP				= 0x0000,
	DR_STE_V1_LU_TYPE_ETHL2_TNL			= 0x0002,
	DR_STE_V1_LU_TYPE_IBL3_EXT			= 0x0102,
	DR_STE_V1_LU_TYPE_ETHL2_O			= 0x0003,
	DR_STE_V1_LU_TYPE_IBL4				= 0x0103,
	DR_STE_V1_LU_TYPE_ETHL2_I			= 0x0004,
	DR_STE_V1_LU_TYPE_SRC_QP_GVMI			= 0x0104,
	DR_STE_V1_LU_TYPE_ETHL2_SRC_O			= 0x0005,
	DR_STE_V1_LU_TYPE_ETHL2_HEADERS_O		= 0x0105,
	DR_STE_V1_LU_TYPE_ETHL2_SRC_I			= 0x0006,
	DR_STE_V1_LU_TYPE_ETHL2_HEADERS_I		= 0x0106,
	DR_STE_V1_LU_TYPE_ETHL3_IPV4_5_TUPLE_O		= 0x0007,
	DR_STE_V1_LU_TYPE_IPV6_DES_O			= 0x0107,
	DR_STE_V1_LU_TYPE_ETHL3_IPV4_5_TUPLE_I		= 0x0008,
	DR_STE_V1_LU_TYPE_IPV6_DES_I			= 0x0108,
	DR_STE_V1_LU_TYPE_ETHL4_O			= 0x0009,
	DR_STE_V1_LU_TYPE_IPV6_SRC_O			= 0x0109,
	DR_STE_V1_LU_TYPE_ETHL4_I			= 0x000a,
	DR_STE_V1_LU_TYPE_IPV6_SRC_I			= 0x010a,
	DR_STE_V1_LU_TYPE_ETHL2_SRC_DST_O		= 0x000b,
	DR_STE_V1_LU_TYPE_MPLS_O			= 0x010b,
	DR_STE_V1_LU_TYPE_ETHL2_SRC_DST_I		= 0x000c,
	DR_STE_V1_LU_TYPE_MPLS_I			= 0x010c,
	DR_STE_V1_LU_TYPE_ETHL3_IPV4_MISC_O		= 0x000d,
	DR_STE_V1_LU_TYPE_GRE				= 0x010d,
	DR_STE_V1_LU_TYPE_FLEX_PARSER_TNL_HEADER	= 0x000e,
	DR_STE_V1_LU_TYPE_GENERAL_PURPOSE		= 0x010e,
	DR_STE_V1_LU_TYPE_ETHL3_IPV4_MISC_I		= 0x000f,
	DR_STE_V1_LU_TYPE_STEERING_REGISTERS_0		= 0x010f,
	DR_STE_V1_LU_TYPE_STEERING_REGISTERS_1		= 0x0110,
	DR_STE_V1_LU_TYPE_FLEX_PARSER_0			= 0x0111,
	DR_STE_V1_LU_TYPE_FLEX_PARSER_1			= 0x0112,
	DR_STE_V1_LU_TYPE_ETHL4_MISC_O			= 0x0113,
	DR_STE_V1_LU_TYPE_ETHL4_MISC_I			= 0x0114,
	DR_STE_V1_LU_TYPE_MATCH				= 0x0400,
	DR_STE_V1_LU_TYPE_INVALID			= 0x00ff,
	DR_STE_V1_LU_TYPE_DONT_CARE			= MLX5DR_STE_LU_TYPE_DONT_CARE,
};

enum dr_ste_v1_header_anchors {
	DR_STE_HEADER_ANCHOR_START_OUTER		= 0x00,
	DR_STE_HEADER_ANCHOR_1ST_VLAN			= 0x02,
	DR_STE_HEADER_ANCHOR_IPV6_IPV4			= 0x07,
	DR_STE_HEADER_ANCHOR_INNER_MAC			= 0x13,
	DR_STE_HEADER_ANCHOR_INNER_IPV6_IPV4		= 0x19,
};

enum dr_ste_v1_action_size {
	DR_STE_ACTION_SINGLE_SZ = 4,
	DR_STE_ACTION_DOUBLE_SZ = 8,
	DR_STE_ACTION_TRIPLE_SZ = 12,
};

enum dr_ste_v1_action_insert_ptr_attr {
	DR_STE_V1_ACTION_INSERT_PTR_ATTR_NONE = 0,  // Regular push header (e.g. push vlan)
	DR_STE_V1_ACTION_INSERT_PTR_ATTR_ENCAP = 1, // Encapsulation / Tunneling
	DR_STE_V1_ACTION_INSERT_PTR_ATTR_ESP = 2,   // IPsec
};

enum dr_ste_v1_action_id {
	DR_STE_V1_ACTION_ID_NOP				= 0x00,
	DR_STE_V1_ACTION_ID_COPY			= 0x05,
	DR_STE_V1_ACTION_ID_SET				= 0x06,
	DR_STE_V1_ACTION_ID_ADD				= 0x07,
	DR_STE_V1_ACTION_ID_REMOVE_BY_SIZE		= 0x08,
	DR_STE_V1_ACTION_ID_REMOVE_HEADER_TO_HEADER	= 0x09,
	DR_STE_V1_ACTION_ID_INSERT_INLINE		= 0x0a,
	DR_STE_V1_ACTION_ID_INSERT_POINTER		= 0x0b,
	DR_STE_V1_ACTION_ID_FLOW_TAG			= 0x0c,
	DR_STE_V1_ACTION_ID_QUEUE_ID_SEL		= 0x0d,
	DR_STE_V1_ACTION_ID_ACCELERATED_LIST		= 0x0e,
	DR_STE_V1_ACTION_ID_MODIFY_LIST			= 0x0f,
	DR_STE_V1_ACTION_ID_ASO				= 0x12,
	DR_STE_V1_ACTION_ID_TRAILER			= 0x13,
	DR_STE_V1_ACTION_ID_COUNTER_ID			= 0x14,
	DR_STE_V1_ACTION_ID_MAX				= 0x21,
	/* use for special cases */
	DR_STE_V1_ACTION_ID_SPECIAL_ENCAP_L3		= 0x22,
};

enum {
	DR_STE_V1_ACTION_MDFY_FLD_L2_OUT_0		= 0x00,
	DR_STE_V1_ACTION_MDFY_FLD_L2_OUT_1		= 0x01,
	DR_STE_V1_ACTION_MDFY_FLD_L2_OUT_2		= 0x02,
	DR_STE_V1_ACTION_MDFY_FLD_SRC_L2_OUT_0		= 0x08,
	DR_STE_V1_ACTION_MDFY_FLD_SRC_L2_OUT_1		= 0x09,
	DR_STE_V1_ACTION_MDFY_FLD_L3_OUT_0		= 0x0e,
	DR_STE_V1_ACTION_MDFY_FLD_L4_OUT_0		= 0x18,
	DR_STE_V1_ACTION_MDFY_FLD_L4_OUT_1		= 0x19,
	DR_STE_V1_ACTION_MDFY_FLD_IPV4_OUT_0		= 0x40,
	DR_STE_V1_ACTION_MDFY_FLD_IPV4_OUT_1		= 0x41,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_0	= 0x44,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_1	= 0x45,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_2	= 0x46,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_3	= 0x47,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_0	= 0x4c,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_1	= 0x4d,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_2	= 0x4e,
	DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_3	= 0x4f,
	DR_STE_V1_ACTION_MDFY_FLD_TCP_MISC_0		= 0x5e,
	DR_STE_V1_ACTION_MDFY_FLD_TCP_MISC_1		= 0x5f,
	DR_STE_V1_ACTION_MDFY_FLD_CFG_HDR_0_0		= 0x6f,
	DR_STE_V1_ACTION_MDFY_FLD_CFG_HDR_0_1		= 0x70,
	DR_STE_V1_ACTION_MDFY_FLD_METADATA_2_CQE	= 0x7b,
	DR_STE_V1_ACTION_MDFY_FLD_GNRL_PURPOSE		= 0x7c,
	DR_STE_V1_ACTION_MDFY_FLD_REGISTER_2		= 0x8c,
	DR_STE_V1_ACTION_MDFY_FLD_REGISTER_3		= 0x8d,
	DR_STE_V1_ACTION_MDFY_FLD_REGISTER_4		= 0x8e,
	DR_STE_V1_ACTION_MDFY_FLD_REGISTER_5		= 0x8f,
	DR_STE_V1_ACTION_MDFY_FLD_REGISTER_6		= 0x90,
	DR_STE_V1_ACTION_MDFY_FLD_REGISTER_7		= 0x91,
};

enum dr_ste_v1_aso_ctx_type {
	DR_STE_V1_ASO_CTX_TYPE_POLICERS = 0x2,
};

static const struct mlx5dr_ste_action_modify_field dr_ste_v1_action_modify_field_arr[] = {
	[MLX5_ACTION_IN_FIELD_OUT_SMAC_47_16] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_SRC_L2_OUT_0, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SMAC_15_0] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_SRC_L2_OUT_1, .start = 16, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_ETHERTYPE] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L2_OUT_1, .start = 0, .end = 15,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DMAC_47_16] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L2_OUT_0, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DMAC_15_0] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L2_OUT_1, .start = 16, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IP_DSCP] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L3_OUT_0, .start = 18, .end = 23,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_FLAGS] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L4_OUT_1, .start = 16, .end = 24,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_SPORT] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L4_OUT_0, .start = 16, .end = 31,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_DPORT] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L4_OUT_0, .start = 0, .end = 15,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_TCP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IP_TTL] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L3_OUT_0, .start = 8, .end = 15,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_OUT_IPV6_HOPLIMIT] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L3_OUT_0, .start = 8, .end = 15,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_UDP_SPORT] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L4_OUT_0, .start = 16, .end = 31,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_UDP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_UDP_DPORT] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L4_OUT_0, .start = 0, .end = 15,
		.l4_type = DR_STE_ACTION_MDFY_TYPE_L4_UDP,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_127_96] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_0, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_95_64] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_1, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_63_32] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_2, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV6_31_0] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_SRC_OUT_3, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_127_96] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_0, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_95_64] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_1, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_63_32] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_2, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV6_31_0] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV6_DST_OUT_3, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV6,
	},
	[MLX5_ACTION_IN_FIELD_OUT_SIPV4] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV4_OUT_0, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_OUT_DIPV4] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_IPV4_OUT_1, .start = 0, .end = 31,
		.l3_type = DR_STE_ACTION_MDFY_TYPE_L3_IPV4,
	},
	[MLX5_ACTION_IN_FIELD_METADATA_REG_A] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_GNRL_PURPOSE, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_METADATA_REG_B] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_METADATA_2_CQE, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_METADATA_REG_C_0] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_REGISTER_6, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_METADATA_REG_C_1] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_REGISTER_7, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_METADATA_REG_C_2] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_REGISTER_4, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_METADATA_REG_C_3] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_REGISTER_5, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_METADATA_REG_C_4] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_REGISTER_2, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_METADATA_REG_C_5] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_REGISTER_3, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_SEQ_NUM] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_TCP_MISC_0, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_TCP_ACK_NUM] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_TCP_MISC_1, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_FIRST_VID] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_L2_OUT_2, .start = 0, .end = 15,
	},
	[MLX5_ACTION_IN_FIELD_OUT_EMD_31_0] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_CFG_HDR_0_1, .start = 0, .end = 31,
	},
	[MLX5_ACTION_IN_FIELD_OUT_EMD_47_32] = {
		.hw_field = DR_STE_V1_ACTION_MDFY_FLD_CFG_HDR_0_0, .start = 0, .end = 15,
	},
};

static void dr_ste_v1_set_entry_type(u8 *hw_ste_p, u8 entry_type)
{
	MLX5_SET(ste_match_bwc, hw_ste_p, entry_format, entry_type);
}

static u8 dr_ste_v1_get_entry_type(u8 *hw_ste_p)
{
	return MLX5_GET(ste_match_bwc, hw_ste_p, entry_format);
}

static void dr_ste_v1_set_miss_addr(u8 *hw_ste_p, u64 miss_addr)
{
	u64 index = miss_addr >> 6;

	MLX5_SET(ste_match_bwc, hw_ste_p, miss_address_39_32, index >> 26);
	MLX5_SET(ste_match_bwc, hw_ste_p, miss_address_31_6, index);
}

static u64 dr_ste_v1_get_miss_addr(u8 *hw_ste_p)
{
	u64 index =
		((u64)MLX5_GET(ste_match_bwc, hw_ste_p, miss_address_31_6) |
		 ((u64)MLX5_GET(ste_match_bwc, hw_ste_p, miss_address_39_32)) << 26);

	return index << 6;
}

static void dr_ste_v1_set_byte_mask(u8 *hw_ste_p, u16 byte_mask)
{
	if (dr_ste_v1_get_entry_type(hw_ste_p) != DR_STE_V1_TYPE_MATCH)
		MLX5_SET(ste_match_bwc, hw_ste_p, byte_mask, byte_mask);
}

static u16 dr_ste_v1_get_byte_mask(u8 *hw_ste_p)
{
	return MLX5_GET(ste_match_bwc, hw_ste_p, byte_mask);
}

static void dr_ste_v1_set_lu_type(u8 *hw_ste_p, u16 lu_type)
{
	MLX5_SET(ste_match_bwc, hw_ste_p, entry_format, lu_type >> 8);
	MLX5_SET(ste_match_bwc, hw_ste_p, match_definer_ctx_idx, lu_type & 0xFF);
}

static void dr_ste_v1_set_next_lu_type(u8 *hw_ste_p, u16 lu_type)
{
	if (dr_ste_v1_get_entry_type(hw_ste_p) != DR_STE_V1_TYPE_MATCH)
		MLX5_SET(ste_match_bwc, hw_ste_p, next_entry_format, lu_type >> 8);
	MLX5_SET(ste_match_bwc, hw_ste_p, hash_definer_ctx_idx, lu_type & 0xFF);
}

static u16 dr_ste_v1_get_next_lu_type(u8 *hw_ste_p)
{
	u8 mode = MLX5_GET(ste_match_bwc, hw_ste_p, next_entry_format);
	u8 index = MLX5_GET(ste_match_bwc, hw_ste_p, hash_definer_ctx_idx);

	return (mode << 8 | index);
}

static void dr_ste_v1_set_hit_gvmi(u8 *hw_ste_p, u16 gvmi)
{
	MLX5_SET(ste_match_bwc, hw_ste_p, next_table_base_63_48, gvmi);
}

static void dr_ste_v1_set_hit_addr(u8 *hw_ste_p, u64 icm_addr, u32 ht_size)
{
	u64 index = (icm_addr >> 5) | ht_size;

	MLX5_SET(ste_match_bwc, hw_ste_p, next_table_base_39_32_size, index >> 27);
	MLX5_SET(ste_match_bwc, hw_ste_p, next_table_base_31_5_size, index);
}

static bool dr_ste_v1_is_match_ste(u16 lu_type)
{
	return ((lu_type >> 8) == DR_STE_V1_TYPE_MATCH);
}

static void dr_ste_v1_init(u8 *hw_ste_p, u16 lu_type,
			   bool is_rx, u16 gvmi)
{
	dr_ste_v1_set_lu_type(hw_ste_p, lu_type);

	/* No need for GVMI on match ste */
	if (!dr_ste_v1_is_match_ste(lu_type))
		MLX5_SET(ste_match_bwc, hw_ste_p, gvmi, gvmi);

	dr_ste_v1_set_next_lu_type(hw_ste_p, MLX5DR_STE_LU_TYPE_DONT_CARE);

	MLX5_SET(ste_match_bwc, hw_ste_p, gvmi, gvmi);
	MLX5_SET(ste_match_bwc, hw_ste_p, next_table_base_63_48, gvmi);
	MLX5_SET(ste_match_bwc, hw_ste_p, miss_address_63_48, gvmi);
}

static void dr_ste_v1_set_ctrl_always_hit_htbl(u8 *hw_ste_p, u16 byte_mask,
					       u16 lu_type, u64 icm_addr,
					       u32 num_of_entries, u16 gvmi)
{
	bool target_is_match = dr_ste_v1_is_match_ste(lu_type);
	u32 *first_action;

	if (target_is_match) {
		/* Convert STE to MATCH */
		dr_ste_v1_set_entry_type(hw_ste_p, DR_STE_V1_TYPE_MATCH);
		dr_ste_v1_set_miss_addr(hw_ste_p, 0);

		/* No need to clear the whole field - clear the first action */
		first_action = (u32 *)MLX5_ADDR_OF(ste_mask_and_match, hw_ste_p, action);
		*first_action = 0;
	} else {
		/* Convert STE to BWC */
		dr_ste_v1_set_entry_type(hw_ste_p, DR_STE_V1_TYPE_BWC_BYTE);
		dr_ste_v1_set_byte_mask(hw_ste_p, byte_mask);
		MLX5_SET(ste_match_bwc, hw_ste_p, gvmi, gvmi);
		MLX5_SET(ste_match_bwc, hw_ste_p, mask_mode, 0);
	}

	dr_ste_v1_set_next_lu_type(hw_ste_p, lu_type);
	dr_ste_v1_set_hit_addr(hw_ste_p, icm_addr, num_of_entries);
}

static void dr_ste_v1_set_ctrl_always_miss(u8 *hw_ste_p, u64 miss_addr,
					   u16 gvmi)
{
	dr_ste_v1_set_hit_addr(hw_ste_p, -1, 0);
	dr_ste_v1_set_next_lu_type(hw_ste_p, DR_STE_V1_LU_TYPE_DONT_CARE);
	dr_ste_v1_set_miss_addr(hw_ste_p, miss_addr);
}

static void dr_ste_v1_prepare_for_postsend(u8 *hw_ste_p,
					   u32 ste_size)
{
	u8 entry_type = dr_ste_v1_get_entry_type(hw_ste_p);
	u8 *tag = hw_ste_p + DR_STE_SIZE_CTRL;
	u8 *mask = tag + DR_STE_SIZE_TAG;
	u8 tmp_tag[DR_STE_SIZE_TAG] = {};

	if (ste_size == DR_STE_SIZE_CTRL)
		return;

	WARN_ON(ste_size != DR_STE_SIZE);

	if (entry_type == DR_STE_V1_TYPE_MATCH)
		return;

	/* Backup tag */
	memcpy(tmp_tag, tag, DR_STE_SIZE_TAG);

	/* Swap mask and tag  both are the same size */
	memcpy(tag, mask, DR_STE_SIZE_MASK);
	memcpy(mask, tmp_tag, DR_STE_SIZE_TAG);
}

static void dr_ste_v1_set_rx_flow_tag(u8 *s_action, u32 flow_tag)
{
	MLX5_SET(ste_single_action_flow_tag, s_action, action_id,
		 DR_STE_V1_ACTION_ID_FLOW_TAG);
	MLX5_SET(ste_single_action_flow_tag, s_action, flow_tag, flow_tag);
}

static void dr_ste_v1_set_counter_id(u8 *hw_ste_p, u32 ctr_id)
{
	MLX5_SET(ste_match_bwc, hw_ste_p, counter_id, ctr_id);
}

static void dr_ste_v1_set_reparse(u8 *hw_ste_p)
{
	MLX5_SET(ste_match_bwc, hw_ste_p, reparse, 1);
}

static void dr_ste_v1_set_encap(u8 *hw_ste_p, u8 *d_action,
				u32 reformat_id, int size)
{
	MLX5_SET(ste_double_action_insert_with_ptr, d_action, action_id,
		 DR_STE_V1_ACTION_ID_INSERT_POINTER);
	/* The hardware expects here size in words (2 byte) */
	MLX5_SET(ste_double_action_insert_with_ptr, d_action, size, size / 2);
	MLX5_SET(ste_double_action_insert_with_ptr, d_action, pointer, reformat_id);
	MLX5_SET(ste_double_action_insert_with_ptr, d_action, attributes,
		 DR_STE_V1_ACTION_INSERT_PTR_ATTR_ENCAP);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v1_set_insert_hdr(u8 *hw_ste_p, u8 *d_action,
				     u32 reformat_id,
				     u8 anchor, u8 offset,
				     int size)
{
	MLX5_SET(ste_double_action_insert_with_ptr, d_action,
		 action_id, DR_STE_V1_ACTION_ID_INSERT_POINTER);
	MLX5_SET(ste_double_action_insert_with_ptr, d_action, start_anchor, anchor);

	/* The hardware expects here size and offset in words (2 byte) */
	MLX5_SET(ste_double_action_insert_with_ptr, d_action, size, size / 2);
	MLX5_SET(ste_double_action_insert_with_ptr, d_action, start_offset, offset / 2);

	MLX5_SET(ste_double_action_insert_with_ptr, d_action, pointer, reformat_id);
	MLX5_SET(ste_double_action_insert_with_ptr, d_action, attributes,
		 DR_STE_V1_ACTION_INSERT_PTR_ATTR_NONE);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v1_set_tx_push_vlan(u8 *hw_ste_p, u8 *d_action,
				       u32 vlan_hdr)
{
	MLX5_SET(ste_double_action_insert_with_inline, d_action,
		 action_id, DR_STE_V1_ACTION_ID_INSERT_INLINE);
	/* The hardware expects offset to vlan header in words (2 byte) */
	MLX5_SET(ste_double_action_insert_with_inline, d_action,
		 start_offset, HDR_LEN_L2_MACS >> 1);
	MLX5_SET(ste_double_action_insert_with_inline, d_action,
		 inline_data, vlan_hdr);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v1_set_rx_pop_vlan(u8 *hw_ste_p, u8 *s_action)
{
	MLX5_SET(ste_single_action_remove_header_size, s_action,
		 action_id, DR_STE_V1_ACTION_ID_REMOVE_BY_SIZE);
	MLX5_SET(ste_single_action_remove_header_size, s_action,
		 start_anchor, DR_STE_HEADER_ANCHOR_1ST_VLAN);
	/* The hardware expects here size in words (2 byte) */
	MLX5_SET(ste_single_action_remove_header_size, s_action,
		 remove_size, HDR_LEN_L2_VLAN >> 1);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v1_set_encap_l3(u8 *hw_ste_p,
				   u8 *frst_s_action,
				   u8 *scnd_d_action,
				   u32 reformat_id,
				   int size)
{
	/* Remove L2 headers */
	MLX5_SET(ste_single_action_remove_header, frst_s_action, action_id,
		 DR_STE_V1_ACTION_ID_REMOVE_HEADER_TO_HEADER);
	MLX5_SET(ste_single_action_remove_header, frst_s_action, end_anchor,
		 DR_STE_HEADER_ANCHOR_IPV6_IPV4);

	/* Encapsulate with given reformat ID */
	MLX5_SET(ste_double_action_insert_with_ptr, scnd_d_action, action_id,
		 DR_STE_V1_ACTION_ID_INSERT_POINTER);
	/* The hardware expects here size in words (2 byte) */
	MLX5_SET(ste_double_action_insert_with_ptr, scnd_d_action, size, size / 2);
	MLX5_SET(ste_double_action_insert_with_ptr, scnd_d_action, pointer, reformat_id);
	MLX5_SET(ste_double_action_insert_with_ptr, scnd_d_action, attributes,
		 DR_STE_V1_ACTION_INSERT_PTR_ATTR_ENCAP);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v1_set_rx_decap(u8 *hw_ste_p, u8 *s_action)
{
	MLX5_SET(ste_single_action_remove_header, s_action, action_id,
		 DR_STE_V1_ACTION_ID_REMOVE_HEADER_TO_HEADER);
	MLX5_SET(ste_single_action_remove_header, s_action, decap, 1);
	MLX5_SET(ste_single_action_remove_header, s_action, vni_to_cqe, 1);
	MLX5_SET(ste_single_action_remove_header, s_action, end_anchor,
		 DR_STE_HEADER_ANCHOR_INNER_MAC);

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v1_set_accelerated_rewrite_actions(u8 *hw_ste_p,
						      u8 *d_action,
						      u16 num_of_actions,
						      u32 re_write_index,
						      u32 re_write_args,
						      u8 *action_data)
{
	if (action_data) {
		memcpy(d_action, action_data, DR_MODIFY_ACTION_SIZE);
	} else {
		MLX5_SET(ste_double_action_accelerated_modify_action_list, d_action,
			 action_id, DR_STE_V1_ACTION_ID_ACCELERATED_LIST);
		MLX5_SET(ste_double_action_accelerated_modify_action_list, d_action,
			 modify_actions_pattern_pointer, re_write_index);
		MLX5_SET(ste_double_action_accelerated_modify_action_list, d_action,
			 number_of_modify_actions, num_of_actions);
		MLX5_SET(ste_double_action_accelerated_modify_action_list, d_action,
			 modify_actions_argument_pointer, re_write_args);
	}

	dr_ste_v1_set_reparse(hw_ste_p);
}

static void dr_ste_v1_set_aso_flow_meter(u8 *d_action,
					 u32 object_id,
					 u32 offset,
					 u8 dest_reg_id,
					 u8 init_color)
{
	MLX5_SET(ste_double_action_aso_v1, d_action, action_id,
		 DR_STE_V1_ACTION_ID_ASO);
	MLX5_SET(ste_double_action_aso_v1, d_action, aso_context_number,
		 object_id + (offset / MLX5DR_ASO_FLOW_METER_NUM_PER_OBJ));
	/* Convert reg_c index to HW 64bit index */
	MLX5_SET(ste_double_action_aso_v1, d_action, dest_reg_id,
		 (dest_reg_id - 1) / 2);
	MLX5_SET(ste_double_action_aso_v1, d_action, aso_context_type,
		 DR_STE_V1_ASO_CTX_TYPE_POLICERS);
	MLX5_SET(ste_double_action_aso_v1, d_action, flow_meter.line_id,
		 offset % MLX5DR_ASO_FLOW_METER_NUM_PER_OBJ);
	MLX5_SET(ste_double_action_aso_v1, d_action, flow_meter.initial_color,
		 init_color);
}

static inline void dr_ste_v1_arr_init_next_match(u8 **last_ste,
						 u32 *added_stes,
						 u16 gvmi)
{
	u8 *action;

	(*added_stes)++;
	*last_ste += DR_STE_SIZE;

	dr_ste_v1_init(*last_ste,
		       DR_STE_V1_LU_TYPE_MATCH | DR_STE_V1_LU_TYPE_DONT_CARE,
		       0, gvmi);

	dr_ste_v1_init(*last_ste, MLX5DR_STE_LU_TYPE_DONT_CARE, 0, gvmi);
	dr_ste_v1_set_entry_type(*last_ste, DR_STE_V1_TYPE_MATCH);

	action = MLX5_ADDR_OF(ste_mask_and_match, *last_ste, action);
	memset(action, 0, MLX5_FLD_SZ_BYTES(ste_mask_and_match, action));
}

static void dr_ste_v1_set_actions_tx(struct mlx5dr_domain *dmn,
				     u8 *action_type_set,
				     u8 *last_ste,
				     struct mlx5dr_ste_actions_attr *attr,
				     u32 *added_stes)
{
	bool allow_encap = true;
	u8 action_sz;
	u8 *action;

	if (dr_ste_v1_get_entry_type(last_ste) == DR_STE_V1_TYPE_MATCH) {
		action_sz = DR_STE_ACTION_TRIPLE_SZ;
		action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
	} else {
		action_sz = DR_STE_ACTION_DOUBLE_SZ;
		action = MLX5_ADDR_OF(ste_match_bwc, last_ste, action);
	}

	if (action_type_set[DR_ACTION_TYP_CTR])
		dr_ste_v1_set_counter_id(last_ste, attr->ctr_id);

	if (action_type_set[DR_ACTION_TYP_MODIFY_HDR]) {
		dr_ste_v1_set_accelerated_rewrite_actions(last_ste, action,
							  attr->modify_actions,
							  attr->modify_index,
							  attr->args_index,
							  attr->single_modify_action);
		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
		allow_encap = false;
	}

	if (action_type_set[DR_ACTION_TYP_PUSH_VLAN]) {
		int i;

		for (i = 0; i < attr->vlans.count; i++) {
			if (action_sz < DR_STE_ACTION_DOUBLE_SZ || !allow_encap) {
				dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
				action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
				action_sz = DR_STE_ACTION_TRIPLE_SZ;
				allow_encap = true;
			}
			dr_ste_v1_set_tx_push_vlan(last_ste, action, attr->vlans.headers[i]);
			action_sz -= DR_STE_ACTION_DOUBLE_SZ;
			action += DR_STE_ACTION_DOUBLE_SZ;
		}
	}

	if (action_type_set[DR_ACTION_TYP_L2_TO_TNL_L2]) {
		if (!allow_encap || action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
			allow_encap = true;
		}
		dr_ste_v1_set_encap(last_ste, action,
				    attr->reformat.reformat_id,
				    attr->reformat.reformat_size);
		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
	} else if (action_type_set[DR_ACTION_TYP_L2_TO_TNL_L3]) {
		u8 *d_action;

		if (action_sz < DR_STE_ACTION_TRIPLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
		}
		d_action = action + DR_STE_ACTION_SINGLE_SZ;

		dr_ste_v1_set_encap_l3(last_ste,
				       action, d_action,
				       attr->reformat.reformat_id,
				       attr->reformat.reformat_size);
		action_sz -= DR_STE_ACTION_TRIPLE_SZ;
		action += DR_STE_ACTION_TRIPLE_SZ;
	} else if (action_type_set[DR_ACTION_TYP_INSERT_HDR]) {
		if (!allow_encap || action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
		}
		dr_ste_v1_set_insert_hdr(last_ste, action,
					 attr->reformat.reformat_id,
					 attr->reformat.reformat_param_0,
					 attr->reformat.reformat_param_1,
					 attr->reformat.reformat_size);
		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
	}

	if (action_type_set[DR_ACTION_TYP_ASO_FLOW_METER]) {
		if (action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
		}
		dr_ste_v1_set_aso_flow_meter(action,
					     attr->aso_flow_meter.obj_id,
					     attr->aso_flow_meter.offset,
					     attr->aso_flow_meter.dest_reg_id,
					     attr->aso_flow_meter.init_color);
		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
	}

	dr_ste_v1_set_hit_gvmi(last_ste, attr->hit_gvmi);
	dr_ste_v1_set_hit_addr(last_ste, attr->final_icm_addr, 1);
}

static void dr_ste_v1_set_actions_rx(struct mlx5dr_domain *dmn,
				     u8 *action_type_set,
				     u8 *last_ste,
				     struct mlx5dr_ste_actions_attr *attr,
				     u32 *added_stes)
{
	bool allow_modify_hdr = true;
	bool allow_encap = true;
	bool allow_ctr = true;
	u8 action_sz;
	u8 *action;

	if (dr_ste_v1_get_entry_type(last_ste) == DR_STE_V1_TYPE_MATCH) {
		action_sz = DR_STE_ACTION_TRIPLE_SZ;
		action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
	} else {
		action_sz = DR_STE_ACTION_DOUBLE_SZ;
		action = MLX5_ADDR_OF(ste_match_bwc, last_ste, action);
	}

	if (action_type_set[DR_ACTION_TYP_TNL_L3_TO_L2]) {
		dr_ste_v1_set_accelerated_rewrite_actions(last_ste, action,
							  attr->decap_actions,
							  attr->decap_index,
							  attr->decap_args_index,
							  NULL);
		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
		allow_modify_hdr = false;
		allow_encap = false;
		allow_ctr = false;
	} else if (action_type_set[DR_ACTION_TYP_TNL_L2_TO_L2]) {
		dr_ste_v1_set_rx_decap(last_ste, action);
		action_sz -= DR_STE_ACTION_SINGLE_SZ;
		action += DR_STE_ACTION_SINGLE_SZ;
		allow_modify_hdr = false;
		allow_encap = false;
		allow_ctr = false;
	}

	if (action_type_set[DR_ACTION_TYP_POP_VLAN]) {
		int i;

		for (i = 0; i < attr->vlans.count; i++) {
			if (action_sz < DR_STE_ACTION_SINGLE_SZ ||
			    !allow_modify_hdr) {
				dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
				action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
				action_sz = DR_STE_ACTION_TRIPLE_SZ;
				allow_modify_hdr = false;
				allow_encap = false;
				allow_ctr = false;
			}

			dr_ste_v1_set_rx_pop_vlan(last_ste, action);
			action_sz -= DR_STE_ACTION_SINGLE_SZ;
			action += DR_STE_ACTION_SINGLE_SZ;
		}
	}

	if (action_type_set[DR_ACTION_TYP_TAG]) {
		if (action_sz < DR_STE_ACTION_SINGLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
			allow_modify_hdr = true;
			allow_encap = true;
			allow_ctr = true;
		}
		dr_ste_v1_set_rx_flow_tag(action, attr->flow_tag);
		action_sz -= DR_STE_ACTION_SINGLE_SZ;
		action += DR_STE_ACTION_SINGLE_SZ;
	}

	if (action_type_set[DR_ACTION_TYP_MODIFY_HDR]) {
		/* Modify header and decapsulation must use different STEs */
		if (!allow_modify_hdr || action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
			allow_modify_hdr = true;
			allow_ctr = true;
		}
		dr_ste_v1_set_accelerated_rewrite_actions(last_ste, action,
							  attr->modify_actions,
							  attr->modify_index,
							  attr->args_index,
							  attr->single_modify_action);
		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
		allow_encap = false;
	}

	if (action_type_set[DR_ACTION_TYP_CTR]) {
		/* Counter action set after decap and before insert_hdr to
		 * exclude decaped / encaped header respectively.
		 */
		if (!allow_ctr) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
			allow_modify_hdr = true;
			allow_encap = false;
			allow_ctr = false;
		}
		dr_ste_v1_set_counter_id(last_ste, attr->ctr_id);
	}

	if (action_type_set[DR_ACTION_TYP_L2_TO_TNL_L2]) {
		if (action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
		}
		dr_ste_v1_set_encap(last_ste, action,
				    attr->reformat.reformat_id,
				    attr->reformat.reformat_size);
		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
		allow_modify_hdr = false;
	} else if (action_type_set[DR_ACTION_TYP_L2_TO_TNL_L3]) {
		u8 *d_action;

		if (action_sz < DR_STE_ACTION_TRIPLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
		}

		d_action = action + DR_STE_ACTION_SINGLE_SZ;

		dr_ste_v1_set_encap_l3(last_ste,
				       action, d_action,
				       attr->reformat.reformat_id,
				       attr->reformat.reformat_size);
		action_sz -= DR_STE_ACTION_TRIPLE_SZ;
		allow_modify_hdr = false;
	} else if (action_type_set[DR_ACTION_TYP_INSERT_HDR]) {
		/* Modify header, decap, and encap must use different STEs */
		if (!allow_encap || action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
		}
		dr_ste_v1_set_insert_hdr(last_ste, action,
					 attr->reformat.reformat_id,
					 attr->reformat.reformat_param_0,
					 attr->reformat.reformat_param_1,
					 attr->reformat.reformat_size);
		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
		allow_encap = false;
		allow_modify_hdr = false;
	}

	if (action_type_set[DR_ACTION_TYP_ASO_FLOW_METER]) {
		if (action_sz < DR_STE_ACTION_DOUBLE_SZ) {
			dr_ste_v1_arr_init_next_match(&last_ste, added_stes, attr->gvmi);
			action = MLX5_ADDR_OF(ste_mask_and_match, last_ste, action);
			action_sz = DR_STE_ACTION_TRIPLE_SZ;
		}
		dr_ste_v1_set_aso_flow_meter(action,
					     attr->aso_flow_meter.obj_id,
					     attr->aso_flow_meter.offset,
					     attr->aso_flow_meter.dest_reg_id,
					     attr->aso_flow_meter.init_color);
		action_sz -= DR_STE_ACTION_DOUBLE_SZ;
		action += DR_STE_ACTION_DOUBLE_SZ;
	}

	dr_ste_v1_set_hit_gvmi(last_ste, attr->hit_gvmi);
	dr_ste_v1_set_hit_addr(last_ste, attr->final_icm_addr, 1);
}

#define DR_MODIFY_HEADER_QW_OFFSET (0x20)

static void dr_ste_v1_set_action_set(u8 *d_action,
				     u8 hw_field,
				     u8 shifter,
				     u8 length,
				     u32 data)
{
	shifter += DR_MODIFY_HEADER_QW_OFFSET;
	MLX5_SET(ste_double_action_set, d_action, action_id, DR_STE_V1_ACTION_ID_SET);
	MLX5_SET(ste_double_action_set, d_action, destination_dw_offset, hw_field);
	MLX5_SET(ste_double_action_set, d_action, destination_left_shifter, shifter);
	MLX5_SET(ste_double_action_set, d_action, destination_length, length);
	MLX5_SET(ste_double_action_set, d_action, inline_data, data);
}

static void dr_ste_v1_set_action_add(u8 *d_action,
				     u8 hw_field,
				     u8 shifter,
				     u8 length,
				     u32 data)
{
	shifter += DR_MODIFY_HEADER_QW_OFFSET;
	MLX5_SET(ste_double_action_add, d_action, action_id, DR_STE_V1_ACTION_ID_ADD);
	MLX5_SET(ste_double_action_add, d_action, destination_dw_offset, hw_field);
	MLX5_SET(ste_double_action_add, d_action, destination_left_shifter, shifter);
	MLX5_SET(ste_double_action_add, d_action, destination_length, length);
	MLX5_SET(ste_double_action_add, d_action, add_value, data);
}

static void dr_ste_v1_set_action_copy(u8 *d_action,
				      u8 dst_hw_field,
				      u8 dst_shifter,
				      u8 dst_len,
				      u8 src_hw_field,
				      u8 src_shifter)
{
	dst_shifter += DR_MODIFY_HEADER_QW_OFFSET;
	src_shifter += DR_MODIFY_HEADER_QW_OFFSET;
	MLX5_SET(ste_double_action_copy, d_action, action_id, DR_STE_V1_ACTION_ID_COPY);
	MLX5_SET(ste_double_action_copy, d_action, destination_dw_offset, dst_hw_field);
	MLX5_SET(ste_double_action_copy, d_action, destination_left_shifter, dst_shifter);
	MLX5_SET(ste_double_action_copy, d_action, destination_length, dst_len);
	MLX5_SET(ste_double_action_copy, d_action, source_dw_offset, src_hw_field);
	MLX5_SET(ste_double_action_copy, d_action, source_right_shifter, src_shifter);
}

#define DR_STE_DECAP_L3_ACTION_NUM	8
#define DR_STE_L2_HDR_MAX_SZ		20

static int dr_ste_v1_set_action_decap_l3_list(void *data,
					      u32 data_sz,
					      u8 *hw_action,
					      u32 hw_action_sz,
					      u16 *used_hw_action_num)
{
	u8 padded_data[DR_STE_L2_HDR_MAX_SZ] = {};
	void *data_ptr = padded_data;
	u16 used_actions = 0;
	u32 inline_data_sz;
	u32 i;

	if (hw_action_sz / DR_STE_ACTION_DOUBLE_SZ < DR_STE_DECAP_L3_ACTION_NUM)
		return -EINVAL;

	inline_data_sz =
		MLX5_FLD_SZ_BYTES(ste_double_action_insert_with_inline, inline_data);

	/* Add an alignment padding  */
	memcpy(padded_data + data_sz % inline_data_sz, data, data_sz);

	/* Remove L2L3 outer headers */
	MLX5_SET(ste_single_action_remove_header, hw_action, action_id,
		 DR_STE_V1_ACTION_ID_REMOVE_HEADER_TO_HEADER);
	MLX5_SET(ste_single_action_remove_header, hw_action, decap, 1);
	MLX5_SET(ste_single_action_remove_header, hw_action, vni_to_cqe, 1);
	MLX5_SET(ste_single_action_remove_header, hw_action, end_anchor,
		 DR_STE_HEADER_ANCHOR_INNER_IPV6_IPV4);
	hw_action += DR_STE_ACTION_DOUBLE_SZ;
	used_actions++; /* Remove and NOP are a single double action */

	/* Point to the last dword of the header */
	data_ptr += (data_sz / inline_data_sz) * inline_data_sz;

	/* Add the new header using inline action 4Byte at a time, the header
	 * is added in reversed order to the beginning of the packet to avoid
	 * incorrect parsing by the HW. Since header is 14B or 18B an extra
	 * two bytes are padded and later removed.
	 */
	for (i = 0; i < data_sz / inline_data_sz + 1; i++) {
		void *addr_inline;

		MLX5_SET(ste_double_action_insert_with_inline, hw_action, action_id,
			 DR_STE_V1_ACTION_ID_INSERT_INLINE);
		/* The hardware expects here offset to words (2 byte) */
		MLX5_SET(ste_double_action_insert_with_inline, hw_action, start_offset, 0);

		/* Copy byte byte in order to skip endianness problem */
		addr_inline = MLX5_ADDR_OF(ste_double_action_insert_with_inline,
					   hw_action, inline_data);
		memcpy(addr_inline, data_ptr - i * inline_data_sz, inline_data_sz);
		hw_action += DR_STE_ACTION_DOUBLE_SZ;
		used_actions++;
	}

	/* Remove first 2 extra bytes */
	MLX5_SET(ste_single_action_remove_header_size, hw_action, action_id,
		 DR_STE_V1_ACTION_ID_REMOVE_BY_SIZE);
	MLX5_SET(ste_single_action_remove_header_size, hw_action, start_offset, 0);
	/* The hardware expects here size in words (2 byte) */
	MLX5_SET(ste_single_action_remove_header_size, hw_action, remove_size, 1);
	used_actions++;

	*used_hw_action_num = used_actions;

	return 0;
}

static void dr_ste_v1_build_eth_l2_src_dst_bit_mask(struct mlx5dr_match_param *value,
						    bool inner, u8 *bit_mask)
{
	struct mlx5dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_src_dst_v1, bit_mask, dmac_47_16, mask, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, bit_mask, dmac_15_0, mask, dmac_15_0);

	DR_STE_SET_TAG(eth_l2_src_dst_v1, bit_mask, smac_47_16, mask, smac_47_16);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, bit_mask, smac_15_0, mask, smac_15_0);

	DR_STE_SET_TAG(eth_l2_src_dst_v1, bit_mask, first_vlan_id, mask, first_vid);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, bit_mask, first_cfi, mask, first_cfi);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, bit_mask, first_priority, mask, first_prio);
	DR_STE_SET_ONES(eth_l2_src_dst_v1, bit_mask, l3_type, mask, ip_version);

	if (mask->cvlan_tag) {
		MLX5_SET(ste_eth_l2_src_dst_v1, bit_mask, first_vlan_qualifier, -1);
		mask->cvlan_tag = 0;
	} else if (mask->svlan_tag) {
		MLX5_SET(ste_eth_l2_src_dst_v1, bit_mask, first_vlan_qualifier, -1);
		mask->svlan_tag = 0;
	}
}

static int dr_ste_v1_build_eth_l2_src_dst_tag(struct mlx5dr_match_param *value,
					      struct mlx5dr_ste_build *sb,
					      u8 *tag)
{
	struct mlx5dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_src_dst_v1, tag, dmac_47_16, spec, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, tag, dmac_15_0, spec, dmac_15_0);

	DR_STE_SET_TAG(eth_l2_src_dst_v1, tag, smac_47_16, spec, smac_47_16);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, tag, smac_15_0, spec, smac_15_0);

	if (spec->ip_version) {
		if (spec->ip_version == IP_VERSION_IPV4) {
			MLX5_SET(ste_eth_l2_src_dst_v1, tag, l3_type, STE_IPV4);
			spec->ip_version = 0;
		} else if (spec->ip_version == IP_VERSION_IPV6) {
			MLX5_SET(ste_eth_l2_src_dst_v1, tag, l3_type, STE_IPV6);
			spec->ip_version = 0;
		} else {
			pr_info("Unsupported ip_version value\n");
			return -EINVAL;
		}
	}

	DR_STE_SET_TAG(eth_l2_src_dst_v1, tag, first_vlan_id, spec, first_vid);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, tag, first_cfi, spec, first_cfi);
	DR_STE_SET_TAG(eth_l2_src_dst_v1, tag, first_priority, spec, first_prio);

	if (spec->cvlan_tag) {
		MLX5_SET(ste_eth_l2_src_dst_v1, tag, first_vlan_qualifier, DR_STE_CVLAN);
		spec->cvlan_tag = 0;
	} else if (spec->svlan_tag) {
		MLX5_SET(ste_eth_l2_src_dst_v1, tag, first_vlan_qualifier, DR_STE_SVLAN);
		spec->svlan_tag = 0;
	}
	return 0;
}

static void dr_ste_v1_build_eth_l2_src_dst_init(struct mlx5dr_ste_build *sb,
						struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_eth_l2_src_dst_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(ETHL2_SRC_DST, sb->inner);
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l2_src_dst_tag;
}

static int dr_ste_v1_build_eth_l3_ipv6_dst_tag(struct mlx5dr_match_param *value,
					       struct mlx5dr_ste_build *sb,
					       u8 *tag)
{
	struct mlx5dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l3_ipv6_dst, tag, dst_ip_127_96, spec, dst_ip_127_96);
	DR_STE_SET_TAG(eth_l3_ipv6_dst, tag, dst_ip_95_64, spec, dst_ip_95_64);
	DR_STE_SET_TAG(eth_l3_ipv6_dst, tag, dst_ip_63_32, spec, dst_ip_63_32);
	DR_STE_SET_TAG(eth_l3_ipv6_dst, tag, dst_ip_31_0, spec, dst_ip_31_0);

	return 0;
}

static void dr_ste_v1_build_eth_l3_ipv6_dst_init(struct mlx5dr_ste_build *sb,
						 struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_eth_l3_ipv6_dst_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(IPV6_DES, sb->inner);
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l3_ipv6_dst_tag;
}

static int dr_ste_v1_build_eth_l3_ipv6_src_tag(struct mlx5dr_match_param *value,
					       struct mlx5dr_ste_build *sb,
					       u8 *tag)
{
	struct mlx5dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l3_ipv6_src, tag, src_ip_127_96, spec, src_ip_127_96);
	DR_STE_SET_TAG(eth_l3_ipv6_src, tag, src_ip_95_64, spec, src_ip_95_64);
	DR_STE_SET_TAG(eth_l3_ipv6_src, tag, src_ip_63_32, spec, src_ip_63_32);
	DR_STE_SET_TAG(eth_l3_ipv6_src, tag, src_ip_31_0, spec, src_ip_31_0);

	return 0;
}

static void dr_ste_v1_build_eth_l3_ipv6_src_init(struct mlx5dr_ste_build *sb,
						 struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_eth_l3_ipv6_src_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(IPV6_SRC, sb->inner);
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l3_ipv6_src_tag;
}

static int dr_ste_v1_build_eth_l3_ipv4_5_tuple_tag(struct mlx5dr_match_param *value,
						   struct mlx5dr_ste_build *sb,
						   u8 *tag)
{
	struct mlx5dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, destination_address, spec, dst_ip_31_0);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, source_address, spec, src_ip_31_0);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, destination_port, spec, tcp_dport);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, destination_port, spec, udp_dport);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, source_port, spec, tcp_sport);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, source_port, spec, udp_sport);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, protocol, spec, ip_protocol);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, fragmented, spec, frag);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, dscp, spec, ip_dscp);
	DR_STE_SET_TAG(eth_l3_ipv4_5_tuple_v1, tag, ecn, spec, ip_ecn);

	if (spec->tcp_flags) {
		DR_STE_SET_TCP_FLAGS(eth_l3_ipv4_5_tuple_v1, tag, spec);
		spec->tcp_flags = 0;
	}

	return 0;
}

static void dr_ste_v1_build_eth_l3_ipv4_5_tuple_init(struct mlx5dr_ste_build *sb,
						     struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_eth_l3_ipv4_5_tuple_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(ETHL3_IPV4_5_TUPLE, sb->inner);
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l3_ipv4_5_tuple_tag;
}

static void dr_ste_v1_build_eth_l2_src_or_dst_bit_mask(struct mlx5dr_match_param *value,
						       bool inner, u8 *bit_mask)
{
	struct mlx5dr_match_spec *mask = inner ? &value->inner : &value->outer;
	struct mlx5dr_match_misc *misc_mask = &value->misc;

	DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, first_vlan_id, mask, first_vid);
	DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, first_cfi, mask, first_cfi);
	DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, first_priority, mask, first_prio);
	DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, ip_fragmented, mask, frag); // ?
	DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, l3_ethertype, mask, ethertype); // ?
	DR_STE_SET_ONES(eth_l2_src_v1, bit_mask, l3_type, mask, ip_version);

	if (mask->svlan_tag || mask->cvlan_tag) {
		MLX5_SET(ste_eth_l2_src_v1, bit_mask, first_vlan_qualifier, -1);
		mask->cvlan_tag = 0;
		mask->svlan_tag = 0;
	}

	if (inner) {
		if (misc_mask->inner_second_cvlan_tag ||
		    misc_mask->inner_second_svlan_tag) {
			MLX5_SET(ste_eth_l2_src_v1, bit_mask, second_vlan_qualifier, -1);
			misc_mask->inner_second_cvlan_tag = 0;
			misc_mask->inner_second_svlan_tag = 0;
		}

		DR_STE_SET_TAG(eth_l2_src_v1, bit_mask,
			       second_vlan_id, misc_mask, inner_second_vid);
		DR_STE_SET_TAG(eth_l2_src_v1, bit_mask,
			       second_cfi, misc_mask, inner_second_cfi);
		DR_STE_SET_TAG(eth_l2_src_v1, bit_mask,
			       second_priority, misc_mask, inner_second_prio);
	} else {
		if (misc_mask->outer_second_cvlan_tag ||
		    misc_mask->outer_second_svlan_tag) {
			MLX5_SET(ste_eth_l2_src_v1, bit_mask, second_vlan_qualifier, -1);
			misc_mask->outer_second_cvlan_tag = 0;
			misc_mask->outer_second_svlan_tag = 0;
		}

		DR_STE_SET_TAG(eth_l2_src_v1, bit_mask,
			       second_vlan_id, misc_mask, outer_second_vid);
		DR_STE_SET_TAG(eth_l2_src_v1, bit_mask,
			       second_cfi, misc_mask, outer_second_cfi);
		DR_STE_SET_TAG(eth_l2_src_v1, bit_mask,
			       second_priority, misc_mask, outer_second_prio);
	}
}

static int dr_ste_v1_build_eth_l2_src_or_dst_tag(struct mlx5dr_match_param *value,
						 bool inner, u8 *tag)
{
	struct mlx5dr_match_spec *spec = inner ? &value->inner : &value->outer;
	struct mlx5dr_match_misc *misc_spec = &value->misc;

	DR_STE_SET_TAG(eth_l2_src_v1, tag, first_vlan_id, spec, first_vid);
	DR_STE_SET_TAG(eth_l2_src_v1, tag, first_cfi, spec, first_cfi);
	DR_STE_SET_TAG(eth_l2_src_v1, tag, first_priority, spec, first_prio);
	DR_STE_SET_TAG(eth_l2_src_v1, tag, ip_fragmented, spec, frag);
	DR_STE_SET_TAG(eth_l2_src_v1, tag, l3_ethertype, spec, ethertype);

	if (spec->ip_version) {
		if (spec->ip_version == IP_VERSION_IPV4) {
			MLX5_SET(ste_eth_l2_src_v1, tag, l3_type, STE_IPV4);
			spec->ip_version = 0;
		} else if (spec->ip_version == IP_VERSION_IPV6) {
			MLX5_SET(ste_eth_l2_src_v1, tag, l3_type, STE_IPV6);
			spec->ip_version = 0;
		} else {
			pr_info("Unsupported ip_version value\n");
			return -EINVAL;
		}
	}

	if (spec->cvlan_tag) {
		MLX5_SET(ste_eth_l2_src_v1, tag, first_vlan_qualifier, DR_STE_CVLAN);
		spec->cvlan_tag = 0;
	} else if (spec->svlan_tag) {
		MLX5_SET(ste_eth_l2_src_v1, tag, first_vlan_qualifier, DR_STE_SVLAN);
		spec->svlan_tag = 0;
	}

	if (inner) {
		if (misc_spec->inner_second_cvlan_tag) {
			MLX5_SET(ste_eth_l2_src_v1, tag, second_vlan_qualifier, DR_STE_CVLAN);
			misc_spec->inner_second_cvlan_tag = 0;
		} else if (misc_spec->inner_second_svlan_tag) {
			MLX5_SET(ste_eth_l2_src_v1, tag, second_vlan_qualifier, DR_STE_SVLAN);
			misc_spec->inner_second_svlan_tag = 0;
		}

		DR_STE_SET_TAG(eth_l2_src_v1, tag, second_vlan_id, misc_spec, inner_second_vid);
		DR_STE_SET_TAG(eth_l2_src_v1, tag, second_cfi, misc_spec, inner_second_cfi);
		DR_STE_SET_TAG(eth_l2_src_v1, tag, second_priority, misc_spec, inner_second_prio);
	} else {
		if (misc_spec->outer_second_cvlan_tag) {
			MLX5_SET(ste_eth_l2_src_v1, tag, second_vlan_qualifier, DR_STE_CVLAN);
			misc_spec->outer_second_cvlan_tag = 0;
		} else if (misc_spec->outer_second_svlan_tag) {
			MLX5_SET(ste_eth_l2_src_v1, tag, second_vlan_qualifier, DR_STE_SVLAN);
			misc_spec->outer_second_svlan_tag = 0;
		}
		DR_STE_SET_TAG(eth_l2_src_v1, tag, second_vlan_id, misc_spec, outer_second_vid);
		DR_STE_SET_TAG(eth_l2_src_v1, tag, second_cfi, misc_spec, outer_second_cfi);
		DR_STE_SET_TAG(eth_l2_src_v1, tag, second_priority, misc_spec, outer_second_prio);
	}

	return 0;
}

static void dr_ste_v1_build_eth_l2_src_bit_mask(struct mlx5dr_match_param *value,
						bool inner, u8 *bit_mask)
{
	struct mlx5dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, smac_47_16, mask, smac_47_16);
	DR_STE_SET_TAG(eth_l2_src_v1, bit_mask, smac_15_0, mask, smac_15_0);

	dr_ste_v1_build_eth_l2_src_or_dst_bit_mask(value, inner, bit_mask);
}

static int dr_ste_v1_build_eth_l2_src_tag(struct mlx5dr_match_param *value,
					  struct mlx5dr_ste_build *sb,
					  u8 *tag)
{
	struct mlx5dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_src_v1, tag, smac_47_16, spec, smac_47_16);
	DR_STE_SET_TAG(eth_l2_src_v1, tag, smac_15_0, spec, smac_15_0);

	return dr_ste_v1_build_eth_l2_src_or_dst_tag(value, sb->inner, tag);
}

static void dr_ste_v1_build_eth_l2_src_init(struct mlx5dr_ste_build *sb,
					    struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_eth_l2_src_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(ETHL2_SRC, sb->inner);
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l2_src_tag;
}

static void dr_ste_v1_build_eth_l2_dst_bit_mask(struct mlx5dr_match_param *value,
						bool inner, u8 *bit_mask)
{
	struct mlx5dr_match_spec *mask = inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_dst_v1, bit_mask, dmac_47_16, mask, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_dst_v1, bit_mask, dmac_15_0, mask, dmac_15_0);

	dr_ste_v1_build_eth_l2_src_or_dst_bit_mask(value, inner, bit_mask);
}

static int dr_ste_v1_build_eth_l2_dst_tag(struct mlx5dr_match_param *value,
					  struct mlx5dr_ste_build *sb,
					  u8 *tag)
{
	struct mlx5dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l2_dst_v1, tag, dmac_47_16, spec, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_dst_v1, tag, dmac_15_0, spec, dmac_15_0);

	return dr_ste_v1_build_eth_l2_src_or_dst_tag(value, sb->inner, tag);
}

static void dr_ste_v1_build_eth_l2_dst_init(struct mlx5dr_ste_build *sb,
					    struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_eth_l2_dst_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(ETHL2, sb->inner);
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l2_dst_tag;
}

static void dr_ste_v1_build_eth_l2_tnl_bit_mask(struct mlx5dr_match_param *value,
						bool inner, u8 *bit_mask)
{
	struct mlx5dr_match_spec *mask = inner ? &value->inner : &value->outer;
	struct mlx5dr_match_misc *misc = &value->misc;

	DR_STE_SET_TAG(eth_l2_tnl_v1, bit_mask, dmac_47_16, mask, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_tnl_v1, bit_mask, dmac_15_0, mask, dmac_15_0);
	DR_STE_SET_TAG(eth_l2_tnl_v1, bit_mask, first_vlan_id, mask, first_vid);
	DR_STE_SET_TAG(eth_l2_tnl_v1, bit_mask, first_cfi, mask, first_cfi);
	DR_STE_SET_TAG(eth_l2_tnl_v1, bit_mask, first_priority, mask, first_prio);
	DR_STE_SET_TAG(eth_l2_tnl_v1, bit_mask, ip_fragmented, mask, frag);
	DR_STE_SET_TAG(eth_l2_tnl_v1, bit_mask, l3_ethertype, mask, ethertype);
	DR_STE_SET_ONES(eth_l2_tnl_v1, bit_mask, l3_type, mask, ip_version);

	if (misc->vxlan_vni) {
		MLX5_SET(ste_eth_l2_tnl_v1, bit_mask,
			 l2_tunneling_network_id, (misc->vxlan_vni << 8));
		misc->vxlan_vni = 0;
	}

	if (mask->svlan_tag || mask->cvlan_tag) {
		MLX5_SET(ste_eth_l2_tnl_v1, bit_mask, first_vlan_qualifier, -1);
		mask->cvlan_tag = 0;
		mask->svlan_tag = 0;
	}
}

static int dr_ste_v1_build_eth_l2_tnl_tag(struct mlx5dr_match_param *value,
					  struct mlx5dr_ste_build *sb,
					  u8 *tag)
{
	struct mlx5dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	struct mlx5dr_match_misc *misc = &value->misc;

	DR_STE_SET_TAG(eth_l2_tnl_v1, tag, dmac_47_16, spec, dmac_47_16);
	DR_STE_SET_TAG(eth_l2_tnl_v1, tag, dmac_15_0, spec, dmac_15_0);
	DR_STE_SET_TAG(eth_l2_tnl_v1, tag, first_vlan_id, spec, first_vid);
	DR_STE_SET_TAG(eth_l2_tnl_v1, tag, first_cfi, spec, first_cfi);
	DR_STE_SET_TAG(eth_l2_tnl_v1, tag, ip_fragmented, spec, frag);
	DR_STE_SET_TAG(eth_l2_tnl_v1, tag, first_priority, spec, first_prio);
	DR_STE_SET_TAG(eth_l2_tnl_v1, tag, l3_ethertype, spec, ethertype);

	if (misc->vxlan_vni) {
		MLX5_SET(ste_eth_l2_tnl_v1, tag, l2_tunneling_network_id,
			 (misc->vxlan_vni << 8));
		misc->vxlan_vni = 0;
	}

	if (spec->cvlan_tag) {
		MLX5_SET(ste_eth_l2_tnl_v1, tag, first_vlan_qualifier, DR_STE_CVLAN);
		spec->cvlan_tag = 0;
	} else if (spec->svlan_tag) {
		MLX5_SET(ste_eth_l2_tnl_v1, tag, first_vlan_qualifier, DR_STE_SVLAN);
		spec->svlan_tag = 0;
	}

	if (spec->ip_version) {
		if (spec->ip_version == IP_VERSION_IPV4) {
			MLX5_SET(ste_eth_l2_tnl_v1, tag, l3_type, STE_IPV4);
			spec->ip_version = 0;
		} else if (spec->ip_version == IP_VERSION_IPV6) {
			MLX5_SET(ste_eth_l2_tnl_v1, tag, l3_type, STE_IPV6);
			spec->ip_version = 0;
		} else {
			return -EINVAL;
		}
	}

	return 0;
}

static void dr_ste_v1_build_eth_l2_tnl_init(struct mlx5dr_ste_build *sb,
					    struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_eth_l2_tnl_bit_mask(mask, sb->inner, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_ETHL2_TNL;
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l2_tnl_tag;
}

static int dr_ste_v1_build_eth_l3_ipv4_misc_tag(struct mlx5dr_match_param *value,
						struct mlx5dr_ste_build *sb,
						u8 *tag)
{
	struct mlx5dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;

	DR_STE_SET_TAG(eth_l3_ipv4_misc_v1, tag, time_to_live, spec, ttl_hoplimit);

	return 0;
}

static void dr_ste_v1_build_eth_l3_ipv4_misc_init(struct mlx5dr_ste_build *sb,
						  struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_eth_l3_ipv4_misc_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(ETHL3_IPV4_MISC, sb->inner);
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l3_ipv4_misc_tag;
}

static int dr_ste_v1_build_eth_ipv6_l3_l4_tag(struct mlx5dr_match_param *value,
					      struct mlx5dr_ste_build *sb,
					      u8 *tag)
{
	struct mlx5dr_match_spec *spec = sb->inner ? &value->inner : &value->outer;
	struct mlx5dr_match_misc *misc = &value->misc;

	DR_STE_SET_TAG(eth_l4_v1, tag, dst_port, spec, tcp_dport);
	DR_STE_SET_TAG(eth_l4_v1, tag, src_port, spec, tcp_sport);
	DR_STE_SET_TAG(eth_l4_v1, tag, dst_port, spec, udp_dport);
	DR_STE_SET_TAG(eth_l4_v1, tag, src_port, spec, udp_sport);
	DR_STE_SET_TAG(eth_l4_v1, tag, protocol, spec, ip_protocol);
	DR_STE_SET_TAG(eth_l4_v1, tag, fragmented, spec, frag);
	DR_STE_SET_TAG(eth_l4_v1, tag, dscp, spec, ip_dscp);
	DR_STE_SET_TAG(eth_l4_v1, tag, ecn, spec, ip_ecn);
	DR_STE_SET_TAG(eth_l4_v1, tag, ipv6_hop_limit, spec, ttl_hoplimit);

	if (sb->inner)
		DR_STE_SET_TAG(eth_l4_v1, tag, flow_label, misc, inner_ipv6_flow_label);
	else
		DR_STE_SET_TAG(eth_l4_v1, tag, flow_label, misc, outer_ipv6_flow_label);

	if (spec->tcp_flags) {
		DR_STE_SET_TCP_FLAGS(eth_l4_v1, tag, spec);
		spec->tcp_flags = 0;
	}

	return 0;
}

static void dr_ste_v1_build_eth_ipv6_l3_l4_init(struct mlx5dr_ste_build *sb,
						struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_eth_ipv6_l3_l4_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(ETHL4, sb->inner);
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_ipv6_l3_l4_tag;
}

static int dr_ste_v1_build_mpls_tag(struct mlx5dr_match_param *value,
				    struct mlx5dr_ste_build *sb,
				    u8 *tag)
{
	struct mlx5dr_match_misc2 *misc2 = &value->misc2;

	if (sb->inner)
		DR_STE_SET_MPLS(mpls_v1, misc2, inner, tag);
	else
		DR_STE_SET_MPLS(mpls_v1, misc2, outer, tag);

	return 0;
}

static void dr_ste_v1_build_mpls_init(struct mlx5dr_ste_build *sb,
				      struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_mpls_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_CALC_DFNR_TYPE(MPLS, sb->inner);
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_mpls_tag;
}

static int dr_ste_v1_build_tnl_gre_tag(struct mlx5dr_match_param *value,
				       struct mlx5dr_ste_build *sb,
				       u8 *tag)
{
	struct  mlx5dr_match_misc *misc = &value->misc;

	DR_STE_SET_TAG(gre_v1, tag, gre_protocol, misc, gre_protocol);
	DR_STE_SET_TAG(gre_v1, tag, gre_k_present, misc, gre_k_present);
	DR_STE_SET_TAG(gre_v1, tag, gre_key_h, misc, gre_key_h);
	DR_STE_SET_TAG(gre_v1, tag, gre_key_l, misc, gre_key_l);

	DR_STE_SET_TAG(gre_v1, tag, gre_c_present, misc, gre_c_present);
	DR_STE_SET_TAG(gre_v1, tag, gre_s_present, misc, gre_s_present);

	return 0;
}

static void dr_ste_v1_build_tnl_gre_init(struct mlx5dr_ste_build *sb,
					 struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_tnl_gre_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_GRE;
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_tnl_gre_tag;
}

static int dr_ste_v1_build_tnl_mpls_over_udp_tag(struct mlx5dr_match_param *value,
						 struct mlx5dr_ste_build *sb,
						 u8 *tag)
{
	struct mlx5dr_match_misc2 *misc2 = &value->misc2;
	u8 *parser_ptr;
	u8 parser_id;
	u32 mpls_hdr;

	mpls_hdr = misc2->outer_first_mpls_over_udp_label << HDR_MPLS_OFFSET_LABEL;
	misc2->outer_first_mpls_over_udp_label = 0;
	mpls_hdr |= misc2->outer_first_mpls_over_udp_exp << HDR_MPLS_OFFSET_EXP;
	misc2->outer_first_mpls_over_udp_exp = 0;
	mpls_hdr |= misc2->outer_first_mpls_over_udp_s_bos << HDR_MPLS_OFFSET_S_BOS;
	misc2->outer_first_mpls_over_udp_s_bos = 0;
	mpls_hdr |= misc2->outer_first_mpls_over_udp_ttl << HDR_MPLS_OFFSET_TTL;
	misc2->outer_first_mpls_over_udp_ttl = 0;

	parser_id = sb->caps->flex_parser_id_mpls_over_udp;
	parser_ptr = dr_ste_calc_flex_parser_offset(tag, parser_id);
	*(__be32 *)parser_ptr = cpu_to_be32(mpls_hdr);

	return 0;
}

static void dr_ste_v1_build_tnl_mpls_over_udp_init(struct mlx5dr_ste_build *sb,
						   struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_tnl_mpls_over_udp_tag(mask, sb, sb->bit_mask);

	/* STEs with lookup type FLEX_PARSER_{0/1} includes
	 * flex parsers_{0-3}/{4-7} respectively.
	 */
	sb->lu_type = sb->caps->flex_parser_id_mpls_over_udp > DR_STE_MAX_FLEX_0_ID ?
		      DR_STE_V1_LU_TYPE_FLEX_PARSER_1 :
		      DR_STE_V1_LU_TYPE_FLEX_PARSER_0;

	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_tnl_mpls_over_udp_tag;
}

static int dr_ste_v1_build_tnl_mpls_over_gre_tag(struct mlx5dr_match_param *value,
						 struct mlx5dr_ste_build *sb,
						 u8 *tag)
{
	struct mlx5dr_match_misc2 *misc2 = &value->misc2;
	u8 *parser_ptr;
	u8 parser_id;
	u32 mpls_hdr;

	mpls_hdr = misc2->outer_first_mpls_over_gre_label << HDR_MPLS_OFFSET_LABEL;
	misc2->outer_first_mpls_over_gre_label = 0;
	mpls_hdr |= misc2->outer_first_mpls_over_gre_exp << HDR_MPLS_OFFSET_EXP;
	misc2->outer_first_mpls_over_gre_exp = 0;
	mpls_hdr |= misc2->outer_first_mpls_over_gre_s_bos << HDR_MPLS_OFFSET_S_BOS;
	misc2->outer_first_mpls_over_gre_s_bos = 0;
	mpls_hdr |= misc2->outer_first_mpls_over_gre_ttl << HDR_MPLS_OFFSET_TTL;
	misc2->outer_first_mpls_over_gre_ttl = 0;

	parser_id = sb->caps->flex_parser_id_mpls_over_gre;
	parser_ptr = dr_ste_calc_flex_parser_offset(tag, parser_id);
	*(__be32 *)parser_ptr = cpu_to_be32(mpls_hdr);

	return 0;
}

static void dr_ste_v1_build_tnl_mpls_over_gre_init(struct mlx5dr_ste_build *sb,
						   struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_tnl_mpls_over_gre_tag(mask, sb, sb->bit_mask);

	/* STEs with lookup type FLEX_PARSER_{0/1} includes
	 * flex parsers_{0-3}/{4-7} respectively.
	 */
	sb->lu_type = sb->caps->flex_parser_id_mpls_over_gre > DR_STE_MAX_FLEX_0_ID ?
		      DR_STE_V1_LU_TYPE_FLEX_PARSER_1 :
		      DR_STE_V1_LU_TYPE_FLEX_PARSER_0;

	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_tnl_mpls_over_gre_tag;
}

static int dr_ste_v1_build_icmp_tag(struct mlx5dr_match_param *value,
				    struct mlx5dr_ste_build *sb,
				    u8 *tag)
{
	struct mlx5dr_match_misc3 *misc3 = &value->misc3;
	bool is_ipv4 = DR_MASK_IS_ICMPV4_SET(misc3);
	u32 *icmp_header_data;
	u8 *icmp_type;
	u8 *icmp_code;

	if (is_ipv4) {
		icmp_header_data	= &misc3->icmpv4_header_data;
		icmp_type		= &misc3->icmpv4_type;
		icmp_code		= &misc3->icmpv4_code;
	} else {
		icmp_header_data	= &misc3->icmpv6_header_data;
		icmp_type		= &misc3->icmpv6_type;
		icmp_code		= &misc3->icmpv6_code;
	}

	MLX5_SET(ste_icmp_v1, tag, icmp_header_data, *icmp_header_data);
	MLX5_SET(ste_icmp_v1, tag, icmp_type, *icmp_type);
	MLX5_SET(ste_icmp_v1, tag, icmp_code, *icmp_code);

	*icmp_header_data = 0;
	*icmp_type = 0;
	*icmp_code = 0;

	return 0;
}

static void dr_ste_v1_build_icmp_init(struct mlx5dr_ste_build *sb,
				      struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_icmp_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_ETHL4_MISC_O;
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_icmp_tag;
}

static int dr_ste_v1_build_general_purpose_tag(struct mlx5dr_match_param *value,
					       struct mlx5dr_ste_build *sb,
					       u8 *tag)
{
	struct mlx5dr_match_misc2 *misc2 = &value->misc2;

	DR_STE_SET_TAG(general_purpose, tag, general_purpose_lookup_field,
		       misc2, metadata_reg_a);

	return 0;
}

static void dr_ste_v1_build_general_purpose_init(struct mlx5dr_ste_build *sb,
						 struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_general_purpose_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_GENERAL_PURPOSE;
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_general_purpose_tag;
}

static int dr_ste_v1_build_eth_l4_misc_tag(struct mlx5dr_match_param *value,
					   struct mlx5dr_ste_build *sb,
					   u8 *tag)
{
	struct mlx5dr_match_misc3 *misc3 = &value->misc3;

	if (sb->inner) {
		DR_STE_SET_TAG(eth_l4_misc_v1, tag, seq_num, misc3, inner_tcp_seq_num);
		DR_STE_SET_TAG(eth_l4_misc_v1, tag, ack_num, misc3, inner_tcp_ack_num);
	} else {
		DR_STE_SET_TAG(eth_l4_misc_v1, tag, seq_num, misc3, outer_tcp_seq_num);
		DR_STE_SET_TAG(eth_l4_misc_v1, tag, ack_num, misc3, outer_tcp_ack_num);
	}

	return 0;
}

static void dr_ste_v1_build_eth_l4_misc_init(struct mlx5dr_ste_build *sb,
					     struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_eth_l4_misc_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_ETHL4_MISC_O;
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_eth_l4_misc_tag;
}

static int
dr_ste_v1_build_flex_parser_tnl_vxlan_gpe_tag(struct mlx5dr_match_param *value,
					      struct mlx5dr_ste_build *sb,
					      u8 *tag)
{
	struct mlx5dr_match_misc3 *misc3 = &value->misc3;

	DR_STE_SET_TAG(flex_parser_tnl_vxlan_gpe, tag,
		       outer_vxlan_gpe_flags, misc3,
		       outer_vxlan_gpe_flags);
	DR_STE_SET_TAG(flex_parser_tnl_vxlan_gpe, tag,
		       outer_vxlan_gpe_next_protocol, misc3,
		       outer_vxlan_gpe_next_protocol);
	DR_STE_SET_TAG(flex_parser_tnl_vxlan_gpe, tag,
		       outer_vxlan_gpe_vni, misc3,
		       outer_vxlan_gpe_vni);

	return 0;
}

static void
dr_ste_v1_build_flex_parser_tnl_vxlan_gpe_init(struct mlx5dr_ste_build *sb,
					       struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_flex_parser_tnl_vxlan_gpe_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_FLEX_PARSER_TNL_HEADER;
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_flex_parser_tnl_vxlan_gpe_tag;
}

static int
dr_ste_v1_build_flex_parser_tnl_geneve_tag(struct mlx5dr_match_param *value,
					   struct mlx5dr_ste_build *sb,
					   u8 *tag)
{
	struct mlx5dr_match_misc *misc = &value->misc;

	DR_STE_SET_TAG(flex_parser_tnl_geneve, tag,
		       geneve_protocol_type, misc, geneve_protocol_type);
	DR_STE_SET_TAG(flex_parser_tnl_geneve, tag,
		       geneve_oam, misc, geneve_oam);
	DR_STE_SET_TAG(flex_parser_tnl_geneve, tag,
		       geneve_opt_len, misc, geneve_opt_len);
	DR_STE_SET_TAG(flex_parser_tnl_geneve, tag,
		       geneve_vni, misc, geneve_vni);

	return 0;
}

static void
dr_ste_v1_build_flex_parser_tnl_geneve_init(struct mlx5dr_ste_build *sb,
					    struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_flex_parser_tnl_geneve_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_FLEX_PARSER_TNL_HEADER;
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_flex_parser_tnl_geneve_tag;
}

static int dr_ste_v1_build_register_0_tag(struct mlx5dr_match_param *value,
					  struct mlx5dr_ste_build *sb,
					  u8 *tag)
{
	struct mlx5dr_match_misc2 *misc2 = &value->misc2;

	DR_STE_SET_TAG(register_0, tag, register_0_h, misc2, metadata_reg_c_0);
	DR_STE_SET_TAG(register_0, tag, register_0_l, misc2, metadata_reg_c_1);
	DR_STE_SET_TAG(register_0, tag, register_1_h, misc2, metadata_reg_c_2);
	DR_STE_SET_TAG(register_0, tag, register_1_l, misc2, metadata_reg_c_3);

	return 0;
}

static void dr_ste_v1_build_register_0_init(struct mlx5dr_ste_build *sb,
					    struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_register_0_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_STEERING_REGISTERS_0;
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_register_0_tag;
}

static int dr_ste_v1_build_register_1_tag(struct mlx5dr_match_param *value,
					  struct mlx5dr_ste_build *sb,
					  u8 *tag)
{
	struct mlx5dr_match_misc2 *misc2 = &value->misc2;

	DR_STE_SET_TAG(register_1, tag, register_2_h, misc2, metadata_reg_c_4);
	DR_STE_SET_TAG(register_1, tag, register_2_l, misc2, metadata_reg_c_5);
	DR_STE_SET_TAG(register_1, tag, register_3_h, misc2, metadata_reg_c_6);
	DR_STE_SET_TAG(register_1, tag, register_3_l, misc2, metadata_reg_c_7);

	return 0;
}

static void dr_ste_v1_build_register_1_init(struct mlx5dr_ste_build *sb,
					    struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_register_1_tag(mask, sb, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_STEERING_REGISTERS_1;
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_register_1_tag;
}

static void dr_ste_v1_build_src_gvmi_qpn_bit_mask(struct mlx5dr_match_param *value,
						  u8 *bit_mask)
{
	struct mlx5dr_match_misc *misc_mask = &value->misc;

	DR_STE_SET_ONES(src_gvmi_qp_v1, bit_mask, source_gvmi, misc_mask, source_port);
	DR_STE_SET_ONES(src_gvmi_qp_v1, bit_mask, source_qp, misc_mask, source_sqn);
	misc_mask->source_eswitch_owner_vhca_id = 0;
}

static int dr_ste_v1_build_src_gvmi_qpn_tag(struct mlx5dr_match_param *value,
					    struct mlx5dr_ste_build *sb,
					    u8 *tag)
{
	struct mlx5dr_match_misc *misc = &value->misc;
	struct mlx5dr_cmd_vport_cap *vport_cap;
	struct mlx5dr_domain *dmn = sb->dmn;
	struct mlx5dr_cmd_caps *caps;
	u8 *bit_mask = sb->bit_mask;
	bool source_gvmi_set;

	DR_STE_SET_TAG(src_gvmi_qp_v1, tag, source_qp, misc, source_sqn);

	if (sb->vhca_id_valid) {
		/* Find port GVMI based on the eswitch_owner_vhca_id */
		if (misc->source_eswitch_owner_vhca_id == dmn->info.caps.gvmi)
			caps = &dmn->info.caps;
		else if (dmn->peer_dmn && (misc->source_eswitch_owner_vhca_id ==
					   dmn->peer_dmn->info.caps.gvmi))
			caps = &dmn->peer_dmn->info.caps;
		else
			return -EINVAL;

		 misc->source_eswitch_owner_vhca_id = 0;
	} else {
		caps = &dmn->info.caps;
	}

	source_gvmi_set = MLX5_GET(ste_src_gvmi_qp_v1, bit_mask, source_gvmi);
	if (source_gvmi_set) {
		vport_cap = mlx5dr_get_vport_cap(caps, misc->source_port);
		if (!vport_cap || !mlx5dr_is_vport_enabled(vport_cap)) {
			mlx5dr_err(dmn, "Vport 0x%x is disabled or invalid\n",
				   misc->source_port);
			return -EINVAL;
		}

		if (vport_cap->vport_gvmi)
			MLX5_SET(ste_src_gvmi_qp_v1, tag, source_gvmi, vport_cap->vport_gvmi);

		misc->source_port = 0;
	}

	return 0;
}

static void dr_ste_v1_build_src_gvmi_qpn_init(struct mlx5dr_ste_build *sb,
					      struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_src_gvmi_qpn_bit_mask(mask, sb->bit_mask);

	sb->lu_type = DR_STE_V1_LU_TYPE_SRC_QP_GVMI;
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_src_gvmi_qpn_tag;
}

/* Cache structure and functions */
static bool dr_ste_v1_compare_modify_hdr(size_t cur_num_of_actions,
					 __be64 cur_hw_actions[],
					 size_t num_of_actions,
					 __be64 hw_actions[])
{
	int i;

	if (cur_num_of_actions != num_of_actions)
		return false;

	for (i = 0; i < num_of_actions; i++) {
		u8 action_id =
			MLX5_GET(ste_double_action_add, &hw_actions[i], action_id);

		if (action_id == DR_STE_V1_ACTION_ID_COPY) {
			if (hw_actions[i] != cur_hw_actions[i])
				return false;
		} else {
			if ((__be32)hw_actions[i] !=
			    (__be32)cur_hw_actions[i])
				return false;
		}
	}

	return true;
}

static bool dr_ste_v1_compare_reformat_hdr(size_t cur_num_of_actions,
					   u8 cur_hw_action[],
					   size_t num_of_actions,
					   u8 hw_action[])
{
	/* The only check we have is according to the number
	 * of actions, and this was already done prior this call.
	 */
	return true;
}

static bool dr_ste_v1_compare_pattern(enum mlx5dr_action_type cur_type,
				      size_t cur_num_of_actions,
				      u8 cur_hw_action[],
				      enum mlx5dr_action_type type,
				      size_t num_of_actions,
				      u8 hw_action[])
{
	if ((cur_num_of_actions != num_of_actions) || (cur_type != type))
		return false;

	switch (type) {
	case DR_ACTION_TYP_MODIFY_HDR:
		return dr_ste_v1_compare_modify_hdr(cur_num_of_actions,
						    (__be64 *)cur_hw_action,
						    num_of_actions,
						    (__be64 *)hw_action);
	case DR_ACTION_TYP_TNL_L3_TO_L2:
		return dr_ste_v1_compare_reformat_hdr(cur_num_of_actions,
						      cur_hw_action,
						      num_of_actions,
						      hw_action);
	default:
		WARN(true, "Illegal action type - %d", type);
		return false;
	}
}

struct dr_cached_pattern {
	enum mlx5dr_action_type type;
	struct {
		struct mlx5dr_icm_chunk *chunk;
		u8 *data;
		u16 num_of_actions;
		u32 index;
	} rewrite_data;
	refcount_t refcount;
	struct list_head list;
};

static struct dr_cached_pattern *
dr_ste_v1_find_cached_pattern(struct mlx5dr_domain *dmn,
			      struct mlx5dr_action *action)
{
	struct dr_cached_pattern *tmp_cached_action;
	struct dr_cached_pattern *cached_action;

	list_for_each_entry_safe(cached_action, tmp_cached_action,
			&dmn->modify_hdr_list, list) {
		if (dr_ste_v1_compare_pattern(cached_action->type,
					cached_action->rewrite_data.num_of_actions,
					cached_action->rewrite_data.data,
					action->action_type,
					action->rewrite->num_of_actions,
					action->rewrite->data))
			return cached_action;
	}

	return NULL;
}

static struct dr_cached_pattern *
dr_ste_v1_get_cached_pattern(struct mlx5dr_domain *dmn,
			     struct mlx5dr_action *action)
{
	struct dr_cached_pattern *cached_action;

	cached_action = dr_ste_v1_find_cached_pattern(dmn, action);
	if (cached_action) {
		/* LRU: move it to be first in the list */
		list_del(&cached_action->list);
		list_add_tail(&cached_action->list, &dmn->modify_hdr_list);
		refcount_inc(&cached_action->refcount);
	}

	return cached_action;
}

static void dr_ste_v1_put_cached_pattern(struct mlx5dr_domain *dmn,
					 struct mlx5dr_action *action)
{
	struct dr_cached_pattern *cached_pattern;

	cached_pattern = dr_ste_v1_find_cached_pattern(dmn, action);
	if (!cached_pattern) {
		WARN(true, "Cached pattern not found");
		return;
	}

	if (!refcount_dec_and_test(&cached_pattern->refcount))
		return;

	list_del(&cached_pattern->list);

	kfree(action->rewrite->data);
	mlx5dr_icm_free_chunk(action->rewrite->chunk);

	kfree(cached_pattern);
}

static int dr_ste_v1_add_pattern_to_cache(struct mlx5dr_domain *dmn,
					  struct mlx5dr_action *action)
{
	struct dr_cached_pattern *cached_pattern;

	cached_pattern = kzalloc(sizeof(*cached_pattern), GFP_KERNEL);
	if (!cached_pattern)
		return -ENOMEM;

	cached_pattern->type = action->action_type;
	cached_pattern->rewrite_data.chunk = action->rewrite->chunk;
	cached_pattern->rewrite_data.index = action->rewrite->index;
	cached_pattern->rewrite_data.num_of_actions =
		action->rewrite->num_of_actions;
	cached_pattern->rewrite_data.data = action->rewrite->data;

	list_add_tail(&cached_pattern->list, &dmn->modify_hdr_list);

	refcount_set(&cached_pattern->refcount, 1);

	return 0;
}

static enum mlx5dr_arg_chunk_size
dr_get_arg_size(struct mlx5dr_action *action)
{
	if (action->rewrite->num_of_actions <= 8)
		return DR_ARG_CHUNK_SIZE_1;
	if (action->rewrite->num_of_actions <= 16)
		return DR_ARG_CHUNK_SIZE_2;
	if (action->rewrite->num_of_actions <= 32)
		return DR_ARG_CHUNK_SIZE_3;
	return DR_ARG_CHUNK_SIZE_MAX;
}

static int dr_ste_v1_alloc_modify_hdr_arg(struct mlx5dr_domain *dmn,
					  struct mlx5dr_action *action)
{
	int ret;

	action->rewrite->arg = mlx5dr_arg_get_obj(dmn, dr_get_arg_size(action));
	if (!action->rewrite->arg) {
		mlx5dr_err(dmn, "Failed allocating args object for modify header\n");
		return -ENOMEM;
	}

	/* write it into the hw */
	ret = mlx5dr_send_postsend_args(dmn, action);
	if (ret) {
		mlx5dr_err(dmn, "Failed writing args object\n");
		goto put_obj;
	}

	return 0;

put_obj:
	mlx5dr_arg_put_obj(dmn, action->rewrite->arg);
	return ret;
}

static int dr_ste_v1_alloc_modify_hdr_chunk(struct mlx5dr_action *action,
					    u32 chunck_size)
{
	struct mlx5dr_domain *dmn = action->rewrite->dmn;
	struct dr_cached_pattern *cached_pattern;
	int ret;

	if (!dmn->modify_header_ptrn_icm_pool)
		return -ENOTSUPP;

	ret = dr_ste_v1_alloc_modify_hdr_arg(dmn, action);
	if (ret) {
		mlx5dr_err(dmn, "Failed allocating args for modify header\n");
		return -ENOMEM;
	}

	mutex_lock(&dmn->modify_hdr_mutex);

	cached_pattern = dr_ste_v1_get_cached_pattern(dmn, action);
	if (cached_pattern) {
		/* no use the current one, use the cached */
		kfree(action->rewrite->data);

		action->rewrite->chunk = cached_pattern->rewrite_data.chunk;
		action->rewrite->index = cached_pattern->rewrite_data.index;
		action->rewrite->data = cached_pattern->rewrite_data.data;

	} else {
		u64 *hw_actions;
		int i;

		action->rewrite->chunk =
			mlx5dr_icm_alloc_chunk(dmn->modify_header_ptrn_icm_pool,
					       chunck_size);
		if (!action->rewrite->chunk)
			goto put_arg;


		hw_actions = (u64 *)action->rewrite->data;

		/* Here we mask the pattern data to create a valid pattern
		 * since we do an OR operation between the arg and pattern
		 * This should be fixed in the future on to keep the data valid */
		for (i = 0; i < action->rewrite->num_of_actions; i++) {
			u8 action_id = MLX5_GET(ste_double_action_add, &hw_actions[i], action_id);

			if (action_id == DR_STE_V1_ACTION_ID_SET ||
			    action_id == DR_STE_V1_ACTION_ID_ADD ||
			    action_id == DR_STE_V1_ACTION_ID_INSERT_INLINE)
				MLX5_SET(ste_double_action_set, &hw_actions[i], inline_data, 0);
		}

		action->rewrite->index = (action->rewrite->chunk->icm_addr -
			dmn->info.caps.hdr_modify_pattern_icm_addr) /
			MLX5DR_ACTION_CACHE_LINE_SIZE;

		ret = mlx5dr_send_postsend_action(dmn, action);
		if (ret)
			goto clean_chunk;

		ret = dr_ste_v1_add_pattern_to_cache(dmn, action);
		if (ret) {
			mlx5dr_err(dmn, "Failed adding to cache\n");
			goto clean_chunk;
		}
	}

	mutex_unlock(&dmn->modify_hdr_mutex);

	return 0;

clean_chunk:
	mlx5dr_icm_free_chunk(action->rewrite->chunk);
put_arg:
	mutex_unlock(&dmn->modify_hdr_mutex);
	mlx5dr_arg_put_obj(action->rewrite->dmn, action->rewrite->arg);
	return ret;
}

static void dr_ste_v1_dealloc_modify_hdr_chunk(struct mlx5dr_action *action)
{
	struct mlx5dr_domain *dmn = action->rewrite->dmn;

	mutex_lock(&dmn->modify_hdr_mutex);
	dr_ste_v1_put_cached_pattern(action->rewrite->dmn, action);
	mutex_unlock(&dmn->modify_hdr_mutex);

	mlx5dr_arg_put_obj(action->rewrite->dmn, action->rewrite->arg);
}

static void dr_ste_set_flex_parser(u32 *misc4_field_id,
				   u32 *misc4_field_value,
				   bool *parser_is_used,
				   u8 *tag)
{
	u32 id = *misc4_field_id;
	u8 *parser_ptr;

	if (parser_is_used[id])
		return;

	parser_is_used[id] = true;
	parser_ptr = dr_ste_calc_flex_parser_offset(tag, id);

	*(__be32 *)parser_ptr = cpu_to_be32(*misc4_field_value);
	*misc4_field_id = 0;
	*misc4_field_value = 0;
}

static int dr_ste_v1_build_felx_parser_tag(struct mlx5dr_match_param *value,
					   struct mlx5dr_ste_build *sb,
					   u8 *tag)
{
	struct mlx5dr_match_misc4 *misc_4_mask = &value->misc4;
	bool parser_is_used[NUM_OF_PARSERS] = {};

	dr_ste_set_flex_parser(&misc_4_mask->prog_sample_field_id_0,
			       &misc_4_mask->prog_sample_field_value_0,
			       parser_is_used, tag);

	dr_ste_set_flex_parser(&misc_4_mask->prog_sample_field_id_1,
			       &misc_4_mask->prog_sample_field_value_1,
			       parser_is_used, tag);

	dr_ste_set_flex_parser(&misc_4_mask->prog_sample_field_id_2,
			       &misc_4_mask->prog_sample_field_value_2,
			       parser_is_used, tag);

	dr_ste_set_flex_parser(&misc_4_mask->prog_sample_field_id_3,
			       &misc_4_mask->prog_sample_field_value_3,
			       parser_is_used, tag);
	return 0;
}

static void dr_ste_v1_build_flex_parser_0_init(struct mlx5dr_ste_build *sb,
					       struct mlx5dr_match_param *mask)
{
	sb->lu_type = DR_STE_V1_LU_TYPE_FLEX_PARSER_0;
	dr_ste_v1_build_felx_parser_tag(mask, sb, sb->bit_mask);
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_felx_parser_tag;
}

static void dr_ste_v1_build_flex_parser_1_init(struct mlx5dr_ste_build *sb,
					       struct mlx5dr_match_param *mask)
{
	sb->lu_type = DR_STE_V1_LU_TYPE_FLEX_PARSER_1;
	dr_ste_v1_build_felx_parser_tag(mask, sb, sb->bit_mask);
	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_felx_parser_tag;
}

static int
dr_ste_v1_build_flex_parser_tnl_geneve_tlv_option_tag(struct mlx5dr_match_param *value,
						      struct mlx5dr_ste_build *sb,
						      u8 *tag)
{
	struct mlx5dr_match_misc3 *misc3 = &value->misc3;
	u8 parser_id = sb->caps->flex_parser_id_geneve_tlv_option_0;
	u8 *parser_ptr = dr_ste_calc_flex_parser_offset(tag, parser_id);

	MLX5_SET(ste_flex_parser_0, parser_ptr, flex_parser_3,
		   misc3->geneve_tlv_option_0_data);
	misc3->geneve_tlv_option_0_data = 0;

	return 0;
}

static void
dr_ste_v1_build_flex_parser_tnl_geneve_tlv_option_init(struct mlx5dr_ste_build *sb,
						       struct mlx5dr_match_param *mask)
{
	dr_ste_v1_build_flex_parser_tnl_geneve_tlv_option_tag(mask, sb, sb->bit_mask);

	/* STEs with lookup type FLEX_PARSER_{0/1} includes
	 * flex parsers_{0-3}/{4-7} respectively.
	 */
	sb->lu_type = sb->caps->flex_parser_id_geneve_tlv_option_0 > DR_STE_MAX_FLEX_0_ID ?
		      DR_STE_V1_LU_TYPE_FLEX_PARSER_1 :
		      DR_STE_V1_LU_TYPE_FLEX_PARSER_0;

	sb->byte_mask = mlx5dr_ste_conv_bit_to_byte_mask(sb->bit_mask);
	sb->ste_build_tag_func = &dr_ste_v1_build_flex_parser_tnl_geneve_tlv_option_tag;
}

static int dr_ste_v1_build_def0_tag(struct mlx5dr_match_param *value,
				    struct mlx5dr_ste_build *sb,
				    u8 *tag)
{
	struct mlx5dr_match_misc2 *misc2 = &value->misc2;
	struct mlx5dr_match_spec *outer = &value->outer;
	struct mlx5dr_match_spec *inner = &value->inner;

	DR_STE_SET_TAG(def0_v1, tag, metadata_reg_c_0, misc2, metadata_reg_c_0);
	DR_STE_SET_TAG(def0_v1, tag, metadata_reg_c_1, misc2, metadata_reg_c_1);

	DR_STE_SET_TAG(def0_v1, tag, dmac_47_16, outer, dmac_47_16);
	DR_STE_SET_TAG(def0_v1, tag, dmac_15_0, outer, dmac_15_0);
	DR_STE_SET_TAG(def0_v1, tag, smac_47_16, outer, smac_47_16);
	DR_STE_SET_TAG(def0_v1, tag, smac_15_0, outer, smac_15_0);
	DR_STE_SET_TAG(def0_v1, tag, ethertype, outer, ethertype);
	DR_STE_SET_TAG(def0_v1, tag, ip_frag, outer, frag);

	if (outer->ip_version == IP_VERSION_IPV4) {
		MLX5_SET(ste_def0_v1, tag, outer_l3_type, STE_IPV4);
		outer->ip_version = 0;
	} else if (outer->ip_version == IP_VERSION_IPV6) {
		MLX5_SET(ste_def0_v1, tag, outer_l3_type, STE_IPV6);
		outer->ip_version = 0;
	}

	if (outer->cvlan_tag) {
		MLX5_SET(ste_def0_v1, tag, first_vlan_qualifier, DR_STE_CVLAN);
		outer->cvlan_tag = 0;
	} else if (outer->svlan_tag) {
		MLX5_SET(ste_def0_v1, tag, first_vlan_qualifier, DR_STE_SVLAN);
		outer->svlan_tag = 0;
	}

	DR_STE_SET_TAG(def0_v1, tag, first_priority, outer, first_prio);
	DR_STE_SET_TAG(def0_v1, tag, first_vlan_id, outer, first_vid);
	DR_STE_SET_TAG(def0_v1, tag, first_cfi, outer, first_cfi);

	if (sb->caps->definer_supp_checksum) {
		DR_STE_SET_TAG(def0_v1, tag, outer_l3_ok, outer, l3_ok);
		DR_STE_SET_TAG(def0_v1, tag, outer_l4_ok, outer, l4_ok);
		DR_STE_SET_TAG(def0_v1, tag, inner_l3_ok, inner, l3_ok);
		DR_STE_SET_TAG(def0_v1, tag, inner_l4_ok, inner, l4_ok);

		DR_STE_SET_TAG(def0_v1, tag, outer_ipv4_checksum_ok, outer, ipv4_checksum_ok);
		DR_STE_SET_TAG(def0_v1, tag, outer_l4_checksum_ok, outer, l4_checksum_ok);
		DR_STE_SET_TAG(def0_v1, tag, inner_ipv4_checksum_ok, inner, ipv4_checksum_ok);
		DR_STE_SET_TAG(def0_v1, tag, inner_l4_checksum_ok, inner, l4_checksum_ok);
	}

	if (outer->tcp_flags) {
		DR_STE_SET_BOOL(def0_v1, tag, tcp_cwr, outer->tcp_flags & (1 << 7));
		DR_STE_SET_BOOL(def0_v1, tag, tcp_ece, outer->tcp_flags & (1 << 6));
		DR_STE_SET_BOOL(def0_v1, tag, tcp_urg, outer->tcp_flags & (1 << 5));
		DR_STE_SET_BOOL(def0_v1, tag, tcp_ack, outer->tcp_flags & (1 << 4));
		DR_STE_SET_BOOL(def0_v1, tag, tcp_psh, outer->tcp_flags & (1 << 3));
		DR_STE_SET_BOOL(def0_v1, tag, tcp_rst, outer->tcp_flags & (1 << 2));
		DR_STE_SET_BOOL(def0_v1, tag, tcp_syn, outer->tcp_flags & (1 << 1));
		DR_STE_SET_BOOL(def0_v1, tag, tcp_fin, outer->tcp_flags & (1 << 0));
		outer->tcp_flags ^= (outer->tcp_flags & 0xff);
	}

	return 0;
}

static void dr_ste_v1_build_def0_mask(struct mlx5dr_match_param *value,
				      struct mlx5dr_ste_build *sb)
{
	struct mlx5dr_match_spec *outer = &value->outer;
	u8 *tag = sb->match;

	if (outer->svlan_tag || outer->cvlan_tag) {
		MLX5_SET(ste_def0_v1, tag, first_vlan_qualifier, -1);
		outer->cvlan_tag = 0;
		outer->svlan_tag = 0;
	}

	dr_ste_v1_build_def0_tag(value, sb, tag);
}

static void dr_ste_v1_build_def0_init(struct mlx5dr_ste_build *sb,
				      struct mlx5dr_match_param *mask)
{
	sb->lu_type = DR_STE_V1_LU_TYPE_MATCH;
	dr_ste_v1_build_def0_mask(mask, sb);
	sb->ste_build_tag_func = &dr_ste_v1_build_def0_tag;
}

static int dr_ste_v1_build_def6_tag(struct mlx5dr_match_param *value,
				    struct mlx5dr_ste_build *sb,
				    u8 *tag)
{
	struct mlx5dr_match_spec *outer = &value->outer;

	/* Upper layer should verify this the IPv6 is provided */
	DR_STE_SET_TAG(def6_v1, tag, dst_ipv6_127_96, outer, dst_ip_127_96);
	DR_STE_SET_TAG(def6_v1, tag, dst_ipv6_95_64, outer, dst_ip_95_64);
	DR_STE_SET_TAG(def6_v1, tag, dst_ipv6_63_32, outer, dst_ip_63_32);
	DR_STE_SET_TAG(def6_v1, tag, dst_ipv6_31_0, outer, dst_ip_31_0);

	DR_STE_SET_TAG(def6_v1, tag, outer_l4_sport, outer, tcp_sport);
	DR_STE_SET_TAG(def6_v1, tag, outer_l4_sport, outer, udp_sport);
	DR_STE_SET_TAG(def6_v1, tag, outer_l4_dport, outer, tcp_dport);
	DR_STE_SET_TAG(def6_v1, tag, outer_l4_dport, outer, udp_dport);

	DR_STE_SET_TAG(def6_v1, tag, ip_frag, outer, frag);
	DR_STE_SET_TAG(def6_v1, tag, l3_ok, outer, l3_ok);
	DR_STE_SET_TAG(def6_v1, tag, l4_ok, outer, l4_ok);

	if (outer->tcp_flags) {
		DR_STE_SET_TCP_FLAGS(def6_v1, tag, outer);
		outer->tcp_flags = 0;
	}

	return 0;
}

static void dr_ste_v1_build_def6_init(struct mlx5dr_ste_build *sb,
				      struct mlx5dr_match_param *mask)
{
	sb->lu_type = DR_STE_V1_LU_TYPE_MATCH;
	dr_ste_v1_build_def6_tag(mask, sb, sb->match);
	sb->ste_build_tag_func = &dr_ste_v1_build_def6_tag;
}

static int dr_ste_v1_build_def22_tag(struct mlx5dr_match_param *value,
				     struct mlx5dr_ste_build *sb,
				     u8 *tag)
{
	struct mlx5dr_match_misc2 *misc2 = &value->misc2;
	struct mlx5dr_match_spec *outer = &value->outer;

	if (outer->ip_version == IP_VERSION_IPV4) {
		DR_STE_SET_TAG(def22_v1, tag, outer_ip_src_addr, outer, src_ip_31_0);
		DR_STE_SET_TAG(def22_v1, tag, outer_ip_dst_addr, outer, dst_ip_31_0);
	}

	if (outer->ip_version == IP_VERSION_IPV4) {
		MLX5_SET(ste_def22_v1, tag, outer_l3_type, STE_IPV4);
		outer->ip_version = 0;
	} else if (outer->ip_version == IP_VERSION_IPV6) {
		MLX5_SET(ste_def22_v1, tag, outer_l3_type, STE_IPV6);
		outer->ip_version = 0;
	}

	if (outer->ip_protocol == IPPROTO_UDP) {
		MLX5_SET(ste_def22_v1, tag, outer_l4_type, STE_UDP);
		outer->ip_protocol = 0;
	} else if (outer->ip_protocol == IPPROTO_TCP) {
		MLX5_SET(ste_def22_v1, tag, outer_l4_type, STE_TCP);
		outer->ip_protocol = 0;
	}

	if (outer->cvlan_tag) {
		MLX5_SET(ste_def22_v1, tag, first_vlan_qualifier, DR_STE_CVLAN);
		outer->cvlan_tag = 0;
	} else if (outer->svlan_tag) {
		MLX5_SET(ste_def22_v1, tag, first_vlan_qualifier, DR_STE_SVLAN);
		outer->svlan_tag = 0;
	}

	DR_STE_SET_TAG(def22_v1, tag, outer_ip_frag, outer, frag);
	DR_STE_SET_TAG(def22_v1, tag, outer_l4_sport, outer, tcp_sport);
	DR_STE_SET_TAG(def22_v1, tag, outer_l4_sport, outer, udp_sport);
	DR_STE_SET_TAG(def22_v1, tag, outer_l4_dport, outer, tcp_dport);
	DR_STE_SET_TAG(def22_v1, tag, outer_l4_dport, outer, udp_dport);
	DR_STE_SET_TAG(def22_v1, tag, first_priority, outer, first_prio);
	DR_STE_SET_TAG(def22_v1, tag, first_vlan_id, outer, first_vid);
	DR_STE_SET_TAG(def22_v1, tag, first_cfi, outer, first_cfi);
	DR_STE_SET_TAG(def22_v1, tag, metadata_reg_c_0, misc2, metadata_reg_c_0);
	DR_STE_SET_TAG(def22_v1, tag, outer_dmac_47_16, outer, dmac_47_16);
	DR_STE_SET_TAG(def22_v1, tag, outer_dmac_15_0, outer, dmac_15_0);
	DR_STE_SET_TAG(def22_v1, tag, outer_smac_47_16, outer, smac_47_16);
	DR_STE_SET_TAG(def22_v1, tag, outer_smac_15_0, outer, smac_15_0);

	return 0;
}

static void dr_ste_v1_build_def22_mask(struct mlx5dr_match_param *value,
				       struct mlx5dr_ste_build *sb)
{
	struct mlx5dr_match_spec *outer = &value->outer;
	u8 *tag = sb->match;
	bool is_tcp_or_udp;

	/* Hint to indicate UDP/TCP packet due to l4_type limitations */
	is_tcp_or_udp = outer->tcp_dport || outer->tcp_sport ||
			outer->udp_dport || outer->udp_sport ||
			outer->ip_protocol == IPPROTO_UDP ||
			outer->ip_protocol == IPPROTO_TCP;

	if (outer->ip_protocol && is_tcp_or_udp) {
		MLX5_SET(ste_def22_v1, tag, outer_l4_type, -1);
		outer->ip_protocol = 0;
	}

	if (outer->svlan_tag || outer->cvlan_tag) {
		MLX5_SET(ste_def22_v1, tag, first_vlan_qualifier, -1);
		outer->cvlan_tag = 0;
		outer->svlan_tag = 0;
	}

	dr_ste_v1_build_def22_tag(value, sb, tag);
}

static void dr_ste_v1_build_def22_init(struct mlx5dr_ste_build *sb,
				       struct mlx5dr_match_param *mask)
{
	sb->lu_type = DR_STE_V1_LU_TYPE_MATCH;
	dr_ste_v1_build_def22_mask(mask, sb);
	sb->ste_build_tag_func = &dr_ste_v1_build_def22_tag;
}

static int dr_ste_v1_build_def24_tag(struct mlx5dr_match_param *value,
				     struct mlx5dr_ste_build *sb,
				     u8 *tag)
{
	struct mlx5dr_match_misc2 *misc2 = &value->misc2;
	struct mlx5dr_match_spec *outer = &value->outer;
	struct mlx5dr_match_spec *inner = &value->inner;

	DR_STE_SET_TAG(def24_v1, tag, metadata_reg_c_0, misc2, metadata_reg_c_0);
	DR_STE_SET_TAG(def24_v1, tag, metadata_reg_c_1, misc2, metadata_reg_c_1);
	DR_STE_SET_TAG(def24_v1, tag, metadata_reg_c_2, misc2, metadata_reg_c_2);
	DR_STE_SET_TAG(def24_v1, tag, metadata_reg_c_3, misc2, metadata_reg_c_3);

	if (outer->ip_version == IP_VERSION_IPV4) {
		DR_STE_SET_TAG(def24_v1, tag, outer_ip_src_addr, outer, src_ip_31_0);
		DR_STE_SET_TAG(def24_v1, tag, outer_ip_dst_addr, outer, dst_ip_31_0);
	}

	if (outer->ip_version == IP_VERSION_IPV4) {
		MLX5_SET(ste_def24_v1, tag, outer_l3_type, STE_IPV4);
		outer->ip_version = 0;
	} else if (outer->ip_version == IP_VERSION_IPV6) {
		MLX5_SET(ste_def24_v1, tag, outer_l3_type, STE_IPV6);
		outer->ip_version = 0;
	}

	DR_STE_SET_TAG(def24_v1, tag, outer_l4_sport, outer, tcp_sport);
	DR_STE_SET_TAG(def24_v1, tag, outer_l4_sport, outer, udp_sport);
	DR_STE_SET_TAG(def24_v1, tag, outer_l4_dport, outer, tcp_dport);
	DR_STE_SET_TAG(def24_v1, tag, outer_l4_dport, outer, udp_dport);
	DR_STE_SET_TAG(def24_v1, tag, outer_ip_protocol, outer, ip_protocol);
	DR_STE_SET_TAG(def24_v1, tag, outer_ip_frag, outer, frag);

	if (inner->ip_version == IP_VERSION_IPV4) {
		MLX5_SET(ste_def24_v1, tag, inner_l3_type, STE_IPV4);
		inner->ip_version = 0;
	} else if (inner->ip_version == IP_VERSION_IPV6) {
		MLX5_SET(ste_def24_v1, tag, inner_l3_type, STE_IPV6);
		inner->ip_version = 0;
	}

	if (outer->cvlan_tag) {
		MLX5_SET(ste_def24_v1, tag, outer_first_vlan_type, DR_STE_CVLAN);
		outer->cvlan_tag = 0;
	} else if (outer->svlan_tag) {
		MLX5_SET(ste_def24_v1, tag, outer_first_vlan_type, DR_STE_SVLAN);
		outer->svlan_tag = 0;
	}

	if (inner->cvlan_tag) {
		MLX5_SET(ste_def24_v1, tag, inner_first_vlan_type, DR_STE_CVLAN);
		inner->cvlan_tag = 0;
	} else if (inner->svlan_tag) {
		MLX5_SET(ste_def24_v1, tag, inner_first_vlan_type, DR_STE_SVLAN);
		inner->svlan_tag = 0;
	}

	DR_STE_SET_TAG(def24_v1, tag, inner_ip_protocol, inner, ip_protocol);
	DR_STE_SET_TAG(def24_v1, tag, inner_ip_frag, inner, frag);

	return 0;
}

static void dr_ste_v1_build_def24_mask(struct mlx5dr_match_param *value,
				       struct mlx5dr_ste_build *sb)
{
	struct mlx5dr_match_spec *outer = &value->outer;
	struct mlx5dr_match_spec *inner = &value->inner;
	u8 *tag = sb->match;

	if (outer->svlan_tag || outer->cvlan_tag) {
		MLX5_SET(ste_def24_v1, tag, outer_first_vlan_type, -1);
		outer->cvlan_tag = 0;
		outer->svlan_tag = 0;
	}

	if (inner->svlan_tag || inner->cvlan_tag) {
		MLX5_SET(ste_def24_v1, tag, inner_first_vlan_type, -1);
		inner->cvlan_tag = 0;
		inner->svlan_tag = 0;
	}

	dr_ste_v1_build_def24_tag(value, sb, tag);
}

static void dr_ste_v1_build_def24_init(struct mlx5dr_ste_build *sb,
				       struct mlx5dr_match_param *mask)
{
	sb->lu_type = DR_STE_V1_LU_TYPE_MATCH;
	dr_ste_v1_build_def24_mask(mask, sb);
	sb->ste_build_tag_func = &dr_ste_v1_build_def24_tag;
}

static int dr_ste_v1_build_def25_tag(struct mlx5dr_match_param *value,
				     struct mlx5dr_ste_build *sb,
				     u8 *tag)
{
	struct mlx5dr_match_spec *outer = &value->outer;
	struct mlx5dr_match_spec *inner = &value->inner;

	if (outer->ip_version == IP_VERSION_IPV4) {
		DR_STE_SET_TAG(def25_v1, tag, inner_ip_src_addr, inner, src_ip_31_0);
		DR_STE_SET_TAG(def25_v1, tag, inner_ip_dst_addr, inner, dst_ip_31_0);
	}

	DR_STE_SET_TAG(def25_v1, tag, inner_l4_sport, inner, tcp_sport);
	DR_STE_SET_TAG(def25_v1, tag, inner_l4_sport, inner, udp_sport);
	DR_STE_SET_TAG(def25_v1, tag, inner_l4_dport, inner, tcp_dport);
	DR_STE_SET_TAG(def25_v1, tag, inner_l4_dport, inner, udp_dport);
	DR_STE_SET_TAG(def25_v1, tag, outer_l4_dport, outer, tcp_dport);
	DR_STE_SET_TAG(def25_v1, tag, outer_l4_dport, outer, udp_dport);

	if (outer->ip_version == IP_VERSION_IPV4) {
		MLX5_SET(ste_def25_v1, tag, outer_l3_type, STE_IPV4);
		outer->ip_version = 0;
	} else if (outer->ip_version == IP_VERSION_IPV6) {
		MLX5_SET(ste_def25_v1, tag, outer_l3_type, STE_IPV6);
		outer->ip_version = 0;
	}

	if (inner->ip_version == IP_VERSION_IPV4) {
		MLX5_SET(ste_def25_v1, tag, inner_l3_type, STE_IPV4);
		inner->ip_version = 0;
	} else if (inner->ip_version == IP_VERSION_IPV6) {
		MLX5_SET(ste_def25_v1, tag, inner_l3_type, STE_IPV6);
		inner->ip_version = 0;
	}

	if (outer->ip_protocol == IPPROTO_UDP) {
		MLX5_SET(ste_def25_v1, tag, outer_l4_type, STE_UDP);
		outer->ip_protocol = 0;
	} else if (outer->ip_protocol == IPPROTO_TCP) {
		MLX5_SET(ste_def25_v1, tag, outer_l4_type, STE_TCP);
		outer->ip_protocol = 0;
	}

	if (inner->ip_protocol == IPPROTO_UDP) {
		MLX5_SET(ste_def25_v1, tag, inner_l4_type, STE_UDP);
		inner->ip_protocol = 0;
	} else if (inner->ip_protocol == IPPROTO_TCP) {
		MLX5_SET(ste_def25_v1, tag, inner_l4_type, STE_TCP);
		inner->ip_protocol = 0;
	}

	if (outer->cvlan_tag) {
		MLX5_SET(ste_def25_v1, tag, outer_first_vlan_type, DR_STE_CVLAN);
		outer->cvlan_tag = 0;
	} else if (outer->svlan_tag) {
		MLX5_SET(ste_def25_v1, tag, outer_first_vlan_type, DR_STE_SVLAN);
		outer->svlan_tag = 0;
	}

	if (inner->cvlan_tag) {
		MLX5_SET(ste_def25_v1, tag, inner_first_vlan_type, DR_STE_CVLAN);
		inner->cvlan_tag = 0;
	} else if (inner->svlan_tag) {
		MLX5_SET(ste_def25_v1, tag, inner_first_vlan_type, DR_STE_SVLAN);
		inner->svlan_tag = 0;
	}

	return 0;
}

static void dr_ste_v1_build_def25_mask(struct mlx5dr_match_param *mask,
				       struct mlx5dr_ste_build *sb)
{
	struct mlx5dr_match_spec *outer = &mask->outer;
	struct mlx5dr_match_spec *inner = &mask->inner;
	bool is_out_tcp_or_udp, is_in_tcp_or_udp;
	u8 *tag = sb->match;

	/* Hint to indicate UDP/TCP packet due to l4_type limitations */
	is_out_tcp_or_udp = outer->tcp_dport || outer->tcp_sport ||
			    outer->udp_dport || outer->udp_sport ||
			    outer->ip_protocol == IPPROTO_UDP ||
			    outer->ip_protocol == IPPROTO_TCP;
	is_in_tcp_or_udp = inner->tcp_dport || inner->tcp_sport ||
			   inner->udp_dport || inner->udp_sport ||
			   inner->ip_protocol == IPPROTO_UDP ||
			   inner->ip_protocol == IPPROTO_TCP;

	if (outer->ip_protocol && is_out_tcp_or_udp) {
		MLX5_SET(ste_def25_v1, tag, outer_l4_type, -1);
		outer->ip_protocol = 0;
	}

	if (outer->svlan_tag || outer->cvlan_tag) {
		MLX5_SET(ste_def25_v1, tag, outer_first_vlan_type, -1);
		outer->cvlan_tag = 0;
		outer->svlan_tag = 0;
	}

	if (inner->ip_protocol && is_in_tcp_or_udp) {
		MLX5_SET(ste_def25_v1, tag, inner_l4_type, -1);
		inner->ip_protocol = 0;
	}

	if (inner->svlan_tag || inner->cvlan_tag) {
		MLX5_SET(ste_def25_v1, tag, inner_first_vlan_type, -1);
		inner->cvlan_tag = 0;
		inner->svlan_tag = 0;
	}

	dr_ste_v1_build_def25_tag(mask, sb, tag);
}

static void dr_ste_v1_build_def25_init(struct mlx5dr_ste_build *sb,
				       struct mlx5dr_match_param *mask)
{
	sb->lu_type = DR_STE_V1_LU_TYPE_MATCH;
	dr_ste_v1_build_def25_mask(mask, sb);
	sb->ste_build_tag_func = &dr_ste_v1_build_def25_tag;
}

static int dr_ste_v1_build_def26_tag(struct mlx5dr_match_param *value,
				     struct mlx5dr_ste_build *sb,
				     u8 *tag)
{
	struct mlx5dr_match_spec *outer = &value->outer;
	struct mlx5dr_match_misc *misc = &value->misc;

	if (outer->ip_version == IP_VERSION_IPV6) {
		DR_STE_SET_TAG(def26_v1, tag, src_ipv6_127_96, outer, src_ip_127_96);
		DR_STE_SET_TAG(def26_v1, tag, src_ipv6_95_64, outer, src_ip_95_64);
		DR_STE_SET_TAG(def26_v1, tag, src_ipv6_63_32, outer, src_ip_63_32);
		DR_STE_SET_TAG(def26_v1, tag, src_ipv6_31_0, outer, src_ip_31_0);
	}

	DR_STE_SET_TAG(def26_v1, tag, ip_frag, outer, frag);

	if (outer->ip_version == IP_VERSION_IPV6) {
		MLX5_SET(ste_def26_v1, tag, l3_type, STE_IPV6);
		outer->ip_version = 0;
	}

	if (outer->cvlan_tag) {
		MLX5_SET(ste_def26_v1, tag, first_vlan_type, DR_STE_CVLAN);
		outer->cvlan_tag = 0;
	} else if (outer->svlan_tag) {
		MLX5_SET(ste_def26_v1, tag, first_vlan_type, DR_STE_SVLAN);
		outer->svlan_tag = 0;
	}

	DR_STE_SET_TAG(def26_v1, tag, first_vlan_id, outer, first_vid);
	DR_STE_SET_TAG(def26_v1, tag, first_cfi, outer, first_cfi);
	DR_STE_SET_TAG(def26_v1, tag, first_priority, outer, first_prio);

	DR_STE_SET_TAG(def26_v1, tag, l3_ok, outer, l3_ok);
	DR_STE_SET_TAG(def26_v1, tag, l4_ok, outer, l4_ok);

	if (misc->outer_second_cvlan_tag) {
		MLX5_SET(ste_def26_v1, tag, second_vlan_type, DR_STE_CVLAN);
		misc->outer_second_cvlan_tag = 0;
	} else if (misc->outer_second_svlan_tag) {
		MLX5_SET(ste_def26_v1, tag, second_vlan_type, DR_STE_SVLAN);
		misc->outer_second_svlan_tag = 0;
	}

	DR_STE_SET_TAG(def26_v1, tag, second_vlan_id, misc, outer_second_vid);
	DR_STE_SET_TAG(def26_v1, tag, second_cfi, misc, outer_second_cfi);
	DR_STE_SET_TAG(def26_v1, tag, second_priority, misc, outer_second_prio);

	DR_STE_SET_TAG(def26_v1, tag, smac_47_16, outer, smac_47_16);
	DR_STE_SET_TAG(def26_v1, tag, smac_15_0, outer, smac_15_0);

	DR_STE_SET_TAG(def26_v1, tag, ip_porotcol, outer, ip_protocol);

	if (outer->tcp_flags) {
		DR_STE_SET_BOOL(def26_v1, tag, tcp_cwr, outer->tcp_flags & (1 << 7));
		DR_STE_SET_BOOL(def26_v1, tag, tcp_ece, outer->tcp_flags & (1 << 6));
		DR_STE_SET_BOOL(def26_v1, tag, tcp_urg, outer->tcp_flags & (1 << 5));
		DR_STE_SET_BOOL(def26_v1, tag, tcp_ack, outer->tcp_flags & (1 << 4));
		DR_STE_SET_BOOL(def26_v1, tag, tcp_psh, outer->tcp_flags & (1 << 3));
		DR_STE_SET_BOOL(def26_v1, tag, tcp_rst, outer->tcp_flags & (1 << 2));
		DR_STE_SET_BOOL(def26_v1, tag, tcp_syn, outer->tcp_flags & (1 << 1));
		DR_STE_SET_BOOL(def26_v1, tag, tcp_fin, outer->tcp_flags & (1 << 0));
		outer->tcp_flags ^= (outer->tcp_flags & 0xff);
	}

	return 0;
}

static void dr_ste_v1_build_def26_mask(struct mlx5dr_match_param *mask,
				       struct mlx5dr_ste_build *sb)
{
	struct mlx5dr_match_spec *outer = &mask->outer;
	struct mlx5dr_match_misc *misc = &mask->misc;
	u8 *tag = sb->match;

	if (outer->svlan_tag || outer->cvlan_tag) {
		MLX5_SET(ste_def26_v1, tag, first_vlan_type, -1);
		outer->cvlan_tag = 0;
		outer->svlan_tag = 0;
	}

	if (misc->outer_second_svlan_tag || misc->outer_second_cvlan_tag) {
		MLX5_SET(ste_def26_v1, tag, second_vlan_type, -1);
		misc->outer_second_svlan_tag = 0;
		misc->outer_second_cvlan_tag = 0;
	}

	dr_ste_v1_build_def26_tag(mask, sb, tag);
}

static void dr_ste_v1_build_def26_init(struct mlx5dr_ste_build *sb,
				       struct mlx5dr_match_param *mask)
{
	sb->lu_type = DR_STE_V1_LU_TYPE_MATCH;
	dr_ste_v1_build_def26_mask(mask, sb);
	sb->ste_build_tag_func = &dr_ste_v1_build_def26_tag;
}

static struct mlx5dr_ste_ctx ste_ctx_v1 = {
	/* Builders */
	.build_eth_l2_src_dst_init		= &dr_ste_v1_build_eth_l2_src_dst_init,
	.build_eth_l3_ipv6_src_init		= &dr_ste_v1_build_eth_l3_ipv6_src_init,
	.build_eth_l3_ipv6_dst_init		= &dr_ste_v1_build_eth_l3_ipv6_dst_init,
	.build_eth_l3_ipv4_5_tuple_init		= &dr_ste_v1_build_eth_l3_ipv4_5_tuple_init,
	.build_eth_l2_src_init			= &dr_ste_v1_build_eth_l2_src_init,
	.build_eth_l2_dst_init			= &dr_ste_v1_build_eth_l2_dst_init,
	.build_eth_l2_tnl_init			= &dr_ste_v1_build_eth_l2_tnl_init,
	.build_eth_l3_ipv4_misc_init		= &dr_ste_v1_build_eth_l3_ipv4_misc_init,
	.build_eth_ipv6_l3_l4_init		= &dr_ste_v1_build_eth_ipv6_l3_l4_init,
	.build_mpls_init			= &dr_ste_v1_build_mpls_init,
	.build_tnl_gre_init			= &dr_ste_v1_build_tnl_gre_init,
	.build_tnl_mpls_over_udp_init		= &dr_ste_v1_build_tnl_mpls_over_udp_init,
	.build_tnl_mpls_over_gre_init		= &dr_ste_v1_build_tnl_mpls_over_gre_init,
	.build_icmp_init			= &dr_ste_v1_build_icmp_init,
	.build_general_purpose_init		= &dr_ste_v1_build_general_purpose_init,
	.build_eth_l4_misc_init			= &dr_ste_v1_build_eth_l4_misc_init,
	.build_tnl_vxlan_gpe_init		= &dr_ste_v1_build_flex_parser_tnl_vxlan_gpe_init,
	.build_tnl_geneve_init			= &dr_ste_v1_build_flex_parser_tnl_geneve_init,
	.build_tnl_geneve_tlv_option_init	= &dr_ste_v1_build_flex_parser_tnl_geneve_tlv_option_init,
	.build_register_0_init			= &dr_ste_v1_build_register_0_init,
	.build_register_1_init			= &dr_ste_v1_build_register_1_init,
	.build_src_gvmi_qpn_init		= &dr_ste_v1_build_src_gvmi_qpn_init,
	.build_flex_parser_0_init		= &dr_ste_v1_build_flex_parser_0_init,
	.build_flex_parser_1_init		= &dr_ste_v1_build_flex_parser_1_init,
	.build_def0_init			= &dr_ste_v1_build_def0_init,
	.build_def6_init			= &dr_ste_v1_build_def6_init,
	.build_def22_init			= &dr_ste_v1_build_def22_init,
	.build_def24_init			= &dr_ste_v1_build_def24_init,
	.build_def25_init			= &dr_ste_v1_build_def25_init,
	.build_def26_init			= &dr_ste_v1_build_def26_init,
	/* Getters and Setters */
	.ste_init				= &dr_ste_v1_init,
	.set_next_lu_type			= &dr_ste_v1_set_next_lu_type,
	.get_next_lu_type			= &dr_ste_v1_get_next_lu_type,
	.set_miss_addr				= &dr_ste_v1_set_miss_addr,
	.get_miss_addr				= &dr_ste_v1_get_miss_addr,
	.set_hit_addr				= &dr_ste_v1_set_hit_addr,
	.set_byte_mask				= &dr_ste_v1_set_byte_mask,
	.get_byte_mask				= &dr_ste_v1_get_byte_mask,
	.set_ctrl_always_hit_htbl		= &dr_ste_v1_set_ctrl_always_hit_htbl,
	.set_ctrl_always_miss			= &dr_ste_v1_set_ctrl_always_miss,
	/* Actions */
	.actions_caps				= DR_STE_CTX_ALLOW_RX_ENCAP,

	.set_actions_rx				= &dr_ste_v1_set_actions_rx,
	.set_actions_tx				= &dr_ste_v1_set_actions_tx,
	.modify_field_arr_sz			= ARRAY_SIZE(dr_ste_v1_action_modify_field_arr),
	.modify_field_arr			= dr_ste_v1_action_modify_field_arr,
	.set_action_set				= &dr_ste_v1_set_action_set,
	.set_action_add				= &dr_ste_v1_set_action_add,
	.set_action_copy			= &dr_ste_v1_set_action_copy,
	.set_action_decap_l3_list		= &dr_ste_v1_set_action_decap_l3_list,
	.alloc_modify_hdr_chunk			= &dr_ste_v1_alloc_modify_hdr_chunk,
	.dealloc_modify_hdr_chunk		= &dr_ste_v1_dealloc_modify_hdr_chunk,
	/* Send */
	.prepare_for_postsend			= &dr_ste_v1_prepare_for_postsend,
};

struct mlx5dr_ste_ctx *mlx5dr_ste_get_ctx_v1(void)
{
	return &ste_ctx_v1;
}

