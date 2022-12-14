/*
 * Copyright (c) 2018 Mellanox Technologies. All rights reserved.
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
 *
 */

#ifndef __MLX5_ACCEL_H__
#define __MLX5_ACCEL_H__

#include <linux/mlx5/driver.h>
#include <linux/mlx5/qp.h>

enum mlx5_accel_esp_aes_gcm_keymat_iv_algo {
	MLX5_ACCEL_ESP_AES_GCM_IV_ALGO_SEQ,
};

enum mlx5_accel_esp_flags {
	MLX5_ACCEL_ESP_FLAGS_TUNNEL            = 0,    /* Default */
	MLX5_ACCEL_ESP_FLAGS_TRANSPORT         = 1UL << 0,
	MLX5_ACCEL_ESP_FLAGS_ESN_TRIGGERED     = 1UL << 1,
	MLX5_ACCEL_ESP_FLAGS_ESN_STATE_OVERLAP = 1UL << 2,
	MLX5_ACCEL_ESP_FLAGS_FULL_OFFLOAD      = 1UL << 3,
};

enum mlx5_accel_esp_action {
	MLX5_ACCEL_ESP_ACTION_DECRYPT,
	MLX5_ACCEL_ESP_ACTION_ENCRYPT,
};

enum mlx5_accel_esp_keymats {
	MLX5_ACCEL_ESP_KEYMAT_AES_NONE,
	MLX5_ACCEL_ESP_KEYMAT_AES_GCM,
};

enum mlx5_accel_esp_replay {
	MLX5_ACCEL_ESP_REPLAY_NONE,
	MLX5_ACCEL_ESP_REPLAY_BMP,
};

struct aes_gcm_keymat {
	u64   seq_iv;
	enum mlx5_accel_esp_aes_gcm_keymat_iv_algo iv_algo;

	u32   salt;
	u32   icv_len;

	u32   key_len;
	u32   aes_key[256 / 32];
};

struct mlx5_accel_esp_xfrm_attrs {
	enum mlx5_accel_esp_action action;
	u32   esn;
	u32   spi;
	u32   seq;
	u32   tfc_pad;
	u32   flags;
	u32   sa_handle;
	u32   aulen;
	enum mlx5_accel_esp_replay replay_type;
	union {
		struct {
			u32 size;

		} bmp;
	} replay;
	enum mlx5_accel_esp_keymats keymat_type;
	union {
		struct aes_gcm_keymat aes_gcm;
	} keymat;

	union {
		__be32 a4;
		__be32 a6[4];
	} saddr;

	union {
		__be32 a4;
		__be32 a6[4];
	} daddr;

	u8 is_ipv6;
};

struct mlx5_accel_esp_xfrm {
	struct mlx5_core_dev  *mdev;
	struct mlx5_accel_esp_xfrm_attrs attrs;
};

enum {
	MLX5_ACCEL_XFRM_FLAG_REQUIRE_METADATA = 1UL << 0,
};

enum mlx5_accel_ipsec_cap {
	MLX5_ACCEL_IPSEC_CAP_DEVICE		= 1 << 0,
	MLX5_ACCEL_IPSEC_CAP_REQUIRED_METADATA	= 1 << 1,
	MLX5_ACCEL_IPSEC_CAP_ESP		= 1 << 2,
	MLX5_ACCEL_IPSEC_CAP_IPV6		= 1 << 3,
	MLX5_ACCEL_IPSEC_CAP_LSO		= 1 << 4,
	MLX5_ACCEL_IPSEC_CAP_RX_NO_TRAILER	= 1 << 5,
	MLX5_ACCEL_IPSEC_CAP_ESN		= 1 << 6,
	MLX5_ACCEL_IPSEC_CAP_TX_IV_IS_ESN	= 1 << 7,
	MLX5_ACCEL_IPSEC_CAP_FULL_OFFLOAD	= 1 << 8,
};

#ifdef CONFIG_MLX5_ACCEL
#define MLX5_MAX_AUTH_TAG_BIT_NUM 128
/* up to 128 Authintaction tag data + 5B (up to 3B padding, 1B pad len, 1B next hdr) */
#define MLX5_MAX_IPSEC_TRAILER_SZ (DIV_ROUND_UP(MLX5_MAX_AUTH_TAG_BIT_NUM, BITS_PER_BYTE) + 5)

struct mlx5_accel_trailer {
	u32 wqe_params;
	u8 trbuff[MLX5_MAX_IPSEC_TRAILER_SZ];
	u8 trbufflen;
};

static inline u32 mlx5_accel_ipsec_get_bytes_cnt(struct mlx5_accel_trailer *tr)
{
	return tr->trbufflen;
}

static inline u16 mlx5_accel_ipsec_get_ds_cnt(struct mlx5_accel_trailer *tr)
{
	if (!tr->trbufflen)
		return 0;

	return DIV_ROUND_UP(sizeof(struct mlx5_wqe_inline_seg) + tr->trbufflen,
			    MLX5_SEND_WQE_DS);
}

/* Nullifies trbufflen */
static inline u16 mlx5_accel_ipsec_set_tr(struct mlx5_accel_trailer *tr,
					  struct mlx5_wqe_eth_seg  *eseg,
					  struct mlx5_wqe_data_seg  *dseg)
{
	struct mlx5_wqe_inline_seg *inlseg;
	u16 ds_cnt;

	if (!tr->trbufflen)
		return 0;

	ds_cnt = mlx5_accel_ipsec_get_ds_cnt(tr);
	eseg->trailer |= cpu_to_be32(tr->wqe_params);
	inlseg = (struct mlx5_wqe_inline_seg *)dseg;
	inlseg->byte_count = cpu_to_be32(tr->trbufflen | MLX5_INLINE_SEG);
	memcpy(inlseg->data, tr->trbuff, tr->trbufflen);
	tr->trbufflen = 0;

	return ds_cnt;
}

u32 mlx5_accel_ipsec_device_caps(struct mlx5_core_dev *mdev);

struct mlx5_accel_esp_xfrm *
mlx5_accel_esp_create_xfrm(struct mlx5_core_dev *mdev,
			   const struct mlx5_accel_esp_xfrm_attrs *attrs,
			   u32 flags);
void mlx5_accel_esp_destroy_xfrm(struct mlx5_accel_esp_xfrm *xfrm);
int mlx5_accel_esp_modify_xfrm(struct mlx5_accel_esp_xfrm *xfrm,
			       const struct mlx5_accel_esp_xfrm_attrs *attrs);

#else

static inline u32 mlx5_accel_ipsec_device_caps(struct mlx5_core_dev *mdev) { return 0; }

static inline struct mlx5_accel_esp_xfrm *
mlx5_accel_esp_create_xfrm(struct mlx5_core_dev *mdev,
			   const struct mlx5_accel_esp_xfrm_attrs *attrs,
			   u32 flags) { return ERR_PTR(-EOPNOTSUPP); }
static inline void
mlx5_accel_esp_destroy_xfrm(struct mlx5_accel_esp_xfrm *xfrm) {}
static inline int
mlx5_accel_esp_modify_xfrm(struct mlx5_accel_esp_xfrm *xfrm,
			   const struct mlx5_accel_esp_xfrm_attrs *attrs) { return -EOPNOTSUPP; }

#endif /* CONFIG_MLX5_ACCEL */
#endif /* __MLX5_ACCEL_H__ */
