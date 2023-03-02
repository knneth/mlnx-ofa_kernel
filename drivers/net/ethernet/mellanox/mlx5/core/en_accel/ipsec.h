/*
 * Copyright (c) 2017 Mellanox Technologies. All rights reserved.
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

#ifndef __MLX5E_IPSEC_H__
#define __MLX5E_IPSEC_H__

#include <linux/mlx5/device.h>
#include <net/xfrm.h>
#include <linux/idr.h>
#include "en/ipsec_aso.h"

#define MLX5E_IPSEC_SADB_RX_BITS 10
#define MLX5E_IPSEC_SADB_TX_BITS 10
#define MLX5E_IPSEC_ESN_SCOPE_MID 0x80000000L

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

struct aes_gcm_keymat {
	u64   seq_iv;

	u32   salt;
	u32   icv_len;

	u32   key_len;
	u32   aes_key[256 / 32];
};

struct mlx5_accel_esp_xfrm_attrs {
	enum mlx5_accel_esp_action action;
	u32   esn;
	u32   spi;
	u32   flags;
	struct aes_gcm_keymat aes_gcm;

	union {
		__be32 a4;
		__be32 a6[4];
	} saddr;

	union {
		__be32 a4;
		__be32 a6[4];
	} daddr;

	struct {
		u16 dport;
		u16 dport_mask;
		u8 proto;
	} upspec;

	u8 is_ipv6;
	u32   seq;
	u32   aulen;

	__u64   soft_packet_limit;
	__u64   hard_packet_limit;

	__u32   replay_window;
};

enum mlx5_ipsec_cap {
	MLX5_IPSEC_CAP_CRYPTO		= 1 << 0,
	MLX5_IPSEC_CAP_ESN		= 1 << 1,
	MLX5_IPSEC_CAP_FULL		= 1 << 2,
};

#ifdef CONFIG_MLX5_EN_IPSEC
struct mlx5e_priv;

struct mlx5e_ipsec_sw_stats {
	atomic64_t ipsec_rx_drop_sp_alloc;
	atomic64_t ipsec_rx_drop_sadb_miss;
	atomic64_t ipsec_rx_drop_syndrome;
	atomic64_t ipsec_tx_drop_bundle;
	atomic64_t ipsec_tx_drop_no_state;
	atomic64_t ipsec_tx_drop_not_ip;
	atomic64_t ipsec_tx_drop_trailer;
};

struct mlx5e_ipsec_stats {
	u64 ipsec_full_rx_pkts;
	u64 ipsec_full_rx_bytes;
	u64 ipsec_full_rx_pkts_drop;
	u64 ipsec_full_rx_bytes_drop;
	u64 ipsec_full_tx_pkts;
	u64 ipsec_full_tx_bytes;
	u64 ipsec_full_tx_pkts_drop;
	u64 ipsec_full_tx_bytes_drop;
};

struct mlx5e_accel_fs_esp;
struct mlx5e_ipsec_tx;

struct mlx5e_ipsec {
	struct mlx5_core_dev *mdev;
	DECLARE_HASHTABLE(sadb_rx, MLX5E_IPSEC_SADB_RX_BITS);
	spinlock_t sadb_rx_lock; /* Protects sadb_rx */
	DECLARE_HASHTABLE(sadb_tx, MLX5E_IPSEC_SADB_TX_BITS);
	spinlock_t sadb_tx_lock; /* Protects sadb_tx and halloc */
	struct ida halloc;
	struct mlx5e_ipsec_sw_stats sw_stats;
	struct workqueue_struct *wq;
	struct mlx5e_accel_fs_esp *rx_fs;
	struct mlx5e_ipsec_tx *tx_fs;
	struct mlx5e_ipsec_stats stats;
	struct mlx5e_ipsec_aso *aso;
};

struct mlx5e_ipsec_esn_state {
	u32 esn;
	u8 trigger: 1;
	u8 overlap: 1;
};

struct mlx5e_ipsec_rule {
	struct mlx5_flow_handle *rule;
	struct mlx5_modify_hdr *set_modify_hdr;
	struct mlx5_pkt_reformat *pkt_reformat;
};

struct mlx5e_ipsec_modify_state_work {
	struct work_struct		work;
	struct mlx5_accel_esp_xfrm_attrs attrs;
};

#define IPSEC_NO_LIMIT     GENMASK_ULL(63, 0)
#define IPSEC_SW_LIMIT_BIT 31
#define IPSEC_HW_LIMIT     BIT(IPSEC_SW_LIMIT_BIT + 1)
#define IPSEC_SW_LIMIT     BIT(IPSEC_SW_LIMIT_BIT)
#define IPSEC_SW_MASK      GENMASK(IPSEC_SW_LIMIT_BIT - 1, 0)
#define IPSEC_SAFE         (IPSEC_SW_LIMIT / 16)

struct mlx5e_ipsec_state_lft {
	u64 round_soft; /* Number of interrupt before send soft event */
	u64 round_hard; /* Number of interrupt before send hard event */
	bool is_simulated;
};

struct mlx5e_ipsec_sa_entry {
	struct hlist_node hlist; /* Item in SADB_RX hashtable */
	struct mlx5e_ipsec_esn_state esn_state;
	unsigned int handle; /* Handle in SADB_RX */
	struct xfrm_state *x;
	struct mlx5e_ipsec *ipsec;
	struct mlx5_accel_esp_xfrm_attrs attrs;
	void (*set_iv_op)(struct sk_buff *skb, struct xfrm_state *x,
			  struct xfrm_offload *xo);
	u32 ipsec_obj_id;
	u32 enc_key_id;
	struct mlx5e_ipsec_rule ipsec_rule;
	struct mlx5e_ipsec_modify_state_work modify_work;

	u32 pdn;
	struct mlx5e_ipsec_state_lft lft;
	bool is_removed;
};

void mlx5e_ipsec_init(struct mlx5e_priv *priv);
void mlx5e_ipsec_cleanup(struct mlx5e_priv *priv);
void mlx5e_ipsec_build_netdev(struct mlx5e_priv *priv);

struct xfrm_state *mlx5e_ipsec_sadb_rx_lookup(struct mlx5e_ipsec *dev,
					      unsigned int handle);
int mlx5e_ipsec_async_event(struct mlx5e_priv *priv, u32 obj_id);
void mlx5e_ipsec_ul_cleanup(struct mlx5e_priv *priv);

void mlx5e_accel_ipsec_fs_cleanup(struct mlx5e_ipsec *ipsec);
int mlx5e_accel_ipsec_fs_init(struct mlx5e_ipsec *ipsec);
int mlx5e_accel_ipsec_fs_add_rule(struct mlx5e_priv *priv,
				  struct mlx5e_ipsec_sa_entry *sa_entry);
void mlx5e_accel_ipsec_fs_del_rule(struct mlx5e_priv *priv,
				   struct mlx5e_ipsec_sa_entry *sa_entry);

int mlx5_ipsec_create_sa_ctx(struct mlx5e_ipsec_sa_entry *sa_entry);
void mlx5_ipsec_free_sa_ctx(struct mlx5e_ipsec_sa_entry *sa_entry);

u32 mlx5_ipsec_device_caps(struct mlx5_core_dev *mdev);

void mlx5_accel_esp_modify_xfrm(struct mlx5e_ipsec_sa_entry *sa_entry,
				const struct mlx5_accel_esp_xfrm_attrs *attrs);

static inline struct mlx5_core_dev *
mlx5e_ipsec_sa2dev(struct mlx5e_ipsec_sa_entry *sa_entry)
{
	return sa_entry->ipsec->mdev;
}

static inline bool mlx5_is_ipsec_device(struct mlx5_core_dev *mdev)
{
	return ((mlx5_ipsec_device_caps(mdev) & MLX5_IPSEC_CAP_FULL) == MLX5_IPSEC_CAP_FULL);
}

struct xfrm_state *mlx5e_ipsec_sadb_rx_lookup_state(struct mlx5e_ipsec *ipsec,
						    struct sk_buff *skb, u8 ip_ver);
#else
static inline void mlx5e_ipsec_init(struct mlx5e_priv *priv)
{
}

static inline void mlx5e_ipsec_cleanup(struct mlx5e_priv *priv)
{
}

static inline void mlx5e_ipsec_build_netdev(struct mlx5e_priv *priv)
{
}

static inline u32 mlx5_ipsec_device_caps(struct mlx5_core_dev *mdev)
{
	return 0;
}
static inline bool mlx5_is_ipsec_device(struct mlx5_core_dev *mdev) { return false; }

static inline int mlx5e_ipsec_async_event(struct mlx5e_priv *priv, u32 obj_id)
{
	return NOTIFY_DONE;
}

static inline void mlx5e_ipsec_ul_cleanup(struct mlx5e_priv *priv) {}
#endif

#endif	/* __MLX5E_IPSEC_H__ */
