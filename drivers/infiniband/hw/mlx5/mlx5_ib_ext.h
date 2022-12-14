/*
 * Copyright (c) 2013-2016, Mellanox Technologies. All rights reserved.
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

#ifndef MLX5_IB_EXT_H
#define MLX5_IB_EXT_H

#include <rdma/ib_verbs.h>

/* mlx5_set_ttl feature infra */
struct mlx5_ttl_data {
	int val;
	struct kobject kobj;
};

int init_ttl_sysfs(struct mlx5_ib_dev *dev);
void cleanup_ttl_sysfs(struct mlx5_ib_dev *dev);

/* mlx5_force_tc feature */
enum {
	TCLASS_MATCH_SRC_ADDR_IP,
	TCLASS_MATCH_DST_ADDR_IP,
	TCLASS_MATCH_SRC_ADDR_IP6,
	TCLASS_MATCH_DST_ADDR_IP6,
	TCLASS_MATCH_TCLASS,
	TCLASS_MATCH_TCLASS_NO_PREFIX,
	TCLASS_MATCH_MAX,
};

struct tclass_match {
	u32 mask;
	u8 s_addr[16];
	u8 d_addr[16];
	u8 d_addr_m[16];
	int     tclass; /* Should be always last! */
};

struct tclass_parse_node {
	int (*parse)(const char *str, void *store, void *store_mask);
	int (*compare)(struct tclass_match *match, struct tclass_match *match2,
		       bool with_mask);
	size_t (*print)(struct tclass_match *match, char *buf, size_t size);
	const char *pattern;
	size_t v_offset;
	size_t m_offset;
	u32 mask;
};

#define TCLASS_CREATE_PARSE_NODE(type, parse, compare, print, pattern,	\
				 mask, v_member, m_member)		\
	[(type)] = {parse, compare, print, pattern,			\
		    offsetof(struct tclass_match, v_member),		\
		    offsetof(struct tclass_match, m_member), mask}

enum {
	TCLASS_MATCH_MASK_SRC_ADDR_IP = BIT(TCLASS_MATCH_SRC_ADDR_IP),
	TCLASS_MATCH_MASK_DST_ADDR_IP = BIT(TCLASS_MATCH_DST_ADDR_IP),
	TCLASS_MATCH_MASK_SRC_ADDR_IP6 = BIT(TCLASS_MATCH_SRC_ADDR_IP6),
	TCLASS_MATCH_MASK_DST_ADDR_IP6 = BIT(TCLASS_MATCH_DST_ADDR_IP6),
	TCLASS_MATCH_MASK_TCLASS = BIT(TCLASS_MATCH_TCLASS),
	TCLASS_MATCH_MASK_MAX = BIT(TCLASS_MATCH_MAX),
};

#define TCLASS_MAX_RULES 40
#define TCLASS_MAX_CMD 100

struct mlx5_tc_data {
	struct tclass_match rule[TCLASS_MAX_RULES];
	struct mutex lock;
	bool initialized;
	int val;
	struct kobject kobj;
	struct mlx5_ib_dev *ibdev;
};

int init_tc_sysfs(struct mlx5_ib_dev *dev);
void cleanup_tc_sysfs(struct mlx5_ib_dev *dev);
void tclass_get_tclass(struct mlx5_ib_dev *dev,
		struct mlx5_tc_data *tcd,
		const struct rdma_ah_attr *ah,
		u8 port,
		u8 *tclass);

/* DC_cnak feature */

#define MLX5_DC_CONNECT_QP_DEPTH 8192
#define MLX5_IB_QPT_SW_CNAK     IB_QPT_RESERVED5

enum {
        MLX5_DCT_CS_RES_64      = 2,
        MLX5_CNAK_RX_POLL_CQ_QUOTA      = 256,
};

struct mlx5_ib_dev;

struct mlx5_dc_tracer {
        struct page     *pg;
        dma_addr_t      dma;
        int             size;
        int             order;
};

struct mlx5_dc_desc {
        dma_addr_t      dma;
        void            *buf;
};

enum mlx5_op {
        MLX5_WR_OP_MLX  = 1,
};

struct mlx5_mlx_wr {
        u8      sl;
        u16     dlid;
        int     icrc;
};

struct mlx5_send_wr {
        struct ib_send_wr       wr;
        union {
                struct mlx5_mlx_wr      mlx;
        } sel;
};

struct mlx5_dc_stats {
	struct kobject          kobj;
	struct mlx5_ib_dev      *dev;
	int                     port;
	atomic64_t              connects;
	atomic64_t              cnaks;
	atomic64_t              discards;
	int                     *rx_scatter;
	int                     initialized;
};

struct mlx5_dc_data {
        struct ib_mr            *mr;
        struct ib_qp            *dcqp;
        struct ib_cq            *rcq;
        struct ib_cq            *scq;
        unsigned int            rx_npages;
        unsigned int            tx_npages;
        struct mlx5_dc_desc     *rxdesc;
        struct mlx5_dc_desc     *txdesc;
        unsigned int            max_wqes;
        unsigned int            cur_send;
        unsigned int            last_send_completed;
        int                     tx_pending;
        struct mlx5_ib_dev      *dev;
        int                     port;
        int                     initialized;
	int                     index;
	int                     tx_signal_factor;
        struct ib_wc            wc_tbl[MLX5_CNAK_RX_POLL_CQ_QUOTA];
};

int mlx5_ib_mmap_dc_info_page(struct mlx5_ib_dev *dev,
                              struct vm_area_struct *vma);
int mlx5_ib_init_dc_improvements(struct mlx5_ib_dev *dev);
void mlx5_ib_cleanup_dc_improvements(struct mlx5_ib_dev *dev);

void mlx5_ib_set_mlx_seg(struct mlx5_mlx_seg *seg, struct mlx5_mlx_wr *wr);
#endif /*MLX5_IB_EXT_H*/
