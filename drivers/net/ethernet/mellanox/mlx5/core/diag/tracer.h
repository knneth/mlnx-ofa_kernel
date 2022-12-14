/*
 * Copyright (c) 2018, Mellanox Technologies, Ltd.  All rights reserved.
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

#ifndef __LIB_TRACER_H__
#define __LIB_TRACER_H__

#include <linux/mlx5/driver.h>
#include <mlx5_core.h>

enum mlx5_tracer_ownership_state {
	MLX5_TRACER_RELEASE_OWNERSHIP,
	MLX5_TRACER_ACQUIRE_OWNERSHIP,
};

#define STRINGS_DB_READ_SIZE_BYTES 64
#define TRACER_BUFFER_PAGE_NUM 2
#define TRACER_BUFFER_CHUNK 4096
#define TRACE_BUFFER_SIZE_BYTE (TRACER_BUFFER_PAGE_NUM * TRACER_BUFFER_CHUNK)

enum tracing_mode {
	TRACE_TO_MEMORY = 1 << 0,
};

enum tracer_ctrl_fields_select {
	TRACE_STATUS = 1 << 0,
	PRODUCER_INDEX = 1 << 1,
	CONSUMER_INDEX = 1 << 2,
};

int mlx5_tracer_init(struct mlx5_core_dev *dev);
void mlx5_tracer_cleanup(struct mlx5_core_dev *dev);
void mlx5_tracer_event(struct mlx5_core_dev *dev, struct mlx5_eqe *eqe);

enum tracer_event_type {
	TRACER_EVENT_TYPE_STRING,
	TRACER_EVENT_TYPE_TIMESTAMP = 0xFF,
	TRACER_EVENT_TYPE_UNRECOGNIZED,
};

struct mlx5_ifc_tracer_event_bits {
	u8         lost[0x1];
	u8         timestamp[0x7];
	u8         event_id[0x8];
	u8         event_data[0x30];
};

struct mlx5_ifc_tracer_string_event_bits {
	u8         lost[0x1];
	u8         timestamp[0x7];
	u8         event_id[0x8];
	u8         tmsn[0xd];
	u8         tdsn[0x3];
	u8         string_param[0x20];
};

struct mlx5_ifc_tracer_timestamp_event_bits {
	u8         timestamp7_0[0x8];
	u8         event_id[0x8];
	u8         urts[0x3];
	u8         timestamp52_40[0xd];
	u8         timestamp39_8[0x20];
};

struct tracer_timestamp_event {
	u64        timestamp;
	u8         unreliable;
};

struct tracer_string_event {
	u32        timestamp;
	u32        tmsn;
	u32        tdsn;
	u32        string_param;
};

struct tracer_event {
	bool      lost_event;
	u32       type;
	u8        event_id;
	union {
		struct tracer_string_event string_event;
		struct tracer_timestamp_event timestamp_event;
	};
};

#endif
