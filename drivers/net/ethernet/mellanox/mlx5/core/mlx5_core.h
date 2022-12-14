/*
 * Copyright (c) 2013-2015, Mellanox Technologies, Ltd.  All rights reserved.
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

#ifndef __MLX5_CORE_H__
#define __MLX5_CORE_H__

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/if_link.h>
#include <linux/clocksource.h>

#define DRIVER_NAME "mlx5_core"
#define DRIVER_VERSION	"4.0-2.0.0"
#define DRIVER_RELDATE	"28 Mar 2017"

#define MLX5_TOTAL_VPORTS(mdev) (1 + pci_sriov_get_totalvfs(mdev->pdev))

#define MLX5_DEFAULT_COMP_IRQ_NAME "mlx5_comp%d"

extern uint mlx5_core_debug_mask;

#define mlx5_core_dbg(__dev, format, ...)				\
	dev_dbg(&(__dev)->pdev->dev, "%s:%d:(pid %d): " format,		\
		 __func__, __LINE__, current->pid,			\
		 ##__VA_ARGS__)

#define mlx5_core_dbg_mask(__dev, mask, format, ...)			\
do {									\
	if ((mask) & mlx5_core_debug_mask)				\
		mlx5_core_dbg(__dev, format, ##__VA_ARGS__);		\
} while (0)

#define mlx5_core_err(__dev, format, ...)				\
	dev_err(&(__dev)->pdev->dev, "%s:%d:(pid %d): " format,	\
		__func__, __LINE__, current->pid,	\
	       ##__VA_ARGS__)

#define mlx5_core_warn(__dev, format, ...)				\
	dev_warn(&(__dev)->pdev->dev, "%s:%d:(pid %d): " format,	\
		 __func__, __LINE__, current->pid,			\
		##__VA_ARGS__)

#define mlx5_core_info(__dev, format, ...)				\
	dev_info(&(__dev)->pdev->dev, format, ##__VA_ARGS__)

enum {
	MLX5_CMD_DATA, /* print command payload only */
	MLX5_CMD_TIME, /* print command execution time */
};

enum {
	MLX5_DRIVER_STATUS_ABORTED = 0xfe,
	MLX5_DRIVER_SYND = 0xbadd00de,
};

enum mlx5_icmd_conf_address {
	MLX5_ICMD_CTRL		= 0x0,      /* RW */
	MLX5_ICMD_MAILBOX_SZ	= 0x1000,   /* RO */
	MLX5_ICMD_SYNDROME	= 0x1008,   /* RO */
	MLX5_ICMD_MAILBOX	= 0x100000, /* RW */
};

enum mlx5_icmd_ctrl_opcode {
	MLX5_ICMD_ACCESS_REG	= 0x9001,
};

enum mlx5_icmd_access_reg_id {
	MLX5_ICMD_MCION		= 0x9052,
};

enum mlx5_icmd_access_reg_method {
	MLX5_ICMD_QUERY		= 0x1,
	MLX5_ICMD_WRITE		= 0x2,
};

enum {
	MLX5_ICMD_ACCESS_REG_DATA_DW_SZ = 0x2,
};

struct mlx5_icmd_ctrl_bits {
	u16 opcode;
	u8  status;
	u8  busy;
} __packed;

struct mlx5_icmd_access_reg_input_bits {
	u16 constant_1_2;
	u8  reserved_0[0x2];
	u16 register_id;
	u8  method;
	u8  constant_3;
	u8  reserved_1[0x8];
	u16 len;
	u8  reserved_2[0x2];
	u32 reg_data[MLX5_ICMD_ACCESS_REG_DATA_DW_SZ];
} __packed;

struct mlx5_icmd_access_reg_output_bits {
	u8  reserved_0[0x2];
	u8  status;
	u8  reserved_1[0x1];
	u16 register_id;
	u8  reserved_2[0xA];
	u16 len;
	u8  reserved_3[0x2];
	u32 reg_data[MLX5_ICMD_ACCESS_REG_DATA_DW_SZ];
} __packed;

struct mlx5_mcion_reg {
	u8  reserved_0[0x1];
	u8  module;
	u8  reserved_1[0x5];
	u8  module_status;
} __packed;

int mlx5_query_hca_caps(struct mlx5_core_dev *dev);
int mlx5_query_board_id(struct mlx5_core_dev *dev);
int mlx5_cmd_init_hca(struct mlx5_core_dev *dev);
int mlx5_cmd_teardown_hca(struct mlx5_core_dev *dev);
void mlx5_core_event(struct mlx5_core_dev *dev, enum mlx5_dev_event event,
		     unsigned long param);
void mlx5_port_module_event(struct mlx5_core_dev *dev, struct mlx5_eqe *eqe);
void mlx5_enter_error_state(struct mlx5_core_dev *dev);
void mlx5_disable_device(struct mlx5_core_dev *dev);
void mlx5_recover_device(struct mlx5_core_dev *dev);
void mlx5_add_pci_to_irq_name(struct mlx5_core_dev *dev, const char *src_name,
			      char *dest_name);
void mlx5_rename_comp_eq(struct mlx5_core_dev *dev, unsigned int eq_ix,
			 char *name);
int mlx5_sriov_init(struct mlx5_core_dev *dev);
void mlx5_sriov_cleanup(struct mlx5_core_dev *dev);
int mlx5_sriov_attach(struct mlx5_core_dev *dev);
void mlx5_sriov_detach(struct mlx5_core_dev *dev);
int mlx5_core_sriov_configure(struct pci_dev *dev, int num_vfs);
bool mlx5_sriov_is_enabled(struct mlx5_core_dev *dev);
int mlx5_sriov_sysfs_init(struct mlx5_core_dev *dev);
void mlx5_sriov_sysfs_cleanup(struct mlx5_core_dev *dev);
int mlx5_create_vfs_sysfs(struct mlx5_core_dev *dev, int num_vfs);
void mlx5_destroy_vfs_sysfs(struct mlx5_core_dev *dev);
int mlx5_core_enable_hca(struct mlx5_core_dev *dev, u16 func_id);
int mlx5_core_disable_hca(struct mlx5_core_dev *dev, u16 func_id);
int mlx5_create_scheduling_element_cmd(struct mlx5_core_dev *dev, u8 hierarchy,
				       void *context, u32 *element_id);
int mlx5_modify_scheduling_element_cmd(struct mlx5_core_dev *dev, u8 hierarchy,
				       void *context, u32 element_id,
				       u32 modify_bitmask);
int mlx5_destroy_scheduling_element_cmd(struct mlx5_core_dev *dev, u8 hierarchy,
					u32 element_id);
int mlx5_wait_for_vf_pages(struct mlx5_core_dev *dev);
cycle_t mlx5_read_internal_timer(struct mlx5_core_dev *dev);
u32 mlx5_get_msix_vec(struct mlx5_core_dev *dev, int vecidx);
struct mlx5_eq *mlx5_eqn2eq(struct mlx5_core_dev *dev, int eqn);
int mlx5_vector2eq(struct mlx5_core_dev *dev, int vector, struct mlx5_eq *eqc);
void mlx5_cq_tasklet_cb(unsigned long data);

int mlx5_query_pcam_reg(struct mlx5_core_dev *dev, u32 *pcam, u8 feature_group,
			u8 access_reg_group);
int mlx5_query_mcam_reg(struct mlx5_core_dev *dev, u32 *mcap, u8 feature_group,
			u8 access_reg_group);

void mlx5_lag_add(struct mlx5_core_dev *dev, struct net_device *netdev);
void mlx5_lag_remove(struct mlx5_core_dev *dev);

void mlx5_add_device(struct mlx5_interface *intf, struct mlx5_priv *priv);
void mlx5_remove_device(struct mlx5_interface *intf, struct mlx5_priv *priv);
void mlx5_attach_device(struct mlx5_core_dev *dev);
void mlx5_detach_device(struct mlx5_core_dev *dev);
bool mlx5_device_registered(struct mlx5_core_dev *dev);
int mlx5_register_device(struct mlx5_core_dev *dev);
void mlx5_unregister_device(struct mlx5_core_dev *dev);
void mlx5_add_dev_by_protocol(struct mlx5_core_dev *dev, int protocol);
void mlx5_remove_dev_by_protocol(struct mlx5_core_dev *dev, int protocol);
struct mlx5_core_dev *mlx5_get_next_phys_dev(struct mlx5_core_dev *dev);
void mlx5_dev_list_lock(void);
void mlx5_dev_list_unlock(void);
int mlx5_dev_list_trylock(void);

bool mlx5_lag_intf_add(struct mlx5_interface *intf, struct mlx5_priv *priv);

int mlx5_mst_dump_init(struct mlx5_core_dev *dev);
int mlx5_mst_capture(struct mlx5_core_dev *dev);
u32 mlx5_mst_dump(struct mlx5_core_dev *dev, void *buff, u32 buff_sz);
void mlx5_mst_free_capture(struct mlx5_core_dev *dev);
void mlx5_mst_dump_cleanup(struct mlx5_core_dev *dev);

int mlx5_icmd_access_register(struct mlx5_core_dev *dev,
			      int reg_id,
			      int method,
			      void *io_buff,
			      u32 io_buff_dw_sz);

void mlx5e_init(void);
void mlx5e_cleanup(void);

int mlx5_modify_other_hca_cap_roce(struct mlx5_core_dev *mdev,
				   int function_id, bool value);
int mlx5_get_other_hca_cap_roce(struct mlx5_core_dev *mdev,
				int function_id, bool *value);

static inline int mlx5_lag_is_lacp_owner(struct mlx5_core_dev *dev)
{
	/* LACP owner conditions:
	 * 1) Function is physical.
	 * 2) LAG is supported by FW.
	 * 3) LAG is managed by driver (currently the only option).
	 */
	return  MLX5_CAP_GEN(dev, vport_group_manager) &&
		   (MLX5_CAP_GEN(dev, num_lag_ports) > 1) &&
		    MLX5_CAP_GEN(dev, lag_master);
}

#endif /* __MLX5_CORE_H__ */
