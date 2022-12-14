# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_MLX5_INFINIBAND) += mlx5_ib.o

mlx5_ib-y := ah.o \
	     cmd.o \
	     cong.o \
	     counters.o \
	     cq.o \
	     doorbell.o \
	     gsi.o \
	     ib_virt.o \
	     mad.o \
	     main.o \
	     main_ext.o \
	     mem.o \
	     mr.o \
	     nvmf.o  \
	     qp.o \
	     qpc.o \
	     qp_nvmf.o  \
	     restrack.o \
	     srq.o \
	     srq_cmd.o \
	     srq_nvmf.o \
	     wr.o

mlx5_ib-$(CONFIG_INFINIBAND_ON_DEMAND_PAGING) += odp.o
mlx5_ib-$(CONFIG_MLX5_ESWITCH) += ib_rep.o
mlx5_ib-$(CONFIG_INFINIBAND_USER_ACCESS) += devx.o \
					    fs.o \
					    qos.o \
					    std_types.o
