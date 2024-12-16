# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_FWCTL_MLX5) += mlx5_fwctl.o

ifeq ($(CONFIG_IS_MARINER), y)
EXTRA_CFLAGS += -fno-exceptions
endif

mlx5_fwctl-y += main.o
