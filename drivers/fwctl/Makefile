# SPDX-License-Identifier: GPL-2.0
#

#ACKPORTS: Added to support 5.17 and below
ccflags-y := -std=gnu11 -Wno-declaration-after-statement

ifeq ($(CONFIG_IS_MARINER), y)
EXTRA_CFLAGS += -fno-exceptions
endif

obj-$(CONFIG_FWCTL) += fwctl.o
obj-$(CONFIG_FWCTL_MLX5) += mlx5/

fwctl-y += main.o
