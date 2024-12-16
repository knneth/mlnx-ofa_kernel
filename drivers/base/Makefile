# SPDX-License-Identifier: GPL-2.0
# Makefile for the Linux device tree

obj-$(CONFIG_AUXILIARY_BUS) += auxiliary.o
auxiliary-y += auxiliary_main.o
ifeq ($(CONFIG_SYSFS),y)
auxiliary-y += auxiliary_sysfs.o
endif
