# SPDX-License-Identifier: GPL-2.0
GCOV_PROFILE := $(CONFIG_MLX5_GCOV)
obj-$(CONFIG_INFINIBAND_IPOIB)			+= ib_ipoib.o

ib_ipoib-y					:= ipoib_main.o \
						   ipoib_ib.o \
						   ipoib_multicast.o \
						   ipoib_verbs.o \
						   ipoib_vlan.o \
						   ipoib_ethtool.o \
						   ipoib_netlink.o \
						   ipoib_genetlink.o
ib_ipoib-$(CONFIG_INFINIBAND_IPOIB_CM)		+= ipoib_cm.o
ib_ipoib-$(CONFIG_INFINIBAND_IPOIB_DEBUG)	+= ipoib_fs.o
