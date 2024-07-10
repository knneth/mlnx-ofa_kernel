# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_INFINIBAND_ISER)	+= ib_iser.o
obj-$(CONFIG_INFINIBAND_ISER_DUMMY)		+= ib_iser.o

ifeq ($(CONFIG_INFINIBAND_ISER_DUMMY),m)
ib_iser-y := ib_iser_dummy.o
else ifeq ($(CONFIG_ISCSI_TCP),)
ib_iser-y := ib_iser_dummy.o
else
ib_iser-y			:= iser_verbs.o iser_initiator.o iser_memory.o \
				   iscsi_iser.o
endif
