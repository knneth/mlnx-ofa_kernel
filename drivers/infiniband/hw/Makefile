# SPDX-License-Identifier: GPL-2.0
GCOV_PROFILE := $(CONFIG_MLX5_GCOV)
obj-$(CONFIG_INFINIBAND_MTHCA)		+= mthca/
obj-$(CONFIG_INFINIBAND_QIB)		+= qib/
obj-$(CONFIG_INFINIBAND_CXGB3)		+= cxgb3/
obj-$(CONFIG_INFINIBAND_CXGB4)		+= cxgb4/
obj-m					+= efa/ # For SLES12 SP5 errata kernels.
obj-$(CONFIG_INFINIBAND_IRDMA)          += irdma/
obj-m					+= mana/ # For SLES15 SP5 errata kernels.
obj-$(CONFIG_INFINIBAND_I40IW)		+= i40iw/
obj-$(CONFIG_MLX4_INFINIBAND)		+= mlx4/
obj-$(CONFIG_MLX5_INFINIBAND)		+= mlx5/
obj-$(CONFIG_INFINIBAND_NES)		+= nes/
obj-$(CONFIG_INFINIBAND_OCRDMA)		+= ocrdma/
obj-$(CONFIG_INFINIBAND_VMWARE_PVRDMA)	+= vmw_pvrdma/
obj-$(CONFIG_INFINIBAND_USNIC)		+= usnic/
obj-$(CONFIG_INFINIBAND_HFI1)		+= hfi1/

ifneq ($(CONFIG_INFINIBAND_HNS),)
obj-$(CONFIG_INFINIBAND_HNS)		+= hns/
else
obj-$(CONFIG_INFINIBAND_HNS_HIP08)	+= hns/
endif

obj-$(CONFIG_INFINIBAND_QEDR)		+= qedr/
obj-$(CONFIG_INFINIBAND_BNXT_RE)	+= bnxt_re/
obj-$(CONFIG_INFINIBAND_ERDMA)		+= erdma/
