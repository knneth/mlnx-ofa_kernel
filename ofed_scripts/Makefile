ifneq ($(CONFIG_MLNX_EN),m)
EXTRA_CFLAGS += $(OPENIB_KERNEL_EXTRA_CFLAGS) \
		$(KERNEL_MEMTRACK_CFLAGS) \
		-I$(CWD)/include \
		-I$(CWD)/drivers/infiniband/ulp/ipoib$(CONFIG_IPOIB_VERSION) \
		-I$(CWD)/drivers/infiniband/debug \
		-I$(CWD)/net/rds \
		-I$(CWD)/drivers/net/ethernet/mellanox/mlx5/core \
		-I$(CWD)/drivers/infiniband/hw/mlx5 \
		-I$(CWD)/net/mlxdevm \

obj-y := compat$(CONFIG_COMPAT_VERSION)/
obj-$(CONFIG_INFINIBAND)        += drivers/infiniband/
obj-$(CONFIG_INFINIBAND_IPATH)  += drivers/infiniband/hw/ipath/
obj-$(CONFIG_INFINIBAND_EHCA)   += drivers/infiniband/hw/ehca/
obj-$(CONFIG_INFINIBAND_AMSO1100)   += drivers/infiniband/hw/amso1100/
obj-$(CONFIG_MLX5_CORE)         += drivers/net/ethernet/mellanox/mlx5/core/
obj-$(CONFIG_MLXFW)             += drivers/net/ethernet/mellanox/mlxfw/
obj-$(CONFIG_MLXSW_CORE)	+= drivers/net/ethernet/mellanox/mlxsw/
obj-$(CONFIG_RDS)               += net/rds/
obj-$(CONFIG_MLXDEVM)          += net/mlxdevm/
obj-$(CONFIG_MEMTRACK)          += drivers/infiniband/debug/
obj-$(CONFIG_SUNRPC_XPRT_RDMA)  += net/sunrpc/xprtrdma/
obj-$(CONFIG_SUNRPC_XPRT_RDMA_DUMMY)  += net/sunrpc/xprtrdma/
obj-$(CONFIG_SUNRPC_XPRT_RDMA_CLIENT)  += net/sunrpc/xprtrdma/
obj-$(CONFIG_SUNRPC_XPRT_RDMA_SERVER)  += net/sunrpc/xprtrdma/
obj-$(CONFIG_NET_9P_RDMA) += net/9p/
obj-$(CONFIG_BLK_DEV_RNBD) += drivers/block/rnbd/
obj-$(CONFIG_SCSI_SRP_ATTRS)    += drivers/scsi/
obj-$(CONFIG_NVME_CORE)         += drivers/nvme/host/
obj-$(CONFIG_NVME_HOST_WITHOUT_FC)      += drivers/nvme/host/
obj-$(CONFIG_NVME_HOST_WITHOUT_FC)      += drivers/nvme/target/
obj-$(CONFIG_BLK_DEV_NVME)      += drivers/nvme/host/
obj-$(CONFIG_NVME_FABRICS)      += drivers/nvme/host/
obj-$(CONFIG_NVME_FC)           += drivers/nvme/host/
obj-$(CONFIG_NVME_RDMA)         += drivers/nvme/host/
obj-$(CONFIG_NVME_TCP)          += drivers/nvme/host/
obj-$(CONFIG_NVME_APPLE)        += drivers/nvme/host/
obj-$(CONFIG_NVME_HOST_AUTH)         += drivers/nvme/host/
obj-$(CONFIG_NVME_COMMON)       += drivers/nvme/common/
obj-$(CONFIG_NVME_MULTIPATH)    += drivers/nvme/host/
obj-$(CONFIG_NVME_HOST_DUMMY)   += drivers/nvme/host/
obj-$(CONFIG_NVME_TARGET)       += drivers/nvme/target/
obj-$(CONFIG_NVME_TARGET_LOOP)  += drivers/nvme/target/
obj-$(CONFIG_NVME_TARGET_RDMA)  += drivers/nvme/target/
obj-$(CONFIG_NVME_TARGET_TCP)   += drivers/nvme/target/
obj-$(CONFIG_NVME_TARGET_FC)    += drivers/nvme/target/
obj-$(CONFIG_NVME_TARGET_FCLOOP)  += drivers/nvme/target/
obj-$(CONFIG_NVME_TARGET_DUMMY) += drivers/nvme/target/
obj-$(CONFIG_RDMA_RXE_DUMMY)	+= drivers/infiniband/sw/rxe/
obj-$(CONFIG_SMC)		+= net/smc/
obj-$(CONFIG_SMC_DIAG)		+= net/smc/
obj-$(CONFIG_AUXILIARY_BUS)     += drivers/base/
obj-$(CONFIG_FWCTL)     	+= drivers/fwctl/
obj-$(CONFIG_CIFS_SMB_DIRECT)		+= fs/cifs/
obj-$(CONFIG_MLX5_VDPA_NET)	+= drivers/vdpa/mlx5/
obj-$(CONFIG_MLX5_VFIO_PCI) += drivers/vfio/pci/mlx5/

else

EXTRA_CFLAGS += $(OPENIB_KERNEL_EXTRA_CFLAGS) \
		$(KERNEL_MEMTRACK_CFLAGS) \
		$(KERNEL_SYSTUNE_CFLAGS) \
		-I$(CWD)/include \
		-I$(CWD)/drivers/net/ethernet/mellanox/mlx5 \
		-I$(CWD)/drivers/net/ethernet/mellanox/mlxfw \

obj-y := compat$(CONFIG_COMPAT_VERSION)/
obj-$(CONFIG_MLX5_CORE)         += drivers/net/ethernet/mellanox/mlx5/core/
obj-$(CONFIG_MLX5_CORE)         += drivers/infiniband/hw/mlx5/mlx5_ib-dummy/
obj-$(CONFIG_MLXFW)             += drivers/net/ethernet/mellanox/mlxfw/
obj-$(CONFIG_AUXILIARY_BUS)     += drivers/base/
obj-$(CONFIG_FWCTL)   		+= drivers/fwctl/
obj-$(CONFIG_MEMTRACK)          += drivers/net/ethernet/mellanox/debug/
obj-$(CONFIG_MLXDEVM)		+= net/mlxdevm/
endif
