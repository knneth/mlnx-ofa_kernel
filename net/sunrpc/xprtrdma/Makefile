# SPDX-License-Identifier: GPL-2.0

ifeq ($(CONFIG_GPU_DIRECT_STORAGE),y)
ccflags-y				+= -DCONFIG_NVFS
endif

obj-$(CONFIG_SUNRPC_XPRT_RDMA) += rpcrdma.o

obj-$(CONFIG_SUNRPC_XPRT_RDMA_DUMMY) += rpcrdma.o
obj-$(CONFIG_SUNRPC_XPRT_RDMA_DUMMY) += xprtrdma.o
obj-$(CONFIG_SUNRPC_XPRT_RDMA_DUMMY) += svcrdma.o
obj-$(CONFIG_SUNRPC_XPRT_RDMA_CLIENT) += xprtrdma.o
obj-$(CONFIG_SUNRPC_XPRT_RDMA_SERVER) += svcrdma.o
xprtrdma-y := xprtrdma_dummy.o
svcrdma-y := svcrdma_dummy.o

ifeq ($(CONFIG_SUNRPC_XPRT_RDMA_DUMMY),m)
rpcrdma-y := rpcrdma_dummy.o
else
rpcrdma-y := transport.o rpc_rdma.o verbs.o \
	frwr_ops.o \
	svc_rdma.o svc_rdma_backchannel.o svc_rdma_transport.o \
	svc_rdma_sendto.o svc_rdma_recvfrom.o svc_rdma_rw.o \
	svc_rdma_pcl.o module.o

ifeq ($(CONFIG_GPU_DIRECT_STORAGE),y)
rpcrdma-y += nvfs_rpc_rdma.o
endif

rpcrdma-$(CONFIG_SUNRPC_BACKCHANNEL) += backchannel.o
endif
