# SPDX-License-Identifier: GPL-2.0

# Retpoline support: check if this is the right architecture and that
# the kernel does not support it already.
# Alternatively, if we are called from the main mlnx-ofa build system,
# CONFIG_RETPOLINE will be set by the configure script, however
# subdir-ccflags-y will be set by the toplevel Makefile.
ifneq (,$(findstring $(ARCH),i386 x86_64))
  ifndef CONFIG_RETPOLINE
    ifneq (,$(shell awk 'BEGIN {if ($(VERSION).$(PATCHLEVEL) < 4.15) {print 1}}' </dev/null))
      CFLAGS_RETPOLINE=-mindirect-branch=thunk-inline -mindirect-branch-register -DRETPOLINE_MLNX
    endif
  endif
endif

# Enable retpoline support if the above holds and the compiler supports it.
ifneq (,$(CFLAGS_RETPOLINE))
  do_retpoline = $(call cc-option-yn, -mindirect-branch-register)
  subdir-ccflags-$(do_retpoline) += $(CFLAGS_RETPOLINE)
endif

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
	module.o

ifeq ($(CONFIG_GPU_DIRECT_STORAGE),y)
rpcrdma-y += nvfs_rpc_rdma.o
endif

rpcrdma-$(CONFIG_SUNRPC_BACKCHANNEL) += backchannel.o
endif
