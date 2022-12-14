obj-m += mlx_compat.o
#compat-objs :=

obj-$(CONFIG_COMPAT_FIRMWARE_CLASS) += compat_firmware_class.o
obj-$(CONFIG_COMPAT_NET_SCH_CODEL) += sch_codel.o
obj-$(CONFIG_COMPAT_NET_SCH_FQ_CODEL) += sch_fq_codel.o

mlx_compat-y += main.o

mlx_compat-$(CONFIG_COMPAT_KFIFO) += kfifo.o

mlx_compat-$(CONFIG_COMPAT_KERNEL_3_10) += compat-3.10.o
mlx_compat-$(CONFIG_COMPAT_KERNEL_3_11) += compat-3.11.o
mlx_compat-$(CONFIG_COMPAT_KERNEL_3_12) += compat-3.12.o
mlx_compat-$(CONFIG_COMPAT_KERNEL_3_13) += compat-3.13.o
mlx_compat-$(CONFIG_COMPAT_KERNEL_3_15) += compat-3.15.o
mlx_compat-$(CONFIG_COMPAT_KERNEL_3_16) += compat-3.16.o
mlx_compat-$(CONFIG_COMPAT_KERNEL_3_18) += compat-3.18.o

mlx_compat-$(CONFIG_COMPAT_KERNEL_4_1) += compat-4.1.o

mlx_compat-$(CONFIG_COMPAT_CORDIC) += cordic.o
mlx_compat-$(CONFIG_COMPAT_CRC8) += crc8.o
mlx_compat-$(CONFIG_COMPAT_FLOW_DISSECTOR) += flow_dissector.o
mlx_compat-y += string.o
mlx_compat-y += output_core.o
mlx_compat-y += idr.o
mlx_compat-y += interval_tree.o

ifndef CONFIG_64BIT
ifndef CONFIG_GENERIC_ATOMIC64
  mlx_compat-y += compat_atomic.o
endif
endif

mlx_compat-y += xz_crc32.o
mlx_compat-y += xz_dec_lzma2.o
mlx_compat-y += xz_dec_stream.o
mlx_compat-y += xz_dec_syms.o
mlx_compat-$(CONFIG_XZ_DEC_BCJ) += xz_dec_bcj.o

mlx_compat-y += mm_util.o
mlx_compat-y += uuid.o
mlx_compat-y += rhashtable.o
mlx_compat-y += ../block/blk-mq-rdma.o
mlx_compat-y += exec.o
mlx_compat-y += pci.o
mlx_compat-y += syscall.o
mlx_compat-y += mmu_notifier.o
mlx_compat-y += xarray.o
mlx_compat-y += rdma_dim.o
mlx_compat-y += dim.o
mlx_compat-y += net_dim.o
ifdef CONFIG_MLX5_CLS_ACT
mlx_compat-y += flow_offload.o
mlx_compat-y += cls_api.o
mlx_compat-$(CONFIG_COMPAT_CLS_FLOWER_4_18_MOD) += nf_flow_table_core.o nf_flow_table_offload.o
endif

mlx_compat-y += bitmap.o
