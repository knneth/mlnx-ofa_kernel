EXTRA_CFLAGS += $(OPENIB_KERNEL_EXTRA_CFLAGS) \
		$(KERNEL_MEMTRACK_CFLAGS) \
		$(KERNEL_SYSTUNE_CFLAGS) \
		-I$(CWD)/include \
		-I$(CWD)/drivers/net/ethernet/mellanox/mlx4 \
		-I$(CWD)/drivers/net/ethernet/mellanox/mlx5 \

obj-y := compat$(CONFIG_COMPAT_VERSION)/
obj-$(CONFIG_MLX4_CORE)         += drivers/net/ethernet/mellanox/mlx4/
obj-$(CONFIG_MLX4_CORE)         += drivers/infiniband/hw/mlx4/
obj-$(CONFIG_MLX5_CORE)         += drivers/net/ethernet/mellanox/mlx5/core/
obj-$(CONFIG_MLX5_CORE)         += drivers/infiniband/hw/mlx5/
obj-$(CONFIG_MEMTRACK)          += drivers/net/ethernet/mellanox/debug/
