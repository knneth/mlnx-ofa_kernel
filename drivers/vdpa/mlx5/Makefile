subdir-ccflags-y += -I$(src)/core

ifeq ($(CONFIG_MLX5_VDPA_NET_DUMMY),y)
obj-m += mlx5_vdpa.o
mlx5_vdpa-y := mlx5_vdpa_dummy.o
else
obj-$(CONFIG_MLX5_VDPA_NET) += mlx5_vdpa.o
mlx5_vdpa-$(CONFIG_MLX5_VDPA_NET) += net/mlx5_vnet.o core/resources.o core/mr.o net/debug.o
endif
