subdir-ccflags-y += -I$(src)/../../drivers/net/ethernet/mellanox/mlx5/core

obj-$(CONFIG_COMPAT_TCF_TUNNEL_KEY_MOD) += act_tunnel_key.o
obj-$(CONFIG_COMPAT_TCF_VLAN_MOD)       += act_vlan.o
obj-$(CONFIG_COMPAT_TCF_PEDIT_MOD)      += act_pedit.o

obj-$(CONFIG_COMPAT_CLS_FLOWER_MOD)     += cls_flower.o
ifneq ($(CONFIG_COMPAT_CLS_FLOWER_MOD),)
       cls_flower-y := cls_flower_compat.o
endif

obj-$(CONFIG_COMPAT_CLS_FLOWER_4_18_MOD) += cls_flower.o act_ct.o
ifneq ($(CONFIG_COMPAT_CLS_FLOWER_4_18_MOD),)
	cls_flower-y := cls_flower_4_18.o
	act_ct-y := act_ct_4_18.o
endif
