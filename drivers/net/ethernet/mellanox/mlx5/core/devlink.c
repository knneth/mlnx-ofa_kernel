// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2019 Mellanox Technologies */

#include <devlink.h>

#include "mlx5_core.h"
#include "fs_core.h"
#include "eswitch.h"
#include "en/tc_ct.h"

static int mlx5_devlink_flash_update(struct devlink *devlink,
				     const char *file_name,
				     const char *component,
				     struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	const struct firmware *fw;
	int err;

	if (component)
		return -EOPNOTSUPP;

	err = request_firmware_direct(&fw, file_name, &dev->pdev->dev);
	if (err)
		return err;

	err = mlx5_firmware_flash(dev, fw, extack);
	release_firmware(fw);

	return err;
}

static u8 mlx5_fw_ver_major(u32 version)
{
	return (version >> 24) & 0xff;
}

static u8 mlx5_fw_ver_minor(u32 version)
{
	return (version >> 16) & 0xff;
}

static u16 mlx5_fw_ver_subminor(u32 version)
{
	return version & 0xffff;
}

#define DEVLINK_FW_STRING_LEN 32

static int
mlx5_devlink_info_get(struct devlink *devlink, struct devlink_info_req *req,
		      struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	char version_str[DEVLINK_FW_STRING_LEN];
	u32 running_fw, stored_fw;
	int err;

	err = devlink_info_driver_name_put(req, DRIVER_NAME);
	if (err)
		return err;

	err = devlink_info_version_fixed_put(req, "fw.psid", dev->board_id);
	if (err)
		return err;

	err = mlx5_fw_version_query(dev, &running_fw, &stored_fw);
	if (err)
		return err;

	snprintf(version_str, sizeof(version_str), "%d.%d.%04d",
		 mlx5_fw_ver_major(running_fw), mlx5_fw_ver_minor(running_fw),
		 mlx5_fw_ver_subminor(running_fw));
	err = devlink_info_version_running_put(req, "fw.version", version_str);
	if (err)
		return err;

	/* no pending version, return running (stored) version */
	if (stored_fw == 0)
		stored_fw = running_fw;

	snprintf(version_str, sizeof(version_str), "%d.%d.%04d",
		 mlx5_fw_ver_major(stored_fw), mlx5_fw_ver_minor(stored_fw),
		 mlx5_fw_ver_subminor(stored_fw));
	err = devlink_info_version_stored_put(req, "fw.version", version_str);
	if (err)
		return err;

	return 0;
}

static int mlx5_devlink_reload_down(struct devlink *devlink, bool netns_change,
				    struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
#ifdef CONFIG_MLX5_ESWITCH
	u16 mode = 0;

	if (!mlx5_devlink_eswitch_mode_get(devlink, &mode)) {
		if (mode == DEVLINK_ESWITCH_MODE_SWITCHDEV) {
			NL_SET_ERR_MSG_MOD(extack, "Reload not supported in switchdev mode");
			return -EOPNOTSUPP;
		}
	}
#endif

	mlx5_unload_one(dev, false);
	return 0;
}

static int mlx5_devlink_reload_up(struct devlink *devlink,
				  struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	return mlx5_load_one(dev, false);
}

static const struct devlink_ops mlx5_devlink_ops = {
#ifdef CONFIG_MLX5_ESWITCH
	.eswitch_mode_set = mlx5_devlink_eswitch_mode_set,
	.eswitch_mode_get = mlx5_devlink_eswitch_mode_get,
	.eswitch_inline_mode_set = mlx5_devlink_eswitch_inline_mode_set,
	.eswitch_inline_mode_get = mlx5_devlink_eswitch_inline_mode_get,
	.eswitch_encap_mode_set = mlx5_devlink_eswitch_encap_mode_set,
	.eswitch_encap_mode_get = mlx5_devlink_eswitch_encap_mode_get,
	.port_function_hw_addr_get = mlx5_devlink_port_function_hw_addr_get,
	.port_function_hw_addr_set = mlx5_devlink_port_function_hw_addr_set,
#endif
	.flash_update = mlx5_devlink_flash_update,
	.info_get = mlx5_devlink_info_get,
	.reload_down = mlx5_devlink_reload_down,
	.reload_up = mlx5_devlink_reload_up,
};

struct devlink *mlx5_devlink_alloc(void)
{
	return devlink_alloc(&mlx5_devlink_ops, sizeof(struct mlx5_core_dev));
}

void mlx5_devlink_free(struct devlink *devlink)
{
	devlink_free(devlink);
}

static int mlx5_devlink_fs_mode_validate(struct devlink *devlink, u32 id,
					 union devlink_param_value val,
					 struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	char *value = val.vstr;
	int err = 0;

	if (!strcmp(value, "dmfs")) {
		return 0;
	} else if (!strcmp(value, "smfs")) {
		u8 eswitch_mode;
		bool smfs_cap;

		eswitch_mode = mlx5_eswitch_mode(dev->priv.eswitch);
		smfs_cap = mlx5_fs_dr_is_supported(dev);

		if (!smfs_cap) {
			err = -EOPNOTSUPP;
			NL_SET_ERR_MSG_MOD(extack,
					   "Software managed steering is not supported by current device");
		}

		else if (eswitch_mode == MLX5_ESWITCH_OFFLOADS) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Software managed steering is not supported when eswitch offloads enabled.");
			err = -EOPNOTSUPP;
		}
	} else {
		NL_SET_ERR_MSG_MOD(extack,
				   "Bad parameter: supported values are [\"dmfs\", \"smfs\"]");
		err = -EINVAL;
	}

	return err;
}

static int mlx5_devlink_fs_mode_set(struct devlink *devlink, u32 id,
				    struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	enum mlx5_flow_steering_mode mode;

	if (!strcmp(ctx->val.vstr, "smfs"))
		mode = MLX5_FLOW_STEERING_MODE_SMFS;
	else
		mode = MLX5_FLOW_STEERING_MODE_DMFS;
	dev->priv.steering->mode = mode;

	return 0;
}

static int mlx5_devlink_fs_mode_get(struct devlink *devlink, u32 id,
				    struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	if (dev->priv.steering->mode == MLX5_FLOW_STEERING_MODE_SMFS)
		strcpy(ctx->val.vstr, "smfs");
	else
		strcpy(ctx->val.vstr, "dmfs");
	return 0;
}

static int mlx5_devlink_enable_roce_validate(struct devlink *devlink, u32 id,
					     union devlink_param_value val,
					     struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	bool new_state = val.vbool;

	if (new_state && !MLX5_CAP_GEN(dev, roce)) {
		NL_SET_ERR_MSG_MOD(extack, "Device doesn't support RoCE");
		return -EOPNOTSUPP;
	}

	return 0;
}

#ifdef CONFIG_MLX5_ESWITCH
static int mlx5_devlink_large_group_num_validate(struct devlink *devlink, u32 id,
						 union devlink_param_value val,
						 struct netlink_ext_ack *extack)
{
	int group_num = val.vu32;

	if (group_num < 1 || group_num > 1024) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Unsupported group number, supported range is 1-1024");
		return -EOPNOTSUPP;
	}

	return 0;
}

#if IS_ENABLED(CONFIG_NET_CLS_E2E_CACHE)
static int mlx5_devlink_e2e_cache_size_validate(struct devlink *devlink, u32 id,
						union devlink_param_value val,
						struct netlink_ext_ack *extack)
{
	int size = val.vu32;

	if (size < 0) {
		NL_SET_ERR_MSG_MOD(extack, "Unsupported e2e cache size");
		return -EOPNOTSUPP;
	}

	return 0;
}
#endif
static int mlx5_devlink_esw_pet_insert_set(struct devlink *devlink, u32 id,
					   struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	if (!MLX5_ESWITCH_MANAGER(dev))
		return -EOPNOTSUPP;

	return mlx5_esw_offloads_pet_insert_set(dev->priv.eswitch, ctx->val.vbool);
}

static int mlx5_devlink_esw_pet_insert_get(struct devlink *devlink, u32 id,
					   struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	if (!MLX5_ESWITCH_MANAGER(dev))
		return -EOPNOTSUPP;

	ctx->val.vbool = mlx5_eswitch_pet_insert_allowed(dev->priv.eswitch);
	return 0;
}

static int mlx5_devlink_esw_pet_insert_validate(struct devlink *devlink, u32 id,
						union devlink_param_value val,
						struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	u8 esw_mode;

	if (!MLX5_ESWITCH_MANAGER(dev)) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch is unsupported");
		return -EOPNOTSUPP;
	}

	esw_mode = mlx5_eswitch_mode(dev->priv.eswitch);
	if (esw_mode == MLX5_ESWITCH_OFFLOADS) {
		NL_SET_ERR_MSG_MOD(extack,
				   "E-Switch must either disabled or non switchdev mode");
		return -EBUSY;
	}

	if (!mlx5e_esw_offloads_pet_supported(dev->priv.eswitch))
		return -EOPNOTSUPP;

	if (!mlx5_core_is_ecpf(dev))
		return -EOPNOTSUPP;

	return 0;
}
#endif /* CONFIG_MLX5_ESWITCH */

static int mlx5_devlink_ct_max_offloaded_conns_set(struct devlink *devlink, u32 id,
						   struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	mlx5_tc_ct_max_offloaded_conns_set(dev, ctx->val.vu32);
	return 0;
}

static int mlx5_devlink_ct_max_offloaded_conns_get(struct devlink *devlink, u32 id,
						   struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	ctx->val.vu32 = mlx5_tc_ct_max_offloaded_conns_get(dev);
	return 0;
}

static const struct devlink_param mlx5_devlink_params[] = {
	DEVLINK_PARAM_DRIVER(MLX5_DEVLINK_PARAM_ID_CT_ACTION_ON_NAT_CONNS,
			     "ct_action_on_nat_conns", DEVLINK_PARAM_TYPE_BOOL,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     mlx5_devlink_ct_action_on_nat_conns_get,
			     mlx5_devlink_ct_action_on_nat_conns_set,
			     NULL),
	DEVLINK_PARAM_DRIVER(MLX5_DEVLINK_PARAM_ID_FLOW_STEERING_MODE,
			     "flow_steering_mode", DEVLINK_PARAM_TYPE_STRING,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     mlx5_devlink_fs_mode_get, mlx5_devlink_fs_mode_set,
			     mlx5_devlink_fs_mode_validate),
	DEVLINK_PARAM_GENERIC(ENABLE_ROCE, BIT(DEVLINK_PARAM_CMODE_DRIVERINIT),
			      NULL, NULL, mlx5_devlink_enable_roce_validate),
	DEVLINK_PARAM_DRIVER(MLX5_DEVLINK_PARAM_ID_CT_MAX_OFFLOADED_CONNS,
			     "ct_max_offloaded_conns", DEVLINK_PARAM_TYPE_U32,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     mlx5_devlink_ct_max_offloaded_conns_get,
			     mlx5_devlink_ct_max_offloaded_conns_set,
			     NULL),
#ifdef CONFIG_MLX5_ESWITCH
	DEVLINK_PARAM_DRIVER(MLX5_DEVLINK_PARAM_ID_ESW_LARGE_GROUP_NUM,
			     "fdb_large_groups", DEVLINK_PARAM_TYPE_U32,
			     BIT(DEVLINK_PARAM_CMODE_DRIVERINIT),
			     NULL, NULL,
			     mlx5_devlink_large_group_num_validate),
#if IS_ENABLED(CONFIG_NET_CLS_E2E_CACHE)
	DEVLINK_PARAM_DRIVER(MLX5_DEVLINK_PARAM_ID_ESW_E2E_CACHE_SIZE,
			     "e2e_cache_size", DEVLINK_PARAM_TYPE_U32,
			     BIT(DEVLINK_PARAM_CMODE_DRIVERINIT),
			     NULL, NULL,
			     mlx5_devlink_e2e_cache_size_validate),
#endif
	DEVLINK_PARAM_DRIVER(MLX5_DEVLINK_PARAM_ID_ESW_PET_INSERT,
			     "esw_pet_insert", DEVLINK_PARAM_TYPE_BOOL,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     mlx5_devlink_esw_pet_insert_get,
			     mlx5_devlink_esw_pet_insert_set,
			     mlx5_devlink_esw_pet_insert_validate),
#endif /* CONFIG_MLX5_ESWITCH */
};

static void mlx5_devlink_set_params_init_values(struct devlink *devlink)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	union devlink_param_value value;

	if (dev->priv.steering->mode == MLX5_FLOW_STEERING_MODE_DMFS)
		strcpy(value.vstr, "dmfs");
	else
		strcpy(value.vstr, "smfs");
	devlink_param_driverinit_value_set(devlink,
					   MLX5_DEVLINK_PARAM_ID_FLOW_STEERING_MODE,
					   value);

	value.vbool = MLX5_CAP_GEN(dev, roce);
	devlink_param_driverinit_value_set(devlink,
					   DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE,
					   value);

#ifdef CONFIG_MLX5_ESWITCH
	value.vu32 = ESW_OFFLOADS_DEFAULT_NUM_GROUPS;
	devlink_param_driverinit_value_set(devlink,
					   MLX5_DEVLINK_PARAM_ID_ESW_LARGE_GROUP_NUM,
					   value);

	value.vu32 = ESW_DEFAULT_E2E_CACHE_SIZE;
	devlink_param_driverinit_value_set(devlink,
					   MLX5_DEVLINK_PARAM_ID_ESW_E2E_CACHE_SIZE,
					   value);

	if (MLX5_ESWITCH_MANAGER(dev)) {
		value.vbool = false;
		devlink_param_driverinit_value_set(devlink,
						   MLX5_DEVLINK_PARAM_ID_ESW_PET_INSERT,
						   value);
	}
#endif
}

int mlx5_devlink_register(struct devlink *devlink, struct device *dev)
{
	int err;

	err = devlink_register(devlink, dev);
	if (err)
		return err;

	err = devlink_params_register(devlink, mlx5_devlink_params,
				      ARRAY_SIZE(mlx5_devlink_params));
	if (err)
		goto params_reg_err;
	mlx5_devlink_set_params_init_values(devlink);
	devlink_params_publish(devlink);
	return 0;

params_reg_err:
	devlink_unregister(devlink);
	return err;
}

void mlx5_devlink_unregister(struct devlink *devlink)
{
	devlink_params_unregister(devlink, mlx5_devlink_params,
				  ARRAY_SIZE(mlx5_devlink_params));
	devlink_unregister(devlink);
}

int
mlx5_devlink_ct_action_on_nat_conns_set(struct devlink *devlink, u32 id,
					struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	dev->mlx5e_res.ct.ct_action_on_nat_conns = ctx->val.vbool;
	return 0;
}

int
mlx5_devlink_ct_action_on_nat_conns_get(struct devlink *devlink, u32 id,
					struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	ctx->val.vbool = dev->mlx5e_res.ct.ct_action_on_nat_conns;
	return 0;
}
