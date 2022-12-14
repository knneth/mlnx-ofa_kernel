#include <linux/mlx5/driver.h>
#include <linux/mlx5/device.h>
#include "mlx5_core.h"
#include "dev.h"
#include "devlink.h"
#include <net/mlxdevm.h>

#include "cfg_driver.h"

struct mlx5_sf_cfg_devm {
	struct mlxdevm device;
	struct mlx5_sf_dev *sf_dev;
};

enum mlx5_devm_param_id {
	MLX5_DEVM_PARAM_ID_CMPL_EQ_DEPTH,
	MLX5_DEVM_PARAM_ID_ASYNC_EQ_DEPTH,
	MLX5_DEVM_PARAM_ID_DISABLE_ROCE,
	MLX5_DEVM_PARAM_ID_DISABLE_FC,
	MLX5_DEVM_PARAM_ID_DISABLE_NETDEV,
	MLX5_DEVM_PARAM_ID_MAX_CMPL_EQS,
};

static struct mlx5_sf_dev *mlxdevm_to_sf_dev(struct mlxdevm *devm)
{
	struct mlx5_sf_cfg_devm *sf_cfg_dev;

	sf_cfg_dev = container_of(devm, struct mlx5_sf_cfg_devm, device);
	return sf_cfg_dev->sf_dev;
}

static int mlx5_devm_cmpl_eq_depth_get(struct mlxdevm *devm, u32 id,
				       struct mlxdevm_param_gset_ctx *ctx)
{
	struct mlx5_sf_dev *sf_dev = mlxdevm_to_sf_dev(devm);

	ctx->val.vu32 = sf_dev->cmpl_eq_depth;
	return 0;
}

static int mlx5_devm_cmpl_eq_depth_set(struct mlxdevm *devm, u32 id,
				       struct mlxdevm_param_gset_ctx *ctx)
{
	struct mlx5_sf_dev *sf_dev = mlxdevm_to_sf_dev(devm);

	sf_dev->cmpl_eq_depth = ctx->val.vu32;
	return 0;
}

static int mlx5_devm_async_eq_depth_get(struct mlxdevm *devm, u32 id,
					struct mlxdevm_param_gset_ctx *ctx)
{
	struct mlx5_sf_dev *sf_dev = mlxdevm_to_sf_dev(devm);

	ctx->val.vu32 = sf_dev->async_eq_depth;
	return 0;
}

static int mlx5_devm_async_eq_depth_set(struct mlxdevm *devm, u32 id,
					struct mlxdevm_param_gset_ctx *ctx)
{
	struct mlx5_sf_dev *sf_dev = mlxdevm_to_sf_dev(devm);

	sf_dev->async_eq_depth = ctx->val.vu32;
	return 0;
}

static int mlx5_devm_eq_depth_validate(struct mlxdevm *devm, u32 id,
				       union mlxdevm_param_value val,
				       struct netlink_ext_ack *extack)
{
	return (val.vu32 >= 64 && val.vu32 <= 4096) ? 0 : -EINVAL;
}

static int mlx5_devm_disable_fc_get(struct mlxdevm *devm, u32 id,
				    struct mlxdevm_param_gset_ctx *ctx)
{
	struct mlx5_sf_dev *sf_dev = mlxdevm_to_sf_dev(devm);

	ctx->val.vbool = sf_dev->disable_fc;
	return 0;
}

static int mlx5_devm_disable_fc_set(struct mlxdevm *devm, u32 id,
				    struct mlxdevm_param_gset_ctx *ctx)
{
	struct mlx5_sf_dev *sf_dev = mlxdevm_to_sf_dev(devm);

	sf_dev->disable_fc = ctx->val.vbool;
	return 0;
}

static int mlx5_devm_disable_netdev_get(struct mlxdevm *devm, u32 id,
					struct mlxdevm_param_gset_ctx *ctx)
{
	struct mlx5_sf_dev *sf_dev = mlxdevm_to_sf_dev(devm);

	ctx->val.vbool = sf_dev->disable_netdev;
	return 0;
}

static int mlx5_devm_disable_netdev_set(struct mlxdevm *devm, u32 id,
					struct mlxdevm_param_gset_ctx *ctx)
{
	struct mlx5_sf_dev *sf_dev = mlxdevm_to_sf_dev(devm);

	sf_dev->disable_netdev = ctx->val.vbool;
	return 0;
}

static int mlx5_devm_max_cmpl_eqs_get(struct mlxdevm *devm, u32 id,
				      struct mlxdevm_param_gset_ctx *ctx)
{
	struct mlx5_sf_dev *sf_dev = mlxdevm_to_sf_dev(devm);

	ctx->val.vu16 = sf_dev->max_cmpl_eqs;
	return 0;
}

static int mlx5_devm_max_cmpl_eqs_set(struct mlxdevm *devm, u32 id,
				      struct mlxdevm_param_gset_ctx *ctx)
{
	struct mlx5_sf_dev *sf_dev = mlxdevm_to_sf_dev(devm);

	sf_dev->max_cmpl_eqs = ctx->val.vu16;
	return 0;
}

static int mlx5_devm_max_cmpl_eqs_validate(struct mlxdevm *devm, u32 id,
					   union mlxdevm_param_value val,
					   struct netlink_ext_ack *extack)
{
	return (val.vu16 != 0) ? 0 : -EINVAL;
}

static const struct mlxdevm_param mlx5_sf_cfg_devm_params[] = {
	MLXDEVM_PARAM_DRIVER(MLX5_DEVM_PARAM_ID_CMPL_EQ_DEPTH,
			     "cmpl_eq_depth", MLXDEVM_PARAM_TYPE_U32,
			     BIT(MLXDEVM_PARAM_CMODE_RUNTIME),
			     mlx5_devm_cmpl_eq_depth_get, mlx5_devm_cmpl_eq_depth_set,
			     mlx5_devm_eq_depth_validate),
	MLXDEVM_PARAM_DRIVER(MLX5_DEVM_PARAM_ID_ASYNC_EQ_DEPTH,
			     "async_eq_depth", MLXDEVM_PARAM_TYPE_U32,
			     BIT(MLXDEVM_PARAM_CMODE_RUNTIME),
			     mlx5_devm_async_eq_depth_get, mlx5_devm_async_eq_depth_set,
			     mlx5_devm_eq_depth_validate),
	MLXDEVM_PARAM_DRIVER(MLX5_DEVM_PARAM_ID_DISABLE_FC,
			     "disable_fc", MLXDEVM_PARAM_TYPE_BOOL,
			     BIT(MLXDEVM_PARAM_CMODE_RUNTIME),
			     mlx5_devm_disable_fc_get, mlx5_devm_disable_fc_set,
			     NULL),
	MLXDEVM_PARAM_DRIVER(MLX5_DEVM_PARAM_ID_DISABLE_NETDEV,
			     "disable_netdev", MLXDEVM_PARAM_TYPE_BOOL,
			     BIT(MLXDEVM_PARAM_CMODE_RUNTIME),
			     mlx5_devm_disable_netdev_get, mlx5_devm_disable_netdev_set,
			     NULL),
	MLXDEVM_PARAM_DRIVER(MLX5_DEVM_PARAM_ID_MAX_CMPL_EQS,
			     "max_cmpl_eqs", MLXDEVM_PARAM_TYPE_U16,
			     BIT(MLXDEVM_PARAM_CMODE_RUNTIME),
			     mlx5_devm_max_cmpl_eqs_get, mlx5_devm_max_cmpl_eqs_set,
			     mlx5_devm_max_cmpl_eqs_validate),
};

static void mlx5_sf_cfg_devm_set_params_init_values(struct mlxdevm *devm)
{
	struct mlx5_sf_cfg_devm *sf_cfg_dev;
	union mlxdevm_param_value value;

	sf_cfg_dev = container_of(devm, struct mlx5_sf_cfg_devm, device);

	value.vbool = false;
	mlxdevm_param_driverinit_value_set(devm, MLX5_DEVM_PARAM_ID_DISABLE_ROCE, value);

	value.vbool = false;
	mlxdevm_param_driverinit_value_set(devm, MLX5_DEVM_PARAM_ID_DISABLE_FC, value);

	value.vbool = false;
	mlxdevm_param_driverinit_value_set(devm, MLX5_DEVM_PARAM_ID_DISABLE_NETDEV, value);

	value.vu32 = 0;
	mlxdevm_param_driverinit_value_set(devm, MLX5_DEVM_PARAM_ID_CMPL_EQ_DEPTH, value);

	value.vu32 = 0;
	mlxdevm_param_driverinit_value_set(devm, MLX5_DEVM_PARAM_ID_ASYNC_EQ_DEPTH, value);

	value.vu16 = 0;
	mlxdevm_param_driverinit_value_set(devm, MLX5_DEVM_PARAM_ID_MAX_CMPL_EQS, value);

}

static int mlx5_sf_cfg_dev_probe(struct auxiliary_device *adev,
				 const struct auxiliary_device_id *id)
{
	struct mlx5_sf_dev *sf_dev = container_of(adev, struct mlx5_sf_dev, adev);
	struct mlx5_sf_cfg_devm *sf_cfg_dev;
	struct mlxdevm *devm;
	int err;

	sf_cfg_dev = kzalloc(sizeof(*sf_cfg_dev), GFP_KERNEL);
	if (!sf_cfg_dev)
		return -ENOMEM;

	devm = &sf_cfg_dev->device;
	devm->device = &sf_dev->adev.dev;
	sf_cfg_dev->sf_dev = sf_dev;

	err = mlxdevm_register(devm);
	if (err)
		goto err;

	err = mlxdevm_params_register(devm, mlx5_sf_cfg_devm_params,
				      ARRAY_SIZE(mlx5_sf_cfg_devm_params));
	if (err)
		goto params_reg_err;

	mlx5_sf_cfg_devm_set_params_init_values(devm);
	mlxdevm_params_publish(devm);

	dev_set_drvdata(&sf_dev->adev.dev, sf_cfg_dev);
	return 0;

params_reg_err:
	mlxdevm_unregister(devm);
err:
	kfree(sf_cfg_dev);
	return err;
}

static void mlx5_sf_cfg_dev_remove(struct auxiliary_device *adev)
{
	struct mlx5_sf_dev *sf_dev = container_of(adev, struct mlx5_sf_dev, adev);
	struct mlx5_sf_cfg_devm *sf_cfg_dev;
	struct mlxdevm *devm;

	sf_cfg_dev = dev_get_drvdata(&sf_dev->adev.dev);
	devm = &sf_cfg_dev->device;
	mlxdevm_params_unregister(devm, mlx5_sf_cfg_devm_params,
				  ARRAY_SIZE(mlx5_sf_cfg_devm_params));
	mlxdevm_unregister(devm);
	kfree(sf_cfg_dev);
}

static const struct auxiliary_device_id mlx5_sf_dev_id_table[] = {
	{ .name = MLX5_ADEV_NAME "." MLX5_SF_DEV_ID_NAME, },
	{ },
};

static struct auxiliary_driver mlx5_sf_cfg_driver = {
	.name = "sf_cfg",
	.probe = mlx5_sf_cfg_dev_probe,
	.remove = mlx5_sf_cfg_dev_remove,
	.id_table = mlx5_sf_dev_id_table,
};

int mlx5_sf_cfg_driver_register(void)
{
	return auxiliary_driver_register(&mlx5_sf_cfg_driver);
}

void mlx5_sf_cfg_driver_unregister(void)
{
	auxiliary_driver_unregister(&mlx5_sf_cfg_driver);
}
