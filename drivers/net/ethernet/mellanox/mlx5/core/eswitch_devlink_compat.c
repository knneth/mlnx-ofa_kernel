#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/mlx5_ifc.h>
#include <linux/mlx5/vport.h>
#include <linux/mlx5/fs.h>
#include <uapi/linux/devlink.h>
#include <linux/fs.h>
#include "mlx5_core.h"
#include "eswitch.h"
#include "devlink.h"
#include "en.h"

#ifdef CONFIG_MLX5_ESWITCH

static char *mode_to_str[] = {
	[DEVLINK_ESWITCH_MODE_LEGACY] = "legacy",
	[DEVLINK_ESWITCH_MODE_SWITCHDEV] = "switchdev",
};

static char *inline_to_str[] = {
	[DEVLINK_ESWITCH_INLINE_MODE_NONE] = "none",
	[DEVLINK_ESWITCH_INLINE_MODE_LINK] = "link",
	[DEVLINK_ESWITCH_INLINE_MODE_NETWORK] = "network",
	[DEVLINK_ESWITCH_INLINE_MODE_TRANSPORT] = "transport",
};

static char *encap_to_str[] = {
	[DEVLINK_ESWITCH_ENCAP_MODE_NONE] = "none",
	[DEVLINK_ESWITCH_ENCAP_MODE_BASIC] = "basic",
};

static char *steering_mode_to_str[] = {
	[DEVLINK_ESWITCH_STEERING_MODE_DMFS] = "dmfs",
	[DEVLINK_ESWITCH_STEERING_MODE_SMFS] = "smfs",
};

static char *ipsec_to_str[] = {
	[DEVLINK_ESWITCH_IPSEC_MODE_NONE] = "none",
	[DEVLINK_ESWITCH_IPSEC_MODE_FULL] = "full",
};

static char *vport_match_to_str[] = {
	[DEVLINK_ESWITCH_VPORT_MATCH_MODE_METADATA] = "metadata",
	[DEVLINK_ESWITCH_VPORT_MATCH_MODE_LEGACY] = "legacy",
};

static char *lag_port_select_mode_to_str[] = {
	[DEVLINK_ESWITCH_LAG_PORT_SELECT_MODE_QUEUE_AFFINITY] =
		"queue_affinity",
	[DEVLINK_ESWITCH_LAG_PORT_SELECT_MODE_HASH] = "hash",
};
static char *devlink_param_bool_to_str[] = {
	[0] = "disable",
	[1] = "enable",
};

struct devlink_compat_op {
#ifdef HAVE_DEVLINK_ESWITCH_MODE_SET_EXTACK
	int (*write_enum)(struct devlink *devlink, enum devlink_eswitch_encap_mode set, struct netlink_ext_ack *extack);
	int (*write_enum_ipsec)(struct devlink *devlink, enum devlink_eswitch_ipsec_mode ipsec, struct netlink_ext_ack *extack);
	int (*write_u8)(struct devlink *devlink, u8 set, struct netlink_ext_ack *extack);
	int (*write_u16)(struct devlink *devlink, u16 set, struct netlink_ext_ack *extack);
#else
	int (*write_enum_ipsec)(struct devlink *devlink, enum devlink_eswitch_ipsec_mode ipsec);
	int (*write_enum)(struct devlink *devlink, enum devlink_eswitch_encap_mode set);
	int (*write_u8)(struct devlink *devlink, u8 set);
	int (*write_u16)(struct devlink *devlink, u16 set);
#endif
	int (*read_enum)(struct devlink *devlink, enum devlink_eswitch_encap_mode *read);
	int (*read_enum_ipsec)(struct devlink *devlink, enum devlink_eswitch_ipsec_mode *ipsec);
	int (*read_u8)(struct devlink *devlink, u8 *read);
	int (*read_u16)(struct devlink *devlink, u16 *read);

	int (*read_steering_mode)(struct devlink *devlink, enum devlink_eswitch_steering_mode *read);
	int (*write_steering_mode)(struct devlink *devlink, enum devlink_eswitch_steering_mode set);

	int (*read_vport_match_mode)(struct devlink *devlink, enum devlink_eswitch_vport_match_mode *read);
	int (*write_vport_match_mode)(struct devlink *devlink, enum devlink_eswitch_vport_match_mode set);

	int (*read_lag_port_select_mode)(struct devlink *devlink,
					 enum devlink_eswitch_lag_port_select_mode *read);
	int (*write_lag_port_select_mode)(struct devlink *devlink,
					  enum devlink_eswitch_lag_port_select_mode set);

	int (*read_param_bool)(struct devlink *devlink, u32 id,
			       struct devlink_param_gset_ctx *ctx);
	int (*write_param_bool)(struct devlink *devlink, u32 id,
				struct devlink_param_gset_ctx *ctx);

	char **map;
	int map_size;
	char *compat_name;
};

static struct devlink_compat_op devlink_compat_ops[] =  {
	{
		.read_u16 = mlx5_devlink_eswitch_mode_get,
		.write_u16 = mlx5_devlink_eswitch_mode_set,
		.map = mode_to_str,
		.map_size = ARRAY_SIZE(mode_to_str),
		.compat_name = "mode",
	},
	{
		.read_u8 = mlx5_devlink_eswitch_inline_mode_get,
		.write_u8 = mlx5_devlink_eswitch_inline_mode_set,
		.map = inline_to_str,
		.map_size = ARRAY_SIZE(inline_to_str),
		.compat_name = "inline",
	},
	{
#ifdef HAVE_DEVLINK_HAS_ESWITCH_ENCAP_MODE_SET_GET_WITH_ENUM
		.read_enum = mlx5_devlink_eswitch_encap_mode_get,
		.write_enum = mlx5_devlink_eswitch_encap_mode_set,
#else
		.read_u8 = mlx5_devlink_eswitch_encap_mode_get,
		.write_u8 = mlx5_devlink_eswitch_encap_mode_set,
#endif
		.map = encap_to_str,
		.map_size = ARRAY_SIZE(encap_to_str),
		.compat_name = "encap",
	},
	{
		.read_steering_mode = mlx5_devlink_eswitch_steering_mode_get,
		.write_steering_mode = mlx5_devlink_eswitch_steering_mode_set,
		.map = steering_mode_to_str,
		.map_size = ARRAY_SIZE(steering_mode_to_str),
		.compat_name = "steering_mode",
	},
	{
		.read_enum_ipsec = mlx5_devlink_eswitch_ipsec_mode_get,
		.write_enum_ipsec = mlx5_devlink_eswitch_ipsec_mode_set,
		.map = ipsec_to_str,
		.map_size = ARRAY_SIZE(ipsec_to_str),
		.compat_name = "ipsec_mode",
	},
	{
		.read_vport_match_mode = mlx5_devlink_eswitch_vport_match_mode_get,
		.write_vport_match_mode = mlx5_devlink_eswitch_vport_match_mode_set,
		.map = vport_match_to_str,
		.map_size = ARRAY_SIZE(vport_match_to_str),
		.compat_name = "vport_match_mode",
	},
	{
		.read_param_bool = mlx5_devlink_ct_action_on_nat_conns_get,
		.write_param_bool = mlx5_devlink_ct_action_on_nat_conns_set,
		.compat_name = "ct_action_on_nat_conns",
	},
	{
		.read_lag_port_select_mode =
			mlx5_devlink_eswitch_lag_port_select_mode_get,
		.write_lag_port_select_mode =
			mlx5_devlink_eswitch_lag_port_select_mode_set,
		.map = lag_port_select_mode_to_str,
		.map_size = ARRAY_SIZE(lag_port_select_mode_to_str),
		.compat_name = "lag_port_select_mode",
	},
	{
		.read_param_bool = mlx5_devlink_ct_labels_mapping_get,
		.write_param_bool = mlx5_devlink_ct_labels_mapping_set,
		.compat_name = "ct_labels_mapping",
	},
};

struct compat_devlink {
	struct mlx5_core_dev *mdev;
	struct kobj_attribute devlink_kobj;
};

static ssize_t esw_compat_read(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       char *buf)
{
	struct compat_devlink *cdevlink = container_of(attr,
						       struct compat_devlink,
						       devlink_kobj);
	struct mlx5_core_dev *dev = cdevlink->mdev;
	const char *entname = attr->attr.name;
	int i = 0, ret, len = 0, map_size;
	struct devlink_compat_op *op = 0;
	struct devlink *devlink;
	char **map;
	u8 read8;
	u16 read;

	for (i = 0; i < ARRAY_SIZE(devlink_compat_ops); i++) {
		if (!strcmp(devlink_compat_ops[i].compat_name, entname))
			op = &devlink_compat_ops[i];
	}

	if (!op)
		return -ENOENT;

	devlink = priv_to_devlink(dev);
	map_size = op->map_size;
	map = op->map;

	if (op->read_u16) {
		ret = op->read_u16(devlink, &read);
	} else if (op->read_u8) {
		ret = op->read_u8(devlink, &read8);
		read = read8;
	} else if (op->read_enum) {
		enum devlink_eswitch_encap_mode read_enum;

		ret = op->read_enum(devlink, &read_enum);
		read = read_enum;
	} else if (op->read_steering_mode) {
		enum devlink_eswitch_steering_mode read_steering_mode;

		ret = op->read_steering_mode(devlink, &read_steering_mode);
		read = read_steering_mode;
	} else if (op->read_lag_port_select_mode) {
		enum devlink_eswitch_lag_port_select_mode lag_port_select_mode;

		ret = op->read_lag_port_select_mode(devlink,
						    &lag_port_select_mode);
		read = lag_port_select_mode;
	} else if (op->read_enum_ipsec) {
		enum devlink_eswitch_ipsec_mode read_enum_ipsec;

		ret = op->read_enum_ipsec(devlink, &read_enum_ipsec);
		read = read_enum_ipsec;
	} else if (op->read_vport_match_mode) {
		enum devlink_eswitch_vport_match_mode read_vport_match_mode;

		ret = op->read_vport_match_mode(devlink, &read_vport_match_mode);
		read = read_vport_match_mode;
	} else if (op->read_param_bool) {
		struct devlink_param_gset_ctx ctx;

		ret = op->read_param_bool(devlink, 0, &ctx);
		read = ctx.val.vbool;
		map = devlink_param_bool_to_str;
		map_size = ARRAY_SIZE(devlink_param_bool_to_str);
	} else
		ret = -ENOENT;

	if (ret < 0)
		return ret;

	if (read < map_size && map[read])
		len = sprintf(buf, "%s\n", map[read]);
	else
		len = sprintf(buf, "return: %d\n", read);

	return len;
}

static ssize_t esw_compat_write(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	struct compat_devlink *cdevlink = container_of(attr,
						       struct compat_devlink,
						       devlink_kobj);
	struct mlx5_core_dev *dev = cdevlink->mdev;
#ifdef HAVE_NETLINK_EXT_ACK
	static struct netlink_ext_ack ack = { ._msg = NULL };
#endif
	const char *entname = attr->attr.name;
	struct devlink_compat_op *op = 0;
	int ret = 0, i = 0, map_size;
	struct devlink *devlink;
	u16 set = 0;
	char **map;

	for (i = 0; i < ARRAY_SIZE(devlink_compat_ops); i++) {
		if (!strcmp(devlink_compat_ops[i].compat_name, entname)) {
			op = &devlink_compat_ops[i];
			break;
		}
	}

	if (!op)
		return -ENOENT;

	devlink = priv_to_devlink(dev);
	map = op->map;
	map_size = op->map_size;

	if (op->write_param_bool) {
		map = devlink_param_bool_to_str;
		map_size = ARRAY_SIZE(devlink_param_bool_to_str);
	}

	for (i = 0; i < map_size; i++) {
		if (map[i] && sysfs_streq(map[i], buf)) {
			set = i;
			break;
		}
	}

	if (i >= map_size) {
		mlx5_core_warn(dev, "devlink op %s doesn't support %s argument\n",
			       op->compat_name, buf);
		return -EINVAL;
	}

	if (op->write_u16)
		ret = op->write_u16(devlink, set
#ifdef HAVE_DEVLINK_ESWITCH_MODE_SET_EXTACK
				    , &ack
#endif
				    );
	else if (op->write_u8)
		ret = op->write_u8(devlink, set
#ifdef HAVE_DEVLINK_ESWITCH_MODE_SET_EXTACK
				   , &ack
#endif
				   );
	else if (op->write_enum)
		ret = op->write_enum(devlink, set
#ifdef HAVE_DEVLINK_ESWITCH_MODE_SET_EXTACK
				   , &ack
#endif
				   );
	else if (op->write_steering_mode)
		ret = op->write_steering_mode(devlink, set);
	else if (op->write_lag_port_select_mode)
		ret = op->write_lag_port_select_mode(devlink, set);
	else if (op->write_param_bool) {
		struct devlink_param_gset_ctx ctx;

		ctx.val.vbool = set;
		ret = op->write_param_bool(devlink, 0, &ctx);
	} else if (op->write_vport_match_mode)
		ret = op->write_vport_match_mode(devlink, set);
	else if (op->write_enum_ipsec)
		ret = op->write_enum_ipsec(devlink, set
#ifdef HAVE_DEVLINK_ESWITCH_MODE_SET_EXTACK
				   , &ack
#endif
				   );
	else
		ret = -EINVAL;

#ifdef HAVE_NETLINK_EXT_ACK
	if (ack._msg)
		mlx5_core_warn(dev, "%s\n", ack._msg);
#endif
	if (ret < 0)
		return ret;

	return count;
}

int mlx5_eswitch_compat_sysfs_init(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct kobj_attribute *kobj;
	struct compat_devlink *cdevlink;
	struct mlx5_core_dev *mdev;
	int i;
	int err;

	mdev = priv->mdev;
	mdev->mlx5e_res.compat.compat_kobj = kobject_create_and_add("compat",
								    &netdev->dev.kobj);
	if (!mdev->mlx5e_res.compat.compat_kobj)
		return -ENOMEM;

	mdev->mlx5e_res.compat.devlink_kobj =
			kobject_create_and_add("devlink",
					       mdev->mlx5e_res.compat.compat_kobj);
	if (!mdev->mlx5e_res.compat.devlink_kobj) {
		err = -ENOMEM;
		goto cleanup_compat;
	}

	cdevlink = kzalloc(sizeof(*cdevlink) * ARRAY_SIZE(devlink_compat_ops),
			   GFP_KERNEL);
	if (!cdevlink) {
		err = -ENOMEM;
		goto cleanup_devlink;
	}
	mdev->mlx5e_res.compat.devlink_attributes = cdevlink;

	for (i = 0; i < ARRAY_SIZE(devlink_compat_ops); i++) {
		cdevlink->mdev = priv->mdev;
		kobj = &cdevlink->devlink_kobj;
		sysfs_attr_init(&kobj->attr);
		kobj->attr.mode = 0644;
		kobj->attr.name = devlink_compat_ops[i].compat_name;
		kobj->show = esw_compat_read;
		kobj->store = esw_compat_write;
		WARN_ON_ONCE(sysfs_create_file(mdev->mlx5e_res.compat.devlink_kobj,
					       &kobj->attr));
		cdevlink++;
	}

	return 0;

cleanup_devlink:
	kobject_put(mdev->mlx5e_res.compat.devlink_kobj);
cleanup_compat:
	kobject_put(mdev->mlx5e_res.compat.compat_kobj);
	mdev->mlx5e_res.compat.devlink_kobj = NULL;
	return err;
}

void mlx5_eswitch_compat_sysfs_cleanup(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct compat_devlink *cdevlink;
	struct kobj_attribute *kobj;
	struct mlx5_core_dev *mdev;
	int i;

	mdev = priv->mdev;
	if (!mdev->mlx5e_res.compat.devlink_kobj)
		return;

	cdevlink = mdev->mlx5e_res.compat.devlink_attributes;

	for (i = 0; i < ARRAY_SIZE(devlink_compat_ops); i++) {
		kobj = &cdevlink->devlink_kobj;

		sysfs_remove_file(mdev->mlx5e_res.compat.devlink_kobj, &kobj->attr);
		cdevlink++;
	}
	kfree(mdev->mlx5e_res.compat.devlink_attributes);
	kobject_put(mdev->mlx5e_res.compat.devlink_kobj);
	kobject_put(mdev->mlx5e_res.compat.compat_kobj);

	mdev->mlx5e_res.compat.devlink_kobj = NULL;
}

#else

int mlx5_eswitch_compat_sysfs_init(struct net_device *netdev)
{
	return 0;
}

void mlx5_eswitch_compat_sysfs_cleanup(struct net_device *netdev)
{
}

#endif /* CONFIG_MLX5_ESWITCH */
