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
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct devlink *devlink = priv_to_devlink(dev);
	const char *entname = attr->attr.name;
	struct devlink_compat_op *op = 0;
	int i = 0, ret, len = 0;
	enum devlink_eswitch_encap_mode read_enum;
	enum devlink_eswitch_ipsec_mode read_enum_ipsec;
	enum devlink_eswitch_steering_mode read_steering_mode;
	enum devlink_eswitch_vport_match_mode read_vport_match_mode;
	u8 read8;
	u16 read;

	for (i = 0; i < ARRAY_SIZE(devlink_compat_ops); i++) {
		if (!strcmp(devlink_compat_ops[i].compat_name, entname))
			op = &devlink_compat_ops[i];
	}

	if (!op)
		return -ENOENT;

	if (esw && atomic_inc_return(&esw->handler.in_progress) > 1)
		return -EBUSY;

	if (op->read_u16) {
		ret = op->read_u16(devlink, &read);
	} else if (op->read_u8) {
		ret = op->read_u8(devlink, &read8);
		read = read8;
	} else if (op->read_enum) {
		ret = op->read_enum(devlink, &read_enum);
		read = read_enum;
	} else if (op->read_steering_mode) {
		ret = op->read_steering_mode(devlink, &read_steering_mode);
		read = read_steering_mode;
	} else if (op->read_enum_ipsec) {
		ret = op->read_enum_ipsec(devlink, &read_enum_ipsec);
		read = read_enum_ipsec;
	} else if (op->read_vport_match_mode) {
		ret = op->read_vport_match_mode(devlink, &read_vport_match_mode);
		read = read_vport_match_mode;
	} else
		ret = -ENOENT;

	if (esw)
		atomic_set(&esw->handler.in_progress, 0);

	if (ret < 0)
		return ret;

	if (read < op->map_size && op->map[read])
		len = sprintf(buf, "%s\n", op->map[read]);
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
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct devlink *devlink = priv_to_devlink(dev);
#ifdef HAVE_NETLINK_EXT_ACK
	static struct netlink_ext_ack ack = { ._msg = NULL };
#endif
	const char *entname = attr->attr.name;
	struct devlink_compat_op *op = 0;
	u16 set = 0;
	int ret = 0, i = 0;

	for (i = 0; i < ARRAY_SIZE(devlink_compat_ops); i++) {
		if (!strcmp(devlink_compat_ops[i].compat_name, entname)) {
			op = &devlink_compat_ops[i];
			break;
		}
	}

	if (!op)
		return -ENOENT;

	for (i = 0; i < op->map_size; i++) {
		if (op->map[i] && sysfs_streq(op->map[i], buf)) {
			set = i;
			break;
		}
	}

	if (i >= op->map_size) {
		mlx5_core_warn(dev, "devlink op %s doesn't support %s argument\n",
			       op->compat_name, buf);
		return -EINVAL;
	}

	/* For eswitch_mode_set, in_progress will be incremented inside
	 * the callback function, and the value will be kept after return
	 * because it will be set to zero later when eswitch offloads
	 * start/stop is really finished by worker.
	 */
	if (esw && (strcmp(entname, "mode") != 0) &&
	    atomic_inc_return(&esw->handler.in_progress) > 1)
		return -EBUSY;

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
	else if (op->write_vport_match_mode)
		ret = op->write_vport_match_mode(devlink, set);
	else if (op->write_enum_ipsec)
		ret = op->write_enum_ipsec(devlink, set
#ifdef HAVE_DEVLINK_ESWITCH_MODE_SET_EXTACK
				   , &ack
#endif
				   );
	else
		ret = -EINVAL;

	if (esw && strcmp(entname, "mode") != 0)
		atomic_set(&esw->handler.in_progress, 0);

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
	int i;
	int err;

	priv->compat_kobj = kobject_create_and_add("compat",
						   &netdev->dev.kobj);
	if (!priv->compat_kobj)
		return -ENOMEM;

	priv->devlink_kobj = kobject_create_and_add("devlink",
						    priv->compat_kobj);
	if (!priv->devlink_kobj) {
		err = -ENOMEM;
		goto cleanup_compat;
	}

	cdevlink = kzalloc(sizeof(*cdevlink) * ARRAY_SIZE(devlink_compat_ops),
			   GFP_KERNEL);
	if (!cdevlink) {
		err = -ENOMEM;
		goto cleanup_devlink;
	}
	priv->devlink_attributes = cdevlink;

	for (i = 0; i < ARRAY_SIZE(devlink_compat_ops); i++) {
		cdevlink->mdev = priv->mdev;
		kobj = &cdevlink->devlink_kobj;
		sysfs_attr_init(&kobj->attr);
		kobj->attr.mode = 0644;
		kobj->attr.name = devlink_compat_ops[i].compat_name;
		kobj->show = esw_compat_read;
		kobj->store = esw_compat_write;
		WARN_ON_ONCE(sysfs_create_file(priv->devlink_kobj,
					       &kobj->attr));
		cdevlink++;
	}

	return 0;

cleanup_devlink:
	kobject_put(priv->devlink_kobj);
cleanup_compat:
	kobject_put(priv->compat_kobj);
	priv->devlink_kobj = NULL;
	return err;
}

void mlx5_eswitch_compat_sysfs_cleanup(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct compat_devlink *cdevlink;
	struct kobj_attribute *kobj;
	int i;

	if (!priv->devlink_kobj)
		return;

	cdevlink = priv->devlink_attributes;

	for (i = 0; i < ARRAY_SIZE(devlink_compat_ops); i++) {
		kobj = &cdevlink->devlink_kobj;

		sysfs_remove_file(priv->devlink_kobj, &kobj->attr);
		cdevlink++;
	}
	kfree(priv->devlink_attributes);
	kobject_put(priv->devlink_kobj);
	kobject_put(priv->compat_kobj);

	priv->devlink_kobj = NULL;
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
