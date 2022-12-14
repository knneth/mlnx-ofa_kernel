#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/mlx5_ifc.h>
#include <linux/mlx5/vport.h>
#include <linux/mlx5/fs.h>
#include <linux/fs.h>
#include "mlx5_core.h"
#include "eswitch.h"

#ifndef HAVE_DEVLINK_H

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

struct devlink_compat_op {
	int (*write_u8)(struct devlink *devlink, u8 set);
	int (*write_u16)(struct devlink *devlink, u16 set);
	int (*read_u8)(struct devlink *devlink, u8 *read);
	int (*read_u16)(struct devlink *devlink, u16 *read);
	char **map;
	int map_size;
	char *compat_name;
	struct mlx5_eswitch *esw;
};

static struct devlink_compat_op compat_ops[] =  {
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
		.read_u8 = mlx5_devlink_eswitch_encap_mode_get,
		.write_u8 = mlx5_devlink_eswitch_encap_mode_set,
		.map = encap_to_str,
		.map_size = ARRAY_SIZE(encap_to_str),
		.compat_name = "encap",
	},
};

static ssize_t esw_compat_read(struct file *filp, char __user *buf,
			       size_t count, loff_t *pos)
{
	struct mlx5_core_dev *dev = filp->private_data;
	struct devlink *devlink = priv_to_devlink(dev);
	struct dentry *dentry = filp->f_path.dentry;
	const char *entname = dentry->d_name.name;
	struct devlink_compat_op *op = 0;
	char strout[32] = "unknown\n";
	int i = 0, ret;
	u8 read8;
	u16 read;

	if (*pos)
		return 0;

	for (i = 0; i < ARRAY_SIZE(compat_ops); i++) {
		if (!strcmp(compat_ops[i].compat_name, entname))
			op = &compat_ops[i];
	}

	if (!op)
		return -ENOENT;

	if (op->read_u16) {
		ret = op->read_u16(devlink, &read);
	} else {
		ret = op->read_u8(devlink, &read8);
		read = read8;
	}

	if (ret < 0)
		return ret;

	if (read < op->map_size && op->map[read])
		sprintf(strout, "%s\n", op->map[read]);

	if (copy_to_user(buf, strout, strlen(strout)))
		return -EFAULT;

	*pos += strlen(strout);
	ret = strlen(strout);

	return ret;
}

static ssize_t esw_compat_write(struct file *filp, const char __user *buf,
				size_t count, loff_t *pos)
{
	struct mlx5_core_dev *dev = filp->private_data;
	struct devlink *devlink = priv_to_devlink(dev);
	struct dentry *dentry = filp->f_path.dentry;
	const char *entname = dentry->d_name.name;
	struct devlink_compat_op *op = 0;
	char tempbuf[32] = { 0 };
	u16 set = 0;
	int ret = 0, i = 0;

	if (count <= 1)
		return max_t(size_t, count, 0);

	for (i = 0; i < ARRAY_SIZE(compat_ops); i++) {
		if (!strcmp(compat_ops[i].compat_name, entname)) {
			op = &compat_ops[i];
			break;
		}
	}

	if (!op)
		return -ENOENT;

	if (copy_from_user(tempbuf, buf, min(count, sizeof(tempbuf)) - 1))
		return -EFAULT;

	for (i = 0; i < op->map_size; i++) {
		if (op->map[i] && !strcmp(op->map[i], tempbuf)) {
			set = i;
			break;
		}
	}

	if (i >= op->map_size)
		return -EINVAL;

	if (op->write_u16)
		ret = op->write_u16(devlink, set);
	else
		ret = op->write_u8(devlink, set);

	if (ret < 0)
		return ret;

	return count;
}

static const struct file_operations esw_compat_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.read	= esw_compat_read,
	.write	= esw_compat_write,
};

int mlx5_eswitch_compat_debugfs_init(struct mlx5_eswitch *esw)
{
	struct mlx5_core_dev *dev = esw->dev;
	int i;

	if (!dev || !dev->priv.dbg_root)
		return 0;

	dev->priv.compat_debugfs = debugfs_create_dir("compat",
						      dev->priv.dbg_root);
	if (dev->priv.compat_debugfs) {
		for (i = 0; i < ARRAY_SIZE(compat_ops); i++) {
			debugfs_create_file(compat_ops[i].compat_name, 0400,
					    dev->priv.compat_debugfs, dev,
					    &esw_compat_fops);
		}
	}

	return dev->priv.compat_debugfs ? 0 : -ENOMEM;
}

void mlx5_eswitch_compat_debugfs_cleanup(struct mlx5_eswitch *esw)
{
	struct mlx5_core_dev *dev = esw->dev;

	if (!dev || !dev->priv.dbg_root || !dev->priv.compat_debugfs)
		return;

	debugfs_remove_recursive(dev->priv.compat_debugfs);
}

#else

int mlx5_eswitch_compat_debugfs_init(struct mlx5_eswitch *esw)
{
	return 0;
}

void mlx5_eswitch_compat_debugfs_cleanup(struct mlx5_eswitch *esw)
{
}

#endif /* HAVE_DEVLINK_H */
