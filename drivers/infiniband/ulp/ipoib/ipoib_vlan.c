/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/module.h>
#include <linux/sched/signal.h>

#include <linux/init.h>
#include <linux/seq_file.h>

#include <linux/uaccess.h>

#include "ipoib.h"

static ssize_t show_parent(struct device *d, struct device_attribute *attr,
			   char *buf)
{
	struct net_device *dev = to_net_dev(d);
	struct ipoib_dev_priv *priv = ipoib_priv(dev);

	return sprintf(buf, "%s\n", priv->parent->name);
}
static DEVICE_ATTR(parent, S_IRUGO, show_parent, NULL);

static bool is_child_unique(struct ipoib_dev_priv *ppriv,
			    struct ipoib_dev_priv *priv)
{
	struct ipoib_dev_priv *tpriv;

	ASSERT_RTNL();

	/*
	 * Since the legacy sysfs interface uses pkey for deletion it cannot
	 * support more than one interface with the same pkey, it creates
	 * ambiguity.  The RTNL interface deletes using the netdev so it does
	 * not have a problem to support duplicated pkeys.
	 */
	if (priv->child_type != IPOIB_LEGACY_CHILD)
		return true;

	list_for_each_entry(tpriv, &ppriv->child_intfs, list) {
		if (tpriv->pkey == priv->pkey &&
		    tpriv->child_type == IPOIB_LEGACY_CHILD &&
		    tpriv->child_index == priv->child_index) 
			return false;
	}

	return true;
}

/*
 * NOTE: If this function fails then the priv->dev will remain valid, however
 * priv will have been freed and must not be touched by caller in the error
 * case.
 *
 * If (ndev->reg_state == NETREG_UNINITIALIZED) then it is up to the caller to
 * free the net_device (just as rtnl_newlink does) otherwise the net_device
 * will be freed when the rtnl is unlocked.
 */
int __ipoib_vlan_add(struct ipoib_dev_priv *ppriv, struct ipoib_dev_priv *priv,
		     u16 pkey, int type)
{
	struct net_device *ndev = priv->dev;
	int result;

	ASSERT_RTNL();

	/*
	 * We do not need to touch priv if register_netdevice fails, so just
	 * always use this flow.
	 */
	ndev->priv_destructor = ipoib_intf_free;

	/*
	 * Racing with unregister of the parent must be prevented by the
	 * caller.
	 */
	WARN_ON(ppriv->dev->reg_state != NETREG_REGISTERED);

	if (pkey == 0 || pkey == 0x8000) {
		result = -EINVAL;
		goto out_early;
	}

	priv->parent = ppriv->dev;
	priv->pkey = pkey;
	priv->child_type = type;

	if (!is_child_unique(ppriv, priv)) {
		result = -ENOTUNIQ;
		goto out_early;
	}

	result = register_netdevice(ndev);
	if (result) {
		ipoib_warn(priv, "failed to initialize; error %i", result);

		/*
		 * register_netdevice sometimes calls priv_destructor,
		 * sometimes not. Make sure it was done.
		 */
		goto out_early;
	}

	/* RTNL childs don't need proprietary sysfs entries */
	if (type == IPOIB_LEGACY_CHILD) {
		if (ipoib_cm_add_mode_attr(ndev))
			goto sysfs_failed;
		if (ipoib_add_pkey_attr(ndev))
			goto sysfs_failed;
		if (ipoib_add_umcast_attr(ndev))
			goto sysfs_failed;

		if (device_create_file(&ndev->dev, &dev_attr_parent))
			goto sysfs_failed;

		if (priv->max_tx_queues > 1) {
			if (ipoib_set_rss_sysfs(priv))
				goto sysfs_failed;
		}

	}

	return 0;

sysfs_failed:
	unregister_netdevice(priv->dev);
	return -ENOMEM;

out_early:
	if (ndev->priv_destructor)
		ndev->priv_destructor(ndev);
	return result;
}

int ipoib_vlan_add(struct net_device *pdev, unsigned short pkey,
		unsigned char child_index)
{
	struct ipoib_dev_priv *ppriv, *priv = NULL;
	char intf_name[IFNAMSIZ];
	struct net_device *ndev;
	int result;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (!rtnl_trylock())
		return restart_syscall();

	if (pdev->reg_state != NETREG_REGISTERED) {
		rtnl_unlock();
		return -EPERM;
	}

	ppriv = ipoib_priv(pdev);

	snprintf(intf_name, sizeof(intf_name), "%s.%04x",
		 ppriv->dev->name, pkey);

	if (!child_index && ppriv->pkey == pkey) {
 		result = -ENOTUNIQ;
 		goto out;
 	}
	
	/*
	 * for the case of non-legacy and same pkey child we wanted to use
	 * a notation of ibN.pkey:index and ibN:index but this is problematic
	 * with tools like ifconfig who treat devices with ":" in their names
	 * as aliases which are restriced, e.t w.r.t counters, etc
	 */
	if (ppriv->pkey != pkey && child_index == 0) /* legacy child */
		snprintf(intf_name, sizeof(intf_name), "%s.%04x",
			 ppriv->dev->name, pkey);
	else if (ppriv->pkey != pkey && child_index != 0) /* non-legacy child */
		snprintf(intf_name, sizeof(intf_name), "%s.%04x.%d",
			 ppriv->dev->name, pkey, child_index);
	else if (ppriv->pkey == pkey && child_index != 0) /* same pkey child */
		snprintf(intf_name, sizeof(intf_name), "%s.%d",
			 ppriv->dev->name, child_index);
	else  {
		ipoib_warn(ppriv, "wrong pkey/child_index pairing %04x %d\n",
			   pkey, child_index);
		result = -EINVAL;
		goto out;
	}

	ndev = ipoib_intf_alloc(ppriv->ca, ppriv->port, intf_name);
	if (IS_ERR(ndev)) {
		result = PTR_ERR(ndev);
		goto out;
	}
	priv = ipoib_priv(ndev);

	/*
	 * keep the child_index inside the priv, in order to find it when it
	 * needs to be deleted.
	 */
	priv->child_index = child_index;

	result = __ipoib_vlan_add(ppriv, priv, pkey, IPOIB_LEGACY_CHILD);

	if (result && ndev->reg_state == NETREG_UNINITIALIZED)
		free_netdev(ndev);

out:
	rtnl_unlock();

	return result;
}

struct ipoib_vlan_delete_work {
	struct work_struct work;
	struct net_device *dev;
};

/*
 * sysfs callbacks of a netdevice cannot obtain the rtnl lock as
 * unregister_netdev ultimately deletes the sysfs files while holding the rtnl
 * lock. This deadlocks the system.
 *
 * A callback can use rtnl_trylock to avoid the deadlock but it cannot call
 * unregister_netdev as that internally takes and releases the rtnl_lock.  So
 * instead we find the netdev to unregister and then do the actual unregister
 * from the global work queue where we can obtain the rtnl_lock safely.
 */
static void ipoib_vlan_delete_task(struct work_struct *work)
{
	struct ipoib_vlan_delete_work *pwork =
		container_of(work, struct ipoib_vlan_delete_work, work);
	struct net_device *dev = pwork->dev;
	struct ipoib_dev_priv *priv = NULL;
	struct ipoib_dev_priv *ppriv = NULL;

	rtnl_lock();

	/* Unregistering tasks can race with another task or parent removal */
	if (dev->reg_state == NETREG_REGISTERED) {
		priv = ipoib_priv(dev);
		ppriv = ipoib_priv(priv->parent);

		ipoib_dbg(ppriv, "delete child vlan %s\n", dev->name);
		unregister_netdevice(dev);
	}

	rtnl_unlock();

	kfree(pwork);
}

int ipoib_vlan_delete(struct net_device *pdev, unsigned short pkey,
		unsigned char child_index)
{
	struct ipoib_dev_priv *ppriv, *priv, *tpriv;
	int rc;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (!rtnl_trylock())
		return restart_syscall();

	if (pdev->reg_state != NETREG_REGISTERED) {
		rtnl_unlock();
		return -EPERM;
	}

	ppriv = ipoib_priv(pdev);

	rc = -ENODEV;
	list_for_each_entry_safe(priv, tpriv, &ppriv->child_intfs, list) {
		if (priv->pkey == pkey &&
		    priv->child_type == IPOIB_LEGACY_CHILD &&
		    priv->child_index == child_index) {
			struct ipoib_vlan_delete_work *work;

			work = kmalloc(sizeof(*work), GFP_KERNEL);
			if (!work) {
				rc = -ENOMEM;
				goto out;
			}

			down_write(&ppriv->vlan_rwsem);
			list_del_init(&priv->list);
			up_write(&ppriv->vlan_rwsem);
			work->dev = priv->dev;
			INIT_WORK(&work->work, ipoib_vlan_delete_task);
			queue_work(ipoib_workqueue, &work->work);

			rc = 0;
			break;
		}
	}

out:
	rtnl_unlock();

	return rc;
}
