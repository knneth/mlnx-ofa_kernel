/*
 * Copyright (c) 2012 Mellanox Technologies, Inc. -  All rights reserved.
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

#include "ipoib.h"
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/if.h>

/* netlink flags bits */
#define GENL_PATH_NOTIFICATIONS_ACTIVE 2
#define GENL_MC_NOTIFICATIONS_ACTIVE 4

/* attributes types
 * 0 causes issues with Netlink */
enum {
	ATTRIBUTE_UNSPECIFIED,
	PATH_ADD,
	PATH_DEL,
	__IPOIB_NETLINK_ATT_MAX
};

#define	IPOIB_NETLINK_ATT_MAX (__IPOIB_NETLINK_ATT_MAX - 1)

/* command types
 * 0 causes issues with Netlink */
enum {
	COMMAND_UNSPECIFIED,
	REPORT_PATH
};

enum ipoib_genl_grps_id {
	IPOIB_PATH_NOTIFY_GRP_ID,
};

struct genl_multicast_group ipoib_genl_grps[] = {
	/* ipoib mcast group for path rec */
	[IPOIB_PATH_NOTIFY_GRP_ID] = {
		.name = "PATH_NOTIFY"
	},
};

struct ipoib_family_header {
	char	name[IFNAMSIZ];
};

struct ipoib_path_notice {
	u8	gid[16];
	__be16	lid;
	u8	sl;
	u8	hop_limit;
};

struct ipoib_path_del_notice {
	u8	gid[16];
};

struct ipoib_ge_netlink_notify {
	union {
		struct ipoib_path_notice	path_rec;
		struct ipoib_path_del_notice	path_del;
	};
};

struct ipoib_genl_work {
	struct work_struct work;
	struct ipoib_dev_priv *priv;
	struct ipoib_ge_netlink_notify record;
	int type;
};

/* genl_registered's value is changed only on module load/unload */
static int genl_registered;

/*
 * Handler module, contains the logic to process notifications and user
 * requests but not the sending-via-GENL logic.
 */

void generate_reply(struct work_struct *work);

void ipoib_path_add_notify(struct ipoib_dev_priv *priv,
			    struct sa_path_rec *pathrec)
{
	struct ipoib_genl_work *genl_work;

	genl_work = kzalloc(sizeof(struct ipoib_genl_work),
		       GFP_KERNEL);
	if (!genl_work) {
		ipoib_warn(priv, "%s: allocation of ipoib_genl_work failed\n",
			  __func__);
		return;
	}

	memcpy(genl_work->record.path_rec.gid, pathrec->dgid.raw,
	       sizeof(union ib_gid));
	genl_work->record.path_rec.lid = be32_to_cpu(sa_path_get_dlid(pathrec));
	genl_work->record.path_rec.sl = pathrec->sl;
	genl_work->record.path_rec.hop_limit = pathrec->hop_limit;

	INIT_WORK(&genl_work->work, generate_reply);
	genl_work->priv = priv;
	genl_work->type = PATH_ADD;
	queue_work(priv->wq, &genl_work->work);
}

void ipoib_path_del_notify(struct ipoib_dev_priv *priv,
			   struct sa_path_rec *pathrec)
{
	struct ipoib_genl_work *genl_work;

	genl_work = kzalloc(sizeof(struct ipoib_genl_work),
		       GFP_ATOMIC);
	if (!genl_work) {
		ipoib_warn(priv, "%s: allocation of ipoib_genl_work failed\n",
			  __func__);
		return;
	}

	memcpy(genl_work->record.path_del.gid, pathrec->dgid.raw,
	       sizeof(union ib_gid));
	INIT_WORK(&genl_work->work, generate_reply);
	genl_work->priv = priv;
	genl_work->type = PATH_DEL;
	queue_work(priv->wq, &genl_work->work);
}

/*
 * Notifier module. Contains the needed functions to send messages to
 * userspace using GENL.
 */

static struct genl_family ipoib_genl_family = {
	.hdrsize	= sizeof(struct ipoib_family_header),
	.name		= "GENETLINK_IPOIB",
	.version	= 1,
	.maxattr	= IPOIB_NETLINK_ATT_MAX,
	.mcgrps		= ipoib_genl_grps,
	.n_mcgrps	= 1,
};

static inline char *get_command(int command)
{
	switch (command) {
		case PATH_ADD:
			return "PATH_ADD";
		case PATH_DEL:
			return "PATH_DEL";
		default:
			return "";
	}
}

void generate_reply(struct work_struct *work)
{
	struct ipoib_genl_work *genl_work = container_of(work,
						   struct ipoib_genl_work,
						   work);
	struct ipoib_dev_priv *priv;
	struct sk_buff *skb;
	void *msg_head;
	struct nlattr *nla;
	unsigned int seq = 0;
	int i = 0;
	int type = genl_work->type;
	struct ipoib_ge_netlink_notify *record = &genl_work->record;

	priv = genl_work->priv;
	if (!priv) {
		pr_crit("%s: priv is NULL\n", __func__);
		return;
	}

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL) {
		ipoib_printk(KERN_CRIT, priv, "%s: skb allocation failed\n",
			     __func__);
		goto out;
	}

	msg_head = genlmsg_put(skb, 0, seq++, &ipoib_genl_family, 0,
			       REPORT_PATH);
	/* Warning:
	 *  genlmsg_put can return NULL in case there is not enough room
	 *  in the skb for the family and netlink headers. As long as
	 *  allock succeeded and is NLMSG_GOODSIZE the command can't
	 *  fail.
	 */

	memcpy(msg_head, priv->dev->name, IFNAMSIZ);
	nla = __nla_reserve(skb, type, 0);

	nla->nla_type = type;
	switch (type) {
	case PATH_ADD:
	{
		struct ipoib_path_notice *p;
		nla->nla_len += sizeof(struct ipoib_path_notice);
		p = (struct ipoib_path_notice *)skb_put(skb,
		     sizeof(struct ipoib_path_notice));
		memcpy(p, &record->path_rec,
		       sizeof(struct ipoib_path_notice));
		genlmsg_end(skb, msg_head);
		i = genlmsg_multicast(&ipoib_genl_family, skb, 0, IPOIB_PATH_NOTIFY_GRP_ID,
				      GFP_KERNEL);
		break;
	}
	case PATH_DEL:
	{
		struct ipoib_path_del_notice *p;
		nla->nla_len += sizeof(struct ipoib_path_del_notice);
		p = (struct ipoib_path_del_notice *)skb_put(skb,
		     sizeof(struct ipoib_path_del_notice));
		memcpy(p, &record->path_del,
		       sizeof(struct ipoib_path_del_notice));
		genlmsg_end(skb, msg_head);
		i = genlmsg_multicast(&ipoib_genl_family, skb, 0, IPOIB_PATH_NOTIFY_GRP_ID,
				      GFP_KERNEL);
		break;
	}
	}
	if (i && i != -ESRCH) {
		pr_err("%s: sending GENL %s message returned %d\n", __func__,
		       get_command(type), i);
	}

out:
	kfree(genl_work);
	return;
}

/* If needed, deletes the netlink interfaces from the ipoib_genl_if list
 * and resets the flags. */
void ipoib_unregister_genl(void)
{
	if (!genl_registered)
		return;
	genl_registered = 0;
	genl_unregister_family(&ipoib_genl_family);
}

int ipoib_register_genl(void)
{
	int rc;
	rc = genl_register_family(&ipoib_genl_family);
	if (rc != 0)
		goto out;
	genl_registered = 1;

	return 0;
/*	unregistering the family will cause:
 *	all assigned operations to be unregistered automatically.
 *	all assigned multicast groups to be unregistered automatically. */
out:
	return rc;
}
