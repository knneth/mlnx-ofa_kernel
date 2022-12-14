#ifndef _COMPAT_NET_DEVLINK_H
#define _COMPAT_NET_DEVLINK_H

#include "../../compat/config.h"

#ifdef HAVE_DEVLINK_H
#include_next <net/devlink.h>

#ifndef HAVE_DEVLINK_PARAM_GENERIC_ID_MAX
enum devlink_param_generic_id {
	DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE,

	/* add new param generic ids above here*/
	__DEVLINK_PARAM_GENERIC_ID_MAX,
	DEVLINK_PARAM_GENERIC_ID_MAX = __DEVLINK_PARAM_GENERIC_ID_MAX - 1,
};
#endif

#else /* HAVE_DEVLINK_H */

#include <linux/device.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <uapi/linux/devlink.h>

struct devlink {
	char priv[0] __aligned(NETDEV_ALIGN);
};

struct devlink_ops {
	int (*eswitch_mode_get)(struct devlink *devlink, u16 *p_mode);
	int (*eswitch_mode_set)(struct devlink *devlink, u16 mode);
	int (*eswitch_inline_mode_get)(struct devlink *devlink, u8 *p_inline_mode);
	int (*eswitch_inline_mode_set)(struct devlink *devlink, u8 inline_mode);
	int (*eswitch_encap_mode_get)(struct devlink *devlink, u8 *p_encap_mode);
	int (*eswitch_encap_mode_set)(struct devlink *devlink, u8 encap_mode);
	int (*eswitch_ipsec_mode_get)(struct devlink *devlink, u8 *p_ipsec_mode);
	int (*eswitch_ipsec_mode_set)(struct devlink *devlink, u8 ipsec_mode);
};

static inline void *devlink_priv(struct devlink *devlink)
{
	BUG_ON(!devlink);
	return &devlink->priv;
}

static inline struct devlink *priv_to_devlink(void *priv)
{
	BUG_ON(!priv);
	return container_of(priv, struct devlink, priv);
}

static inline struct devlink *devlink_alloc(const struct devlink_ops *ops,
					    size_t priv_size)
{
	return kzalloc(sizeof(struct devlink) + priv_size, GFP_KERNEL);
}

static inline void devlink_free(struct devlink *devlink)
{
	kfree(devlink);
}

static inline int devlink_register(struct devlink *devlink, struct device *dev)
{
	return 0;
}

static inline void devlink_unregister(struct devlink *devlink)
{
}


enum devlink_param_generic_id {
	DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE,

	/* add new param generic ids above here*/
	__DEVLINK_PARAM_GENERIC_ID_MAX,
	DEVLINK_PARAM_GENERIC_ID_MAX = __DEVLINK_PARAM_GENERIC_ID_MAX - 1,
};

#define DEVLINK_PARAM_GENERIC_ENABLE_ROCE_NAME "enable_roce"
#define DEVLINK_PARAM_GENERIC_ENABLE_ROCE_TYPE DEVLINK_PARAM_TYPE_BOOL

#endif /* HAVE_DEVLINK_H */

#ifndef HAVE_DEVLINK_PORT_NEW_ATTRS_STRUCT
struct devlink_port_new_attrs {
	enum devlink_port_flavour flavour;
	unsigned int port_index;
	u32 controller;
	u32 sfnum;
	u16 pfnum;
	u8 port_index_valid:1,
		controller_valid:1,
		sfnum_valid:1;
	};
#endif

#ifndef HAVE_DEVLINK_NET
static inline struct net *devlink_net(const struct devlink *devlink)
{
	return &init_net;
}
#endif

#ifndef HAVE_DEVLINK_DRIVERINIT_VAL
#define __DEVLINK_PARAM_MAX_STRING_VALUE 32
enum devlink_param_type {
	DEVLINK_PARAM_TYPE_U8,
	DEVLINK_PARAM_TYPE_U16,
	DEVLINK_PARAM_TYPE_U32,
	DEVLINK_PARAM_TYPE_STRING,
	DEVLINK_PARAM_TYPE_BOOL,
};

union devlink_param_value {
	u8 vu8;
	u16 vu16;
	u32 vu32;
	char vstr[__DEVLINK_PARAM_MAX_STRING_VALUE];
	bool vbool;
};

extern unsigned int esw_offloads_num_big_groups;

static inline int
devlink_param_driverinit_value_get(struct devlink *devlink, u32 param_id,
				   union devlink_param_value *init_val)
{
	/* if param_id is MLX5_DEVLINK_PARAM_ID_ESW_LARGE_GROUP_NUM */
	if (param_id == DEVLINK_PARAM_GENERIC_ID_MAX + 2)
		init_val->vu32 = esw_offloads_num_big_groups;
	else
		return -EOPNOTSUPP;

	return 0;
}

struct devlink_param_gset_ctx {
	union devlink_param_value val;
	enum devlink_param_cmode cmode;
};

#endif /* HAVE_DEVLINK_DRIVERINIT_VAL */


#ifndef HAVE_DEVLINK_PORT_STRUCT
struct devlink_port_phys_attrs {
	u32 port_number; /* Same value as "split group".
			  * A physical port which is visible to the user
			  * for a given port flavour.
			  *                                                     */
	u32 split_subport_number;
};

struct devlink_port_pci_pf_attrs {
	u16 pf; /* Associated PCI PF for this port. */
};

struct devlink_port_pci_vf_attrs {
	u16 pf; /* Associated PCI PF for this port. */
	u16 vf; /* Associated PCI VF for of the PCI PF for this port. */
};

struct devlink_port_attrs {
	u8 set:1,
	   split:1,
	   switch_port:1;
	enum devlink_port_flavour flavour;
	struct netdev_phys_item_id switch_id;
	union {
		struct devlink_port_phys_attrs phys;
		struct devlink_port_pci_pf_attrs pci_pf;
		struct devlink_port_pci_vf_attrs pci_vf;
	};
};

enum devlink_port_type {
	DEVLINK_PORT_TYPE_NOTSET,
	DEVLINK_PORT_TYPE_AUTO,
	DEVLINK_PORT_TYPE_ETH,
	DEVLINK_PORT_TYPE_IB,
};

struct devlink_port {
	struct list_head list;
	struct list_head param_list;
	struct devlink *devlink;
	unsigned int index;
	bool registered;
	spinlock_t type_lock; /* Protects type and type_dev
			       * pointer consistency.
			       *                                */
	enum devlink_port_type type;
	enum devlink_port_type desired_type;
	void *type_dev;
	struct devlink_port_attrs attrs;
	struct delayed_work type_warn_dw;
};
#endif

#endif /* _COMPAT_NET_DEVLINK_H */
