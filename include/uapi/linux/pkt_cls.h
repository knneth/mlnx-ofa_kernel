#ifndef _COMPAT_UAPI_LINUX_PKT_CLS_H
#define _COMPAT_UAPI_LINUX_PKT_CLS_H

#include "../../../compat/config.h"

#ifdef CONFIG_COMPAT_KERNEL_4_14
#include_next <uapi/linux/pkt_cls.h>
#else
#include_next <uapi/linux/pkt_cls.h>

#endif /* CONFIG_COMPAT_KERNEL_4_14 */

#ifdef CONFIG_MLX5_TC_CT
#ifndef HAVE_FLOW_ACTION_CT_METADATA_ORIG_DIR
enum {
	TCA_FLOWER_KEY_CT_FLAGS_INVALID = 1 << 4, /* Conntrack is invalid. */
	TCA_FLOWER_KEY_CT_FLAGS_REPLY = 1 << 5, /* Packet is in the reply direction. */
};
#endif
#endif

#ifndef HAVE_TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT
enum {
	TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT = (1 << 0),
	TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST = (1 << 1),
};
#elif !defined(HAVE_TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST)
enum {
        TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST = (1 << 1),
};
#endif

#ifdef CONFIG_COMPAT_CLS_FLOWER_4_18_MOD
enum {
	TCA_FLOWER_KEY_PORT_SRC_MIN = __TCA_FLOWER_MAX,    /* be16 */
	TCA_FLOWER_KEY_PORT_SRC_MAX,    /* be16 */
	TCA_FLOWER_KEY_PORT_DST_MIN,    /* be16 */
	TCA_FLOWER_KEY_PORT_DST_MAX,    /* be16 */

	TCA_FLOWER_KEY_CT_STATE,        /* u16 */
	TCA_FLOWER_KEY_CT_STATE_MASK,   /* u16 */
	TCA_FLOWER_KEY_CT_ZONE,         /* u16 */
	TCA_FLOWER_KEY_CT_ZONE_MASK,    /* u16 */
	TCA_FLOWER_KEY_CT_MARK,         /* u32 */
	TCA_FLOWER_KEY_CT_MARK_MASK,    /* u32 */
	TCA_FLOWER_KEY_CT_LABELS,       /* u128 */
	TCA_FLOWER_KEY_CT_LABELS_MASK,  /* u128 */

	__TCA_FLOWER_DUMMY_MAX,
};

#undef TCA_FLOWER_MAX
#define TCA_FLOWER_MAX (__TCA_FLOWER_DUMMY_MAX - 1)

#define TCA_FLOWER_MASK_FLAGS_RANGE    (1 << 0) /* Range-based match */

enum {
	TCA_FLOWER_KEY_CT_FLAGS_NEW = 1 << 0, /* Beginning of a new connection. */
	TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED = 1 << 1, /* Part of an existing connection. */
	TCA_FLOWER_KEY_CT_FLAGS_RELATED = 1 << 2, /* Related to an established connection. */
	TCA_FLOWER_KEY_CT_FLAGS_TRACKED = 1 << 3, /* Conntrack has occurred. */
	TCA_FLOWER_KEY_CT_FLAGS_INVALID = 1 << 4, /* Conntrack is invalid. */
	TCA_FLOWER_KEY_CT_FLAGS_REPLY = 1 << 5, /* Packet is in the reply direction. */
};

#define __TCA_ACT_SAMPLE 26

enum {
	TCA_ID_CTINFO = __TCA_ACT_SAMPLE+1,
	TCA_ID_MPLS,
	TCA_ID_CT,
};
#endif /* CONFIG_COMPAT_CLS_FLOWER_4_18_MOD */

#endif /* _COMPAT_UAPI_LINUX_PKT_CLS_H */
