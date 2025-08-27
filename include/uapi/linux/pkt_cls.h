#ifndef _COMPAT_UAPI_LINUX_PKT_CLS_H
#define _COMPAT_UAPI_LINUX_PKT_CLS_H

#include "../../../compat/config.h"

#include_next <uapi/linux/pkt_cls.h>

#ifdef CONFIG_MLX5_TC_CT
#ifndef HAVE_FLOW_ACTION_CT_METADATA_ORIG_DIR
enum {
	TCA_FLOWER_KEY_CT_FLAGS_INVALID = 1 << 4, /* Conntrack is invalid. */
	TCA_FLOWER_KEY_CT_FLAGS_REPLY = 1 << 5, /* Packet is in the reply direction. */
};
#endif
#endif


#endif /* _COMPAT_UAPI_LINUX_PKT_CLS_H */
