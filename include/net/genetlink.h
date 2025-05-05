/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _COMPAT_NET_GENETLINK_H
#define _COMPAT_NET_GENETLINK_H

#include "../../compat/config.h"

#include_next <net/genetlink.h>

#ifndef HAVE_STRUCT_GENL_SPLIT_OPS
/**
 * struct genl_split_ops - generic netlink operations (do/dump split version)
 * @cmd: command identifier
 * @internal_flags: flags used by the family
 * @flags: GENL_* flags (%GENL_ADMIN_PERM or %GENL_UNS_ADMIN_PERM)
 * @validate: validation flags from enum genl_validate_flags
 * @policy: netlink policy (takes precedence over family policy)
 * @maxattr: maximum number of attributes supported
 *
 * Do callbacks:
 * @pre_doit: called before an operation's @doit callback, it may
 *	do additional, common, filtering and return an error
 * @doit: standard command callback
 * @post_doit: called after an operation's @doit callback, it may
 *	undo operations done by pre_doit, for example release locks
 *
 * Dump callbacks:
 * @start: start callback for dumps
 * @dumpit: callback for dumpers
 * @done: completion callback for dumps
 *
 * Do callbacks can be used if %GENL_CMD_CAP_DO is set in @flags.
 * Dump callbacks can be used if %GENL_CMD_CAP_DUMP is set in @flags.
 * Exactly one of those flags must be set.
 */
struct genl_split_ops {
	union {
		struct {
			int (*pre_doit)(const struct genl_split_ops *ops,
					struct sk_buff *skb,
					struct genl_info *info);
			int (*doit)(struct sk_buff *skb,
				    struct genl_info *info);
			void (*post_doit)(const struct genl_split_ops *ops,
					  struct sk_buff *skb,
					  struct genl_info *info);
		};
		struct {
			int (*start)(struct netlink_callback *cb);
			int (*dumpit)(struct sk_buff *skb,
				      struct netlink_callback *cb);
			int (*done)(struct netlink_callback *cb);
		};
	};
	const struct nla_policy *policy;
	unsigned int		maxattr;
	u8			cmd;
	u8			internal_flags;
	u8			flags;
	u8			validate;
};
#endif
#endif	/* _COMPAT_NET_GENETLINK_H */
