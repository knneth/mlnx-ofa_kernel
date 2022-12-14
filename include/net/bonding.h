#ifndef LINUX_BONDING_H
#define LINUX_BONDING_H

#include "../../compat/config.h"

#ifdef HAVE_BONDING_H
#include_next <net/bonding.h>

#define MLX_USES_PRIMARY(mode)				\
		(((mode) == BOND_MODE_ACTIVEBACKUP) ||	\
		 ((mode) == BOND_MODE_TLB)          ||	\
		 ((mode) == BOND_MODE_ALB))

#define bond_option_active_slave_get_rcu LINUX_BACKPORT(bond_option_active_slave_get_rcu)
static inline struct net_device *bond_option_active_slave_get_rcu(struct bonding
								  *bond)
{
	struct slave *slave = rcu_dereference(bond->curr_active_slave);

	return MLX_USES_PRIMARY(bond->params.mode) && slave ? slave->dev : NULL;
}
#endif /* HAVE_BONDING_H */

#endif /* LINUX_BONDING_H */
