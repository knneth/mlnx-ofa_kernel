#ifndef IB_VERBS_EXP_DEF_H
#define IB_VERBS_EXP_DEF_H

enum ib_qpg_type {
	IB_QPG_NONE	= 0,
	IB_QPG_PARENT	= (1<<0),
	IB_QPG_CHILD_RX = (1<<1),
	IB_QPG_CHILD_TX = (1<<2)
};

enum ib_exp_start_values {
	IB_EXP_ACCESS_FLAGS_SHIFT = 0x0F
};

enum ib_exp_access_flags {
	/* Initial values are non-exp defined as part of  ib_access_flags */
	IB_EXP_ACCESS_SHARED_MR_USER_READ   = (1 << (6 + IB_EXP_ACCESS_FLAGS_SHIFT)),
	IB_EXP_ACCESS_SHARED_MR_USER_WRITE  = (1 << (7 + IB_EXP_ACCESS_FLAGS_SHIFT)),
	IB_EXP_ACCESS_SHARED_MR_GROUP_READ  = (1 << (8 + IB_EXP_ACCESS_FLAGS_SHIFT)),
	IB_EXP_ACCESS_SHARED_MR_GROUP_WRITE = (1 << (9 + IB_EXP_ACCESS_FLAGS_SHIFT)),
	IB_EXP_ACCESS_SHARED_MR_OTHER_READ  = (1 << (10 + IB_EXP_ACCESS_FLAGS_SHIFT)),
	IB_EXP_ACCESS_SHARED_MR_OTHER_WRITE = (1 << (11 + IB_EXP_ACCESS_FLAGS_SHIFT)),
	IB_EXP_ACCESS_PHYSICAL_ADDR	    = (1 << (16 + IB_EXP_ACCESS_FLAGS_SHIFT)),
};

struct ib_odp_statistics {
#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING

	atomic_t num_page_fault_pages;

	atomic_t num_invalidation_pages;

	atomic_t num_invalidations;

	atomic_t invalidations_faults_contentions;

	atomic_t num_page_faults;

	atomic_t num_prefetches_handled;

	atomic_t num_prefetch_pages;
#endif
};

#endif
