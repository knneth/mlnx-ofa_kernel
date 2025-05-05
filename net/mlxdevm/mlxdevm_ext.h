#ifndef _MLXDEVM_EXT_H
#define _MLXDEVM_EXT_H

struct mlxdevm_rate_node {
	struct list_head list;
	char *name;
	u64 tx_max;
	u64 tx_share;

	u32 tc_bw[IEEE_8021QAZ_MAX_TCS];
};
#endif
