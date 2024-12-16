#!/bin/bash
#
# Copyright (c) 2006 Mellanox Technologies. All rights reserved.
#
# This Software is licensed under one of the following licenses:
#
# 1) under the terms of the "Common Public License 1.0" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/cpl.php.
#
# 2) under the terms of the "The BSD License" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/bsd-license.php.
#
# 3) under the terms of the "GNU General Public License (GPL) Version 2" a
#    copy of which is available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/gpl-license.php.
#
# Licensee has the right to choose one of the above licenses.
#
# Redistributions of source code must retain the above copyright
# notice and one of the license notices.
#
# Redistributions in binary form must reproduce both the above copyright
# notice, one of the license notices in the documentation
# and/or other materials provided with the distribution.


# Execute command w/ echo and exit if it fail
ex()
{
        echo "$@"
        if ! "$@"; then
                printf "\nFailed executing $@\n\n"
                exit 1
        fi
}

KER_UNAME_R=`uname -r`
KER_PATH=/lib/modules/${KER_UNAME_R}/build
NJOBS=1
ENABLE_CONTAINER_BUILD=${ENABLE_CONTAINER_BUILD:-0}

usage()
{
cat << EOF

Usage: `basename $0` [--help]: Prints this message
		[--with-memtrack]: Compile with memtrack kernel module to debug memory leaks
		[-k|--kernel <kernel version>]: Build package for this kernel version. Default: $KER_UNAME_R
		[-s|--kernel-sources  <path to the kernel sources>]: Use these kernel sources for the build. Default: $KER_PATH
		--with-linux=DIR  kernel sources directory [/lib/modules/$(uname -r)/source]
		--with-linux-obj=DIR  kernel obj directory [/lib/modules/$(uname -r)/build]
		[-j[N]|--with-njobs=[N]] : Allow N configure jobs at once; jobs as number of CPUs with no arg.
EOF
}

check_kerver_list()
{
	local kver=$1
	shift
	local kverlist=$@

	for i in $kverlist; do
		if echo $kver | grep -q "\b$i" ; then
			return 0
		fi
	done

	return 1
}

# Compare 2 kernel versions
check_kerver()
{
        local kver=$1
        local min_kver=$2
        shift 2

        kver_a=$(echo -n ${kver} | cut -d '.' -f 1)
        kver_b=$(echo -n ${kver} | cut -d '.' -f 2)
        kver_c=$(echo -n ${kver} | cut -d '.' -f 3 | cut -d '-' -f 1 | tr -d [:alpha:][:punct:])

        min_kver_a=$(echo -n ${min_kver} | cut -d '.' -f 1)
        min_kver_b=$(echo -n ${min_kver} | cut -d '.' -f 2)
        min_kver_c=$(echo -n ${min_kver} | cut -d '.' -f 3 | cut -d '-' -f 1 | tr -d [:alpha:][:punct:])

        if [ ${kver_a} -lt ${min_kver_a} ] ||
                [[ ${kver_a} -eq ${min_kver_a} && ${kver_b} -lt ${min_kver_b} ]] ||
                [[ ${kver_a} -eq ${min_kver_a} && ${kver_b} -eq ${min_kver_b} && ${kver_c} -lt ${min_kver_c} ]]; then
                return 1
        fi

        return 0
}

support_only_base()
{
	[ "X$OFED_BASE_KVERSION" == "X$1" ]
}

check_compat_config_h_var()
{
	local var="#define $1 1"
	grep -q "${var}" $COMPAT_CONFIG_H
}

set_complex_define_to_config_h()
{
	echo "#define $1 1" >> $COMPAT_CONFIG_H
}

unset_complex_define_to_config_h()
{
	echo "/* #undef $1 */" >> $COMPAT_CONFIG_H
}

set_config_mk_kernel_module()
{
	echo "Complex config: Set $1 to m in ${CWD}/${CONFIG}"
	echo "Complex config: Set $1 to 1 in ${AUTOCONF_H}"
	echo "$1=m" >> ${CWD}/${CONFIG}
	echo "#define $1 1" >> ${AUTOCONF_H}
}

set_config_mk_kernel()
{
	echo "Complex config: Set $1 to y in ${CWD}/${CONFIG}"
	echo "Complex config: Set $1 to 1 in ${AUTOCONF_H}"
	echo "$1=y" >> ${CWD}/${CONFIG}
	echo "#define $1 1" >> ${AUTOCONF_H}
}

unset_config_mk_kernel()
{
	echo "Complex config: Unset $1 in ${CWD}/${CONFIG}"
	echo "Complex config: Unset $1 in ${AUTOCONF_H}"
	echo "$1=" >> ${CWD}/${CONFIG}
	echo "#undef $1" >> ${AUTOCONF_H}
}

check_config_comapt_tcf_pedit_mod()
{
	RHEL_MAJOR=$(grep ^RHEL_MAJOR ${KSRC_OBJ}/Makefile | sed -n 's/.*= *\(.*\)/\1/p')
	RHEL_MINOR=$(grep ^RHEL_MINOR ${KSRC_OBJ}/Makefile | sed -n 's/.*= *\(.*\)/\1/p')
	RHEL7_4_JD=$(echo ${KVERSION} | grep 3.10.0-693.21.3)

	[[ ${RHEL_MAJOR} -eq "7" && ${RHEL_MINOR} -le "4" && ! $RHEL7_4_JD ]]
}

check_complex_defines()
{
        echo "/* Defines in this section calculated in ofed_scripts/configure " >> $COMPAT_CONFIG_H
        echo " * based on defines prior this section" >> $COMPAT_CONFIG_H

        echo " *  _________________________________________________________ */" >> $COMPAT_CONFIG_H

#define REBASE_STAGE REBASE_STAGE_UPSTREAM/REBASE_STAGE_BASE/REBASE_STAGE_BACKPORTS
	if [ "$REBASE_STAGE" = "UPSTREAM" ]; then
		set_complex_define_to_config_h REBASE_STAGE_UPSTREAM
	elif [ "$REBASE_STAGE" = "BASE" ]; then
		set_complex_define_to_config_h REBASE_STAGE_BASE
	else
		set_complex_define_to_config_h REBASE_STAGE_BACKPORTS
	fi

# Define HAVE_BASECODE_EXTRAS always set define.
# Use to wrap extra code added to base code with backports apply.
# This wrapped code compile over all kernels.
        if [ "X${CONFIG_ENABLE_BASECODE_EXTRAS}" == "Xy" ]
	then
		set_complex_define_to_config_h HAVE_BASECODE_EXTRAS
	else
		unset_complex_define_to_config_h HAVE_BASECODE_EXTRAS
	fi

# Define HAVE_TC_SETUP_FLOW_ACTION from other flags
	if check_compat_config_h_var HAVE_TC_SETUP_FLOW_ACTION_FUNC ||
	   check_compat_config_h_var HAVE_TC_SETUP_OFFLOAD_ACTION_FUNC ||
	   check_compat_config_h_var HAVE_TC_SETUP_OFFLOAD_ACTION_FUNC_HAS_3_PARAM ||
	   check_compat_config_h_var HAVE_TC_SETUP_FLOW_ACTION_WITH_RTNL_HELD
	then
		set_complex_define_to_config_h HAVE_TC_SETUP_FLOW_ACTION
	else
		unset_complex_define_to_config_h HAVE_TC_SETUP_FLOW_ACTION
	fi

# Define HAVE_HMM_RANGE_FAULT_SUPPORT from other flags
	check_autofconf CONFIG_HMM_MIRROR
	if [ "${CONFIG_HMM_MIRROR}" == "1" ]; then
		if check_compat_config_h_var HAVE_HMM_RANGE_FAULT_HAS_ONE_PARAM &&
		   check_compat_config_h_var HAVE_HMM_RANGE_HAS_HMM_PFNS &&
		   check_compat_config_h_var HAVE_HMM_PFN_TO_MAP_ORDER
		then
			set_complex_define_to_config_h HAVE_HMM_RANGE_FAULT_SUPPORT
		else
			unset_complex_define_to_config_h HAVE_HMM_RANGE_FAULT_SUPPORT
		fi
	fi

# Define HAVE_DEVLINK_HEALTH_REPORT_SUPPORT from other flags
	if check_compat_config_h_var HAVE_DEVLINK_HEALTH_REPORT_BASE_SUPPORT &&
	   (check_compat_config_h_var HAVE_DEVLINK_HEALTH_REPORTER_CREATE_4_ARGS ||
	   check_compat_config_h_var HAVE_DEVLINK_HEALTH_REPORTER_CREATE_5_ARGS)
	then
		set_complex_define_to_config_h HAVE_DEVLINK_HEALTH_REPORT_SUPPORT
	else
		unset_complex_define_to_config_h HAVE_DEVLINK_HEALTH_REPORT_SUPPORT
	fi

# Define HAVE_KTLS_RX_SUPPORT from other flags
	if (check_compat_config_h_var HAVE_TLS_OFFLOAD_RX_FORCE_RESYNC_REQUEST ||
		check_compat_config_h_var HAVE_TLS_OFFLOAD_RX_RESYNC_ASYNC_REQUEST_START) &&
	       	[ "X${CONFIG_MLX5_EN_TLS}" == "Xy" ]
	then
		set_complex_define_to_config_h HAVE_KTLS_RX_SUPPORT
	else
		unset_complex_define_to_config_h HAVE_KTLS_RX_SUPPORT
	fi


# Define HAVE_DEVLINK_PORT_ATRRS_SET_GET_SUPPORT from other flags
	if check_compat_config_h_var HAVE_DEVLINK_PORT_ATRRS_SET_GET_5_PARAMS ||
	   check_compat_config_h_var HAVE_DEVLINK_PORT_ATRRS_SET_GET_7_PARAMS ||
	   check_compat_config_h_var HAVE_DEVLINK_PORT_ATRRS_SET_GET_2_PARAMS
	then
		set_complex_define_to_config_h HAVE_DEVLINK_PORT_ATRRS_SET_GET_SUPPORT
	else
		unset_complex_define_to_config_h HAVE_DEVLINK_PORT_ATRRS_SET_GET_SUPPORT
	fi

# Define HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET from other flags
	if check_compat_config_h_var HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_4_PARAMS ||
	   check_compat_config_h_var HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_2_PARAMS ||
	   check_compat_config_h_var HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_CONTROLLER_NUM
	then
		set_complex_define_to_config_h HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET
	else
		unset_complex_define_to_config_h HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET
	fi

# Define HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS from other flags
	if check_compat_config_h_var HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS_IN_SOCK_DRV ||
	   check_compat_config_h_var HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS_IN_SOCK
	then
		set_complex_define_to_config_h HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS
	else
		unset_complex_define_to_config_h HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS
	fi

# Define HAVE_GET_USER_PAGES_GUP_FLAGS from other flags
	if check_compat_config_h_var HAVE_GET_USER_PAGES_4_PARAMS ||
	   check_compat_config_h_var HAVE_GET_USER_PAGES_5_PARAMS ||
	   check_compat_config_h_var HAVE_GET_USER_PAGES_7_PARAMS
	then
		set_complex_define_to_config_h HAVE_GET_USER_PAGES_GUP_FLAGS
	else
		unset_complex_define_to_config_h HAVE_GET_USER_PAGES_GUP_FLAGS
	fi

# Define HAVE_XDP_SUPPORT from other flags
        if [ "X${CONFIG_ENABLE_XDP}" == "Xy" ]
	then
		set_complex_define_to_config_h HAVE_XDP_SUPPORT
	else
		unset_complex_define_to_config_h HAVE_XDP_SUPPORT
	fi

# Define HAVE_VFIO_SUPPORT from other flags
	if check_compat_config_h_var HAVE_VFIO_PRECOPY_INFO && 
	   check_compat_config_h_var HAVE_VFIO_PCI_CORE_INIT &&
	   [ "X${CONFIG_ENABLE_VFIO}" == "Xy" ]
	then
		set_complex_define_to_config_h HAVE_VFIO_SUPPORT
	else
		unset_complex_define_to_config_h HAVE_VFIO_SUPPORT
	fi

# Define HAVE_XSK_ZERO_COPY_SUPPORT from other flags
	if (check_compat_config_h_var HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS ||
		check_compat_config_h_var HAVE_XSK_BUFF_ALLOC) &&
	   check_compat_config_h_var HAVE_XDP_SUPPORT
	then
		set_complex_define_to_config_h HAVE_XSK_ZERO_COPY_SUPPORT
	else
		unset_complex_define_to_config_h HAVE_XSK_ZERO_COPY_SUPPORT
	fi

# Define HAVE_XDP_CONVERT_TO_XDP_FRAME from other flags
	if check_compat_config_h_var HAVE_XDP_CONVERT_TO_XDP_FRAME_IN_NET_XDP ||
	   check_compat_config_h_var HAVE_XDP_CONVERT_TO_XDP_FRAME_IN_UEK_KABI
	then
		set_complex_define_to_config_h HAVE_XDP_CONVERT_TO_XDP_FRAME
	else
		unset_complex_define_to_config_h HAVE_XDP_CONVERT_TO_XDP_FRAME
	fi

#define HAVE_KERNEL_WITH_VXLAN_SUPPORT_ON from other flags
	check_autofconf CONFIG_VXLAN
	if [ "${CONFIG_VXLAN}" == "1" ]; then
		if check_compat_config_h_var HAVE_NDO_UDP_TUNNEL_ADD ||
		   check_compat_config_h_var HAVE_UDP_TUNNEL_NIC_INFO
		then
			set_complex_define_to_config_h HAVE_KERNEL_WITH_VXLAN_SUPPORT_ON
		else
			unset_complex_define_to_config_h HAVE_KERNEL_WITH_VXLAN_SUPPORT_ON
		fi
	fi

# Define HAVE_IS_PCI_P2PDMA_PAGE from other flags
	if check_compat_config_h_var HAVE_IS_PCI_P2PDMA_PAGE_IN_MM_H ||
	   check_compat_config_h_var HAVE_IS_PCI_P2PDMA_PAGE_IN_MEMREMAP_H
	then
		set_complex_define_to_config_h HAVE_IS_PCI_P2PDMA_PAGE
	else
		unset_complex_define_to_config_h HAVE_IS_PCI_P2PDMA_PAGE
	fi

# Define CONFIG_MLX5_MACSEC based on kernel config and HAVE_
	check_autofconf CONFIG_MACSEC
	if [ "${CONFIG_MACSEC}" == "1" ]; then
	    if check_compat_config_h_var HAVE_STRUCT_MACSEC_INFO_METADATA; then
			CONFIG_MLX5_MACSEC="y"
			set_config_mk_kernel CONFIG_MLX5_MACSEC
		else
			CONFIG_MLX5_MACSEC=
			unset_config_mk_kernel CONFIG_MLX5_MACSEC
	    fi
	fi

# Define HAVE_BLK_MQ_BUSY_TAG_ITER_FN_BOOL from other flags
	if check_compat_config_h_var HAVE_BLK_MQ_BUSY_TAG_ITER_FN_BOOL_3_PARAMS ||
	   check_compat_config_h_var HAVE_BLK_MQ_BUSY_TAG_ITER_FN_BOOL_2_PARAMS
	then
		set_complex_define_to_config_h HAVE_BLK_MQ_BUSY_TAG_ITER_FN_BOOL
	else
		unset_complex_define_to_config_h HAVE_BLK_MQ_BUSY_TAG_ITER_FN_BOOL
	fi

# define HAVE_DEVLINK_PORT_TYPE_ETH_SET from other flags
	if check_compat_config_h_var HAVE_DEVLINK_PORT_TYPE_ETH_SET_GET_1_PARAM ||
	   check_compat_config_h_var HAVE_DEVLINK_PORT_TYPE_ETH_SET_GET_2_PARAM
	then
		set_complex_define_to_config_h HAVE_DEVLINK_PORT_TYPE_ETH_SET
	else
		unset_complex_define_to_config_h HAVE_DEVLINK_PORT_TYPE_ETH_SET
	fi

# Define HAVE_DEVLINK_PER_AUXDEV from other flags
	if check_compat_config_h_var HAVE_NET_DEVICE_HAS_DEVLINK_PORT
	then
		set_complex_define_to_config_h HAVE_DEVLINK_PER_AUXDEV
	else
		unset_complex_define_to_config_h HAVE_DEVLINK_PER_AUXDEV
	fi

# define HAVE_TC_CLS_OFFLOAD_EXTACK from other flags
	if check_compat_config_h_var HAVE_FLOW_CLS_OFFLOAD ||
	   check_compat_config_h_var HAVE_TC_CLS_OFFLOAD_EXTACK_FIX
	then
		set_complex_define_to_config_h HAVE_TC_CLS_OFFLOAD_EXTACK
	else
		unset_complex_define_to_config_h HAVE_TC_CLS_OFFLOAD_EXTACK
	fi

# define HAVE_TC_CLSFLOWER_STATS from other flags
	if check_compat_config_h_var HAVE_FLOW_CLS_OFFLOAD ||
		check_compat_config_h_var HAVE_TC_CLSFLOWER_STATS_FIX
	then
		set_complex_define_to_config_h HAVE_TC_CLSFLOWER_STATS
	else
		unset_complex_define_to_config_h HAVE_TC_CLSFLOWER_STATS
	fi

# define HAVE_TC_CLS_FLOWER_OFFLOAD_HAS_STATS_FIELD from other flags
	if check_compat_config_h_var HAVE_FLOW_CLS_OFFLOAD ||
	   check_compat_config_h_var HAVE_TC_CLS_FLOWER_OFFLOAD_HAS_STATS_FIELD_FIX
	then
		set_complex_define_to_config_h HAVE_TC_CLS_FLOWER_OFFLOAD_HAS_STATS_FIELD
	else
		unset_complex_define_to_config_h HAVE_TC_CLS_FLOWER_OFFLOAD_HAS_STATS_FIELD
	fi

# define HAVE_TC_CLS_FLOWER_OFFLOAD_COMMON from other flags
	if check_compat_config_h_var HAVE_FLOW_CLS_OFFLOAD ||
	   check_compat_config_h_var HAVE_TC_CLS_FLOWER_OFFLOAD_COMMON_FIX
	then
		set_complex_define_to_config_h HAVE_TC_CLS_FLOWER_OFFLOAD_COMMON
	else
		unset_complex_define_to_config_h HAVE_TC_CLS_FLOWER_OFFLOAD_COMMON
	fi

# define HAVE_PRIO_CHAIN_SUPPORT from other flags
	if check_compat_config_h_var HAVE_TC_CLS_FLOWER_OFFLOAD_COMMON
	then
		set_complex_define_to_config_h HAVE_PRIO_CHAIN_SUPPORT
	else
		unset_complex_define_to_config_h HAVE_PRIO_CHAIN_SUPPORT
	fi

# define HAVE_PRIO_CHAIN_SUPPORT from other flags
	if check_compat_config_h_var HAVE___TC_INDR_BLOCK_CB_REGISTER ||
	   check_compat_config_h_var HAVE___FLOW_INDR_BLOCK_CB_REGISTER ||
	   check_compat_config_h_var HAVE_FLOW_BLOCK_CB
	then
		set_complex_define_to_config_h HAVE_TC_INDR_API
	else
		unset_complex_define_to_config_h HAVE_TC_INDR_API
	fi

# define HAVE_TCF_PEDIT_TCFP_KEYS_EX from other flags
	if check_compat_config_h_var HAVE_TCF_PEDIT_TCFP_KEYS_EX_FIX ||
	   check_config_comapt_tcf_pedit_mod
	then
		set_complex_define_to_config_h HAVE_TCF_PEDIT_TCFP_KEYS_EX
	else
		unset_complex_define_to_config_h HAVE_TCF_PEDIT_TCFP_KEYS_EX
	fi

# define HAVE_VDPA_SUPPORT from other flags
	if check_compat_config_h_var HAVE_VDPA_SET_CONFIG_HAS_DEVICE_FEATURES
	then
		set_complex_define_to_config_h HAVE_VDPA_SUPPORT
	else
		unset_complex_define_to_config_h HAVE_VDPA_SUPPORT
	fi

# define HAVE_NET_PAGE_POOL_H from other flags
	if check_compat_config_h_var HAVE_NET_PAGE_POOL_OLD_H ||
	   check_compat_config_h_var HAVE_NET_PAGE_POOL_TYPES_H
	then
		set_complex_define_to_config_h HAVE_NET_PAGE_POOL_H
	else
		unset_complex_define_to_config_h HAVE_NET_PAGE_POOL_H
	fi

# Define HAVE_SHAMPO_SUPPORT from other flags
	if check_compat_config_h_var HAVE_NET_PAGE_POOL_H
	then
		set_complex_define_to_config_h HAVE_SHAMPO_SUPPORT
	else
		unset_complex_define_to_config_h HAVE_SHAMPO_SUPPORT
	fi

# define HAVE_PAGE_POOL_GET_DMA_ADDR from other flags
	if check_compat_config_h_var HAVE_PAGE_POOL_GET_DMA_ADDR_OLD ||
	   check_compat_config_h_var HAVE_PAGE_POOL_GET_DMA_ADDR_HELPER
	then
		set_complex_define_to_config_h HAVE_PAGE_POOL_GET_DMA_ADDR
	else
		unset_complex_define_to_config_h HAVE_PAGE_POOL_GET_DMA_ADDR
	fi

# define HAVE_PAGE_POLL_NID_CHANGED from other flags
	if check_compat_config_h_var HAVE_PAGE_POLL_NID_CHANGED_OLD ||
	   check_compat_config_h_var HAVE_PAGE_POLL_NID_CHANGED_HELPERS
	then
		set_complex_define_to_config_h HAVE_PAGE_POLL_NID_CHANGED
	else
		unset_complex_define_to_config_h HAVE_PAGE_POLL_NID_CHANGED
	fi

# define HAVE_GUP_MUST_UNSHARE_GET_3_PARAMS from other flags
	if check_compat_config_h_var HAVE_MM_GUP_MUST_UNSHARE_GET_3_PARAMS ||
	   check_compat_config_h_var HAVE_ASSERT_FAULT_LOCKED
	then
		set_complex_define_to_config_h HAVE_GUP_MUST_UNSHARE_GET_3_PARAMS
	else
		unset_complex_define_to_config_h HAVE_GUP_MUST_UNSHARE_GET_3_PARAMS
	fi

# define HAVE_PAGE_POOL_PARAM_HAS_NAPI from other flags
	if check_compat_config_h_var HAVE_PAGE_POOL_PARAMS_NAPI_TYPES_H ||
	   check_compat_config_h_var HAVE_PAGE_POOL_PARAMS_NAPI_OLD
	then
		set_complex_define_to_config_h HAVE_PAGE_POOL_PARAM_HAS_NAPI
	else
		unset_complex_define_to_config_h HAVE_PAGE_POOL_PARAM_HAS_NAPI
	fi

# define HAVE_PAGE_POOL_DEFRAG_PAGE from other flags
	if check_compat_config_h_var HAVE_PAGE_POOL_DEFRAG_PAGE_IN_PAGE_POOL_H ||
	   check_compat_config_h_var HAVE_PAGE_POOL_DEFRAG_PAGE_IN_PAGE_POOL_TYPES_H
	then
		set_complex_define_to_config_h HAVE_PAGE_POOL_DEFRAG_PAGE
	else
		unset_complex_define_to_config_h HAVE_PAGE_POOL_DEFRAG_PAGE
	fi

# Define HAVE_PAGE_POOL_RELEASE_PAGE from other flags
	if check_compat_config_h_var HAVE_PAGE_POOL_RELEASE_PAGE_IN_PAGE_POOL_H ||
	   check_compat_config_h_var HAVE_PAGE_POOL_RELEASE_PAGE_IN_TYPES_H
	then
		set_complex_define_to_config_h HAVE_PAGE_POOL_RELEASE_PAGE
	else
		unset_complex_define_to_config_h HAVE_PAGE_POOL_RELEASE_PAGE
	fi

# Define HAVE_DEVLINK_FMSG_BINARY_PAIR_PUT_ARG_U32 from other flags
	if check_compat_config_h_var HAVE_DEVLINK_FMSG_BINARY_PAIR_PUT_ARG_U32_RETURN_VOID ||
	   check_compat_config_h_var HAVE_DEVLINK_FMSG_BINARY_PAIR_PUT_ARG_U32_RETURN_INT
	then
		set_complex_define_to_config_h HAVE_DEVLINK_FMSG_BINARY_PAIR_PUT_ARG_U32
	else
		unset_complex_define_to_config_h HAVE_DEVLINK_FMSG_BINARY_PAIR_PUT_ARG_U32
	fi

# Define HAVE_DPLL_SUPPORT from other flags
        if (check_compat_config_h_var HAVE_DPLL_NETDEV_PIN_SET || 
	    check_compat_config_h_var HAVE_NETDEV_DPLL_PIN_SET) &&
           check_compat_config_h_var HAVE_DPLL_STRUCTS
        then
                set_complex_define_to_config_h HAVE_DPLL_SUPPORT
        else
                unset_complex_define_to_config_h HAVE_DPLL_SUPPORT
        fi
# Define CONFIG_MLX5_DPLL based on kernel config and HAVE_DPLL_STRUCTS
	check_autofconf CONFIG_DPLL
	if [ "${CONFIG_DPLL}" == "1" ]; then
	    if check_compat_config_h_var HAVE_DPLL_SUPPORT; then
			CONFIG_MLX5_DPLL="m"
			set_config_mk_kernel_module CONFIG_MLX5_DPLL
		else
			CONFIG_MLX5_DPLL=
			unset_config_mk_kernel CONFIG_MLX5_DPLL
	    fi
	fi
}

check_kerver_rh_cls()
{
	perl -e '($v, $r) = split "-", "'$1'"; exit($v eq "3.10.0" && $r >= 693 ? 0 : 1)'
}

check_kerver_rh_bridge()
{
	perl -e '($v, $r) = split "-", "'$1'"; exit($v eq "4.18.0" && $r >= 147 ? 0 : 1)'
}

# Check if the kernel we build with has an auxiliary bus module
check_inbox_auxiliary() {
	check_autofconf CONFIG_AUXILIARY_BUS
	check_autofconf CONFIG_AUXILIARY_BUS_MODULE
	[ "$CONFIG_AUXILIARY_BUS$CONFIG_AUXILIARY_BUS_MODULE" != '' ]
}

parseparams() {

	while [ ! -z "$1" ]
	do
		case $1 in
			--with-memtrack)
				CONFIG_MEMTRACK="m"
			;;
			-k | --kernel | --kernel-version)
				shift
				KVERSION=$1
			;;
			-s|--kernel-sources)
				shift
				KSRC=$1
			;;
                        --with-linux)
                                shift
                                LINUX_SRC=$1
                        ;;
                        --with-linux=*)
                                LINUX_SRC=`expr "x$1" : 'x[^=]*=\(.*\)'`
                        ;;
                        --with-linux-obj)
                                shift
                                LINUX_OBJ=$1
                        ;;
                        --with-linux-obj=*)
                                LINUX_OBJ=`expr "x$1" : 'x[^=]*=\(.*\)'`
                        ;;
                        -j[0-9]*)
	                        NJOBS=`expr "x$1" : 'x\-j\(.*\)'`
                        ;;
                        --with-njobs=*)
	                        NJOBS=`expr "x$1" : 'x[^=]*=\(.*\)'`
                        ;;
                        -j |--with-njobs)
				shift
	                        NJOBS=$1
                        ;;
			--without-mlx5)
				CONFIG_MLX5_CORE=""
				DEFINE_MLX5_CORE='#undef CONFIG_MLX5_CORE'
				CONFIG_MLX5_CORE_EN=""
				DEFINE_MLX5_CORE_EN='#undef CONFIG_MLX5_CORE_EN'
				CONFIG_MLX5_CORE_EN_DCB=""
				DEFINE_MLX5_CORE_EN_DCB='#undef CONFIG_MLX5_CORE_EN_DCB'
				CONFIG_MLX5_EN_ARFS=""
				DEFINE_MLX5_EN_ARFS='#undef CONFIG_MLX5_EN_ARFS'
				CONFIG_MLX5_EN_RXNFC=""
				DEFINE_MLX5_EN_RXNFC='#undef CONFIG_MLX5_EN_RXNFC'
				CONFIG_MLX5_ESWITCH=""
				DEFINE_MLX5_ESWITCH='#undef CONFIG_MLX5_ESWITCH'
				CONFIG_MLX5_CLS_ACT=""
				DEFINE_MLX5_CLS_ACT="#undef CONFIG_MLX5_CLS_ACT"
				CONFIG_MLX5_BRIDGE=""
				DEFINE_MLX5_BRIDGE="#undef CONFIG_MLX5_BRIDGE"
				CONFIG_MLX5_SW_STEERING=""
				DEFINE_MLX5_SW_STEERING='#undef CONFIG_MLX5_SW_STEERING'
				CONFIG_MLX5_MPFS=""
				DEFINE_MLX5_MPFS='#undef CONFIG_MLX5_MPFS'
				CONFIG_MLX5_ACCEL=""
				DEFINE_MLX5_ACCEL='#undef CONFIG_MLX5_ACCEL'
				CONFIG_MLX5_EN_TLS=""
				DEFINE_MLX5_EN_TLS='#undef CONFIG_MLX5_EN_TLS'
				CONFIG_MLX5_TLS=""
				DEFINE_MLX5_TLS='#undef CONFIG_MLX5_TLS'
				CONFIG_MLX5_SF=""
				DEFINE_MLX5_SF='#undef CONFIG_MLX5_SF'
				CONFIG_MLX5_SF_MANAGER=""
				CONFIG_MLX5_SF_MANAGER='#undef CONFIG_MLX5_SF_MANAGER'
				CONFIG_MLXDEVM=""
				DEFINE_MLXDEVM='#undef CONFIG_MLXDEVM'
			;;
			--without-mlxfw)
				CONFIG_MLXFW=""
				DEFINE_MLXFW='#undef CONFIG_MLXFW'
			;;
			--enable-container-build)
				ENABLE_CONTAINER_BUILD=1
			;;
			--disable-container-build)
				ENABLE_CONTAINER_BUILD=0
			;;
			*)
				echo "Bad input parameter: $1"
				usage
				exit 1
			;;
		esac

		shift
	done
}

function check_autofconf {
	VAR=$1
	VALUE=$(tac ${KSRC_OBJ}/include/*/autoconf.h | grep -m1 ${VAR} | sed -ne 's/.*\([01]\)$/\1/gp')

	eval "export $VAR=$VALUE"
}

main() {

# block RHEL supports
OFED_BASE_KVERSION="6.0.0"
MIN_KVERSION="3.10"

CLS_ACT_SUPPORTED_KVERSION="4.12.0"

# bridge offload
BRIDGE_SUPPORTED_KVERSION="5.0"

MLXDEVM_SUPPORTED_KVERSION="4.15.0"

#Set default values
WITH_QUILT=${WITH_QUILT:-"yes"}
WITH_PATCH=${WITH_PATCH:-"yes"}
EXTRA_FLAGS=""
CONFIG_MEMTRACK=""
CONFIG_AUXILIARY_BUS="m"
CONFIG_MLX5_CORE="m"
CONFIG_MLX5_CORE_EN="y"
CONFIG_MLX5_CORE_EN_DCB="y"
CONFIG_MLX5_EN_ARFS="y"
CONFIG_MLX5_EN_RXNFC="y"
CONFIG_MLX5_ESWITCH="y"
CONFIG_MLX5_CLS_ACT="y"
CONFIG_MLX5_BRIDGE="y"
CONFIG_MLX5_TC_CT="y"
CONFIG_MLX5_TC_SAMPLE="y"
CONFIG_MLX5_SW_STEERING="y"
CONFIG_MLX5_MPFS="y"
CONFIG_MLX5_ACCEL="y"
CONFIG_MLX5_EN_ACCEL_FS="y"
CONFIG_MLX5_EN_TLS="y"
CONFIG_MLX5_TLS="y"
CONFIG_MLX5_SF="y"
CONFIG_MLX5_SF_MANAGER='y'
CONFIG_MLXDEVM='m'
CONFIG_MLX5_SF_CFG='y'
CONFIG_MLXFW="m"
CONFIG_MLNX_BLOCK_REQUEST_MODULE=''
CONFIG_MLX5_FPGA=''
CONFIG_MLX5_FPGA_TLS=''
CONFIG_MLX5_FPGA_IPSEC=''
CONFIG_ENABLE_XDP="y"
CONFIG_ENABLE_BASECODE_EXTRAS="y"
DEFINE_MLX5_CORE='#undef CONFIG_MLX5_CORE\n#define CONFIG_MLX5_CORE 1'
DEFINE_AUXILIARY_BUS='#undef CONFIG_AUXILIARY_BUS\n#define CONFIG_AUXILIARY_BUS 1'
DEFINE_MLX5_CORE_EN='#undef CONFIG_MLX5_CORE_EN\n#define CONFIG_MLX5_CORE_EN 1'
DEFINE_MLX5_CORE_EN_DCB='#undef CONFIG_MLX5_CORE_EN_DCB\n#define CONFIG_MLX5_CORE_EN_DCB 1'
DEFINE_MLX5_EN_ARFS='#undef CONFIG_MLX5_EN_ARFS\n#define CONFIG_MLX5_EN_ARFS 1'
DEFINE_MLX5_EN_RXNFC='#undef CONFIG_MLX5_EN_RXNFC\n#define CONFIG_MLX5_EN_RXNFC 1'
DEFINE_MLX5_ESWITCH='#undef CONFIG_MLX5_ESWITCH\n#define CONFIG_MLX5_ESWITCH 1'
DEFINE_MLX5_CLS_ACT='#undef CONFIG_MLX5_CLS_ACT\n#define CONFIG_MLX5_CLS_ACT 1'
DEFINE_MLX5_BRIDGE='#undef CONFIG_MLX5_BRIDGE\n#define CONFIG_MLX5_BRIDGE 1'
DEFINE_MLX5_TC_CT='#undef CONFIG_MLX5_TC_CT\n#define CONFIG_MLX5_TC_CT 1'
DEFINE_MLX5_TC_SAMPLE='#undef CONFIG_MLX5_TC_SAMPLE\n#define CONFIG_MLX5_TC_SAMPLE 1'
DEFINE_MLX5_SW_STEERING='#undef CONFIG_MLX5_SW_STEERING\n#define CONFIG_MLX5_SW_STEERING 1'
DEFINE_MLX5_MPFS='#undef CONFIG_MLX5_MPFS\n#define CONFIG_MLX5_MPFS 1'
DEFINE_MLX5_ACCEL='#undef CONFIG_MLX5_ACCEL\n#define CONFIG_MLX5_ACCEL 1'
DEFINE_MLX5_EN_ACCEL_FS='#undef CONFIG_MLX5_EN_ACCEL_FS\n#define CONFIG_MLX5_EN_ACCEL_FS 1'
DEFINE_MLX5_EN_TLS='#undef CONFIG_MLX5_EN_TLS\n#define CONFIG_MLX5_EN_TLS 1'
DEFINE_MLX5_TLS='#undef CONFIG_MLX5_TLS\n#define CONFIG_MLX5_TLS 1'
DEFINE_MLX5_SF='#undef CONFIG_MLX5_SF\n#define CONFIG_MLX5_SF 1'
DEFINE_MLX5_SF_MANAGER='#undef CONFIG_MLX5_SF_MANAGER\n#define CONFIG_MLX5_SF_MANAGER 1'
DEFINE_MLXDEVM='#undef CONFIG_MLXDEVM\n#define CONFIG_MLXDEVM 1'
DEFINE_MLX5_SF_CFG='#undef CONFIG_MLX5_SF_CFG\n#define CONFIG_MLX5_SF_CFG 1'
DEFINE_MLXFW='#undef CONFIG_MLXFW\n#define CONFIG_MLXFW 1'
DEFINE_MLX5_FPGA='#undef CONFIG_MLX5_FPGA'
DEFINE_MLX5_FPGA_TLS='#undef CONFIG_MLX5_FPGA_TLS'
DEFINE_MLX5_FPGA_IPSEC='#undef CONFIG_MLX5_FPGA_IPSEC'
DEFINE_CONFIG_MLNX_BLOCK_REQUEST_MODULE='#undef CONFIG_MLNX_BLOCK_REQUEST_MODULE'
DEFINE_ENABLE_XDP='#undef CONFIG_ENABLE_XDP\n#define CONFIG_ENABLE_XDP 1'

parseparams $@

KVERSION=${KVERSION:-$KER_UNAME_R}
if [ ! -z "$LINUX_SRC" ]; then
	KSRC=$LINUX_SRC
fi

if [ ! -z "$LINUX_OBJ" ]; then
	KSRC_OBJ=$LINUX_OBJ
fi

KSRC=${KSRC:-"/lib/modules/${KVERSION}/build"}

if [ -z "$KSRC_OBJ" ]; then
	build_KSRC=$(echo "$KSRC" | grep -w "build")
	linux_obj_KSRC=$(echo "$KSRC" | grep -w "linux-obj")

	if [[ -e "/etc/SuSE-release" && -n "$build_KSRC" && -d ${KSRC/build/source} ]] ||
	   [[ -e "/etc/SUSE-brand"   && -n "$build_KSRC" && -d ${KSRC/build/source} ]] ||
	   [[ -n "$build_KSRC" && -d ${KSRC/build/source} &&
	       "X$(readlink -f $KSRC)" != "X$(readlink -f ${KSRC/build/source})" ]]; then
		KSRC_OBJ=$KSRC
		KSRC=${KSRC_OBJ/build/source}
	elif [[ -e "/etc/SuSE-release" && -n "$linux_obj_KSRC" ]] ||
	     [[ -e "/etc/SUSE-brand" && -n "$linux_obj_KSRC" ]]; then
		sources_dir=$(readlink -f $KSRC 2>/dev/null | sed -e 's/-obj.*//g')
		KSRC_OBJ=$KSRC
		KSRC=${sources_dir}
	fi
fi

KSRC_OBJ=${KSRC_OBJ:-"$KSRC"}

if [[ ! -d "${KSRC}/" && -d "${KSRC_OBJ}/" ]]; then
	KSRC=$KSRC_OBJ
fi

QUILT=${QUILT:-$(/usr/bin/which quilt  2> /dev/null)}
CWD=$(pwd)
CONFIG="config.mk"
PATCH_DIR=${PATCH_DIR:-""}

if [ $ENABLE_CONTAINER_BUILD -eq 0 ]; then
    if [ -e "/.dockerenv" ] || (grep -q docker /proc/self/cgroup &>/dev/null); then
        CONFIG_MLNX_BLOCK_REQUEST_MODULE=y
        DEFINE_CONFIG_MLNX_BLOCK_REQUEST_MODULE="#undef CONFIG_MLNX_BLOCK_REQUEST_MODULE\n#define CONFIG_MLNX_BLOCK_REQUEST_MODULE 1"
    fi
fi

case $KVERSION in
	2.6.18*)
	BACKPORT_INCLUDES="-I$CWD/backport_includes/2.6.18-EL5.2/include"
	CONFIG_COMPAT_VERSION="-2.6.18"
	CONFIG_COMPAT_KOBJECT_BACKPORT=y
	if [ ! -e backports_applied-2.6.18 ]; then
		echo "backports_applied-2.6.18 does not exist. running ofed_patch.sh"
		ex ${CWD}/ofed_scripts/ofed_patch.sh --with-patchdir=backports${CONFIG_COMPAT_VERSION}
		touch backports_applied-2.6.18
	fi
	;;
	*)
	;;
esac

ARCH=${ARCH:-$(uname -m)}

case $ARCH in
	ppc*)
	ARCH=powerpc
	;;
	i?86)
	ARCH=i386
	;;
esac

if ! check_kerver ${KVERSION} ${CLS_ACT_SUPPORTED_KVERSION}; then
	if (! check_kerver_rh ${KVERSION}) || support_only_base ${CLS_ACT_SUPPORTED_KVERSION}; then
			CONFIG_MLX5_CLS_ACT=
			CONFIG_MLX5_TC_CT=
			CONFIG_MLX5_TC_SAMPLE=
			CONFIG_MLX5_SW_STEERING=
			CONFIG_MLX5_BRIDGE=
			echo "Warning: CONFIG_MLX5_CLS_ACT requires kernel version ${CLS_ACT_SUPPORTED_KVERSION} or higher (current: ${KVERSION})."
	fi
fi


if ! check_kerver ${KVERSION} ${BRIDGE_SUPPORTED_KVERSION}; then
	if (! check_kerver_rh_bridge ${KVERSION}) || support_only_base ${BRIDGE_SUPPORTED_KVERSION}; then
			CONFIG_MLX5_BRIDGE=
			echo "Warning: CONFIG_MLX5_BRIDGE requires kernel version ${BRIDGE_SUPPORTED_KVERSION} or higher (current: ${KVERSION})."
	fi
fi

if ! check_kerver ${KVERSION} ${MLXDEVM_SUPPORTED_KVERSION}; then
    CONFIG_MLXDEVM=
    CONFIG_MLX5_SF_CFG=
fi

if check_inbox_auxiliary; then
        CONFIG_AUXILIARY_BUS=
        DEFINE_CONFIG_AUXILIARY_BUS='#undef CONFIG_AUXILIARY_BUS'
else
        CONFIG_AUXILIARY_BUS="m"
        DEFINE_CONFIG_AUXILIARY_BUS='#define CONFIG_AUXILIARY_BUS 1'
fi

check_autofconf CONFIG_RFS_ACCEL
if [ "X${CONFIG_MLX5_EN_ARFS=}" == "Xy" ]; then
    if ! [ "X${CONFIG_RFS_ACCEL=}" == "X1" ]; then
        echo "Warning: CONFIG_RFS_ACCEL is not enabled in the kernel, cannot enable CONFIG_MLX5_EN_ARFS."
        CONFIG_MLX5_EN_ARFS=
        DEFINE_MLX5_EN_ARFS='#undef CONFIG_MLX5_EN_ARFS'
    fi
fi

check_autofconf CONFIG_DCB
if [ "X${CONFIG_MLX5_CORE_EN_DCB}" == "Xy" ]; then
       if ! [ "X${CONFIG_DCB}" == "X1" ]; then
               echo "Warning: CONFIG_DCB is not enabled in the kernel, cannot enable CONFIG_MLX5_CORE_EN_DCB."
               CONFIG_MLX5_CORE_EN_DCB=
       fi
fi

check_autofconf CONFIG_TLS_DEVICE
if [ "X${CONFIG_MLX5_EN_TLS}" == "Xy" ]; then
    if ! [ "X${CONFIG_TLS_DEVICE}" == "X1" ]; then
        echo "Warning: CONFIG_TLS_DEVICE is not enabled in the kernel, cannot enable CONFIG_MLX5_EN_TLS."
        CONFIG_MLX5_EN_TLS=
        DEFINE_MLX5_EN_TLS='#undef CONFIG_MLX5_EN_TLS'
        CONFIG_MLX5_TLS=
        DEFINE_MLX5_TLS='#undef CONFIG_MLX5_TLS'
        check_autofconf CONFIG_MLX5_EN_IPSEC
        if ! [ "X${CONFIG_MLX5_EN_IPSEC}" == "X1" ]; then
                CONFIG_MLX5_ACCEL=
                DEFINE_MLX5_ACCEL='#undef CONFIG_MLX5_ACCEL'
                CONFIG_MLX5_EN_ACCEL_FS=
                DEFINE_MLX5_EN_ACCEL_FS='#undef CONFIG_MLX5_EN_ACCEL_FS'
        fi
    fi
fi

if [ "X${CONFIG_MLX5_ESWITCH}" == "X" ] || [ "X${CONFIG_MLX5_SF}" == "X" ]; then
        CONFIG_MLX5_SF_MANAGER=
        DEFINE_MLX5_SF_MANAGER='#undef CONFIG_MLX5_SF_MANAGER='
fi

# if SF driver is not configured disable its configuration driver as well
if [ "X${CONFIG_MLX5_SF}" == "X" ]; then
	CONFIG_MLX5_SF_CFG=
fi

        # Create config.mk
        /bin/rm -f ${CWD}/${CONFIG}
        cat >> ${CWD}/${CONFIG} << EOFCONFIG
KVERSION=${KVERSION}
CONFIG_COMPAT_VERSION=${CONFIG_COMPAT_VERSION}
CONFIG_COMPAT_KOBJECT_BACKPORT=${CONFIG_COMPAT_KOBJECT_BACKPORT}
BACKPORT_INCLUDES=${BACKPORT_INCLUDES}
ARCH=${ARCH}

MODULES_DIR:=/lib/modules/${KVERSION}/updates
KSRC=${KSRC}
KSRC_OBJ=${KSRC_OBJ}
KLIB_BUILD=${KSRC_OBJ}
CWD=${CWD}
MLNX_EN_EXTRA_CFLAGS:=${EXTRA_FLAGS}
CONFIG_MEMTRACK:=${CONFIG_MEMTRACK}
CONFIG_AUXILIARY_BUS:=${CONFIG_AUXILIARY_BUS}
CONFIG_MLX5_CORE:=${CONFIG_MLX5_CORE}
CONFIG_MLX5_CORE_EN:=${CONFIG_MLX5_CORE_EN}
CONFIG_MLX5_CORE_EN_DCB:=${CONFIG_MLX5_CORE_EN_DCB}
CONFIG_MLX5_EN_ARFS:=${CONFIG_MLX5_EN_ARFS}
CONFIG_MLX5_EN_RXNFC:=${CONFIG_MLX5_EN_RXNFC}
CONFIG_MLX5_ESWITCH:=${CONFIG_MLX5_ESWITCH}
CONFIG_MLX5_CLS_ACT=${CONFIG_MLX5_CLS_ACT}
CONFIG_MLX5_BRIDGE=${CONFIG_MLX5_BRIDGE}
CONFIG_MLX5_TC_CT=${CONFIG_MLX5_TC_CT}
CONFIG_MLX5_TC_SAMPLE=${CONFIG_MLX5_TC_SAMPLE}
CONFIG_MLX5_SW_STEERING:=${CONFIG_MLX5_SW_STEERING}
CONFIG_MLX5_ACCEL:=${CONFIG_MLX5_ACCEL}
CONFIG_MLX5_EN_ACCEL_FS:=${CONFIG_MLX5_EN_ACCEL_FS}
CONFIG_MLX5_MPFS:=${CONFIG_MLX5_MPFS}
CONFIG_MLX5_EN_TLS:=${CONFIG_MLX5_EN_TLS}
CONFIG_MLX5_TLS:=${CONFIG_MLX5_TLS}
CONFIG_MLX5_SF:=${CONFIG_MLX5_SF}
CONFIG_MLX5_SF_MANAGER:=${CONFIG_MLX5_SF_MANAGER}
CONFIG_MLXDEVM:=${CONFIG_MLXDEVM}
CONFIG_MLX5_SF_CFG:=${CONFIG_MLX5_SF_CFG}
CONFIG_MLXFW:=${CONFIG_MLXFW}
CONFIG_MLX5_FPGA_TLS:=${CONFIG_MLX5_FPGA_TLS}
CONFIG_MLX5_FPGA_IPSEC:=${CONFIG_MLX5_FPGA_IPSEC}
CONFIG_MLX5_FPGA:=${CONFIG_MLX5_FPGA}
CONFIG_MLNX_BLOCK_REQUEST_MODULE:=${CONFIG_MLNX_BLOCK_REQUEST_MODULE}
CONFIG_ENABLE_XDP:=${CONFIG_ENABLE_XDP}
EOFCONFIG

echo "Created ${CONFIG}:"
cat ${CWD}/${CONFIG}

COMPAT_CONFIG_H="compat/config.h"
# Create autoconf.h
AUTOCONF_H="${CWD}/include/generated/autoconf.h"
mkdir -p ${CWD}/include/generated

if [ ! -z "${CONFIG_COMPAT_VERSION}" ]; then
	DEFINE_COMPAT_OLD_VERSION="#define CONFIG_COMPAT_VERSION ${CONFIG_COMPAT_VERSION}"
fi

if [ "X${CONFIG_COMPAT_KOBJECT_BACKPORT}" == "Xy" ]; then
	DEFINE_COMPAT_KOBJECT_BACKPORT="#define CONFIG_COMPAT_KOBJECT_BACKPORT ${CONFIG_COMPAT_KOBJECT_BACKPORT}"
fi

if [ "${CONFIG_MLX5_ESWITCH}" == "" ]; then
        DEFINE_MLX5_ESWITCH="#undef CONFIG_MLX5_ESWITCH"
fi

if [ "${CONFIG_MLX5_CLS_ACT}" == "" ]; then
        DEFINE_MLX5_CLS_ACT="#undef CONFIG_MLX5_CLS_ACT"
fi

if [ "${CONFIG_MLX5_BRIDGE}" == "" ]; then
        DEFINE_MLX5_BRIDGE="#undef CONFIG_MLX5_BRIDGE"
fi

if [ "${CONFIG_MLX5_TC_CT}" == "" ]; then
        DEFINE_MLX5_TC_CT="#undef CONFIG_MLX5_TC_CT"
fi

if [ "${CONFIG_MLX5_TC_SAMPLE}" == "" ]; then
        DEFINE_MLX5_TC_SAMPLE="#undef CONFIG_MLX5_TC_SAMPLE"
fi

if [ "${CONFIG_MLX5_SW_STEERING}" == "" ]; then
        DEFINE_MLX5_SW_STEERING="#undef CONFIG_MLX5_SW_STEERING"
fi

if [ "${CONFIG_MLX5_EN_TLS}" == "" ]; then
        DEFINE_MLX5_EN_TLS="#undef CONFIG_MLX5_EN_TLS"
fi

if [ "${CONFIG_MLX5_TLS}" == "" ]; then
        DEFINE_MLX5_TLS="#undef CONFIG_MLX5_TLS"
fi

if [ "${CONFIG_MLX5_SF}" == "" ]; then
        DEFINE_MLX5_SF="#undef CONFIG_MLX5_SF"
fi

if [ "${CONFIG_MLX5_SF_MANAGER}" == "" ]; then
        DEFINE_MLX5_SF_MANAGER="#undef CONFIG_MLX5_SF_MANAGER"
fi

if [ "${CONFIG_MLXDEVM}" == "" ]; then
        DEFINE_MLXDEVM="#undef CONFIG_MLXDEVM"
fi

if [ "${CONFIG_MLX5_SF_CFG}" == "" ]; then
        DEFINE_MLX5_SF_CFG="#undef CONFIG_MLX5_SF_CFG"
fi

cat >> ${AUTOCONF_H}<< EOFAUTO
$(echo -e "${DEFINE_MLX5_CORE}")
$(echo -e "${DEFINE_MLX5_CORE_EN}")
$(echo -e "${DEFINE_MLX5_CORE_EN_DCB}")
$(echo -e "${DEFINE_MLX5_EN_ARFS}")
$(echo -e "${DEFINE_MLX5_EN_RXNFC}")
$(echo -e "${DEFINE_MLX5_ESWITCH}")
$(echo -e "${DEFINE_MLX5_CLS_ACT}")
$(echo -e "${DEFINE_MLX5_BRIDGE}")
$(echo -e "${DEFINE_MLX5_TC_CT}")
$(echo -e "${DEFINE_MLX5_TC_SAMPLE}")
$(echo -e "${DEFINE_MLX5_SW_STEERING}")
$(echo -e "${DEFINE_MLX5_MPFS}")
$(echo -e "${DEFINE_MLX5_ACCEL}")
$(echo -e "${DEFINE_MLX5_EN_ACCEL_FS}")
$(echo -e "${DEFINE_MLX5_EN_TLS}")
$(echo -e "${DEFINE_MLX5_TLS}")
$(echo -e "${DEFINE_MLX5_SF}")
$(echo -e "${DEFINE_MLX5_SF_MANAGER}")
$(echo -e "${DEFINE_MLXDEVM}")
$(echo -e "${DEFINE_MLX5_SF_CFG}")
$(echo -e "${DEFINE_MLXFW}")
$(echo -e "${DEFINE_COMPAT_OLD_VERSION}")
$(echo -e "${DEFINE_COMPAT_KOBJECT_BACKPORT}")
$(echo -e "${DEFINE_CONFIG_MLNX_BLOCK_REQUEST_MODULE}")
$(echo -e "${DEFINE_MLX5_FPGA_TLS}")
$(echo -e "${DEFINE_MLX5_FPGA_IPSEC}")
$(echo -e "${DEFINE_MLX5_FPGA}")
$(echo -e "${DEFINE_ENABLE_XDP}")
EOFAUTO

echo "Running configure..."
cd compat
if [[ ! -x configure ]]; then
    ex ./autogen.sh
fi

/bin/cp -f Makefile.real Makefile
/bin/cp -f Makefile.real Makefile.in

ex ./configure --with-linux-obj=$KSRC_OBJ --with-linux=$KSRC --with-njobs=$NJOBS

cd -

check_complex_defines
}

main $@
