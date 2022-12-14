AC_PREREQ([2.57])
AC_INIT([compat_mlnx], 2.3, [http://support.mellanox.com/SupportWeb/service_center/SelfService], [compat_mlnx])

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([config])

AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC

AM_PROG_AS

AC_CHECK_TOOLS(AR, ar)

LB_PROG_CC

AC_ARG_WITH(njobs,
	AS_HELP_STRING([--with-njobs=N],[Allow N jobs at once; jobs as number of CPUs with no arg.]),
	[
		NJOBS="$withval"
		case "X${NJOBS}" in
			X | X[A-Za-z]*)
			NJOBS=$(MLXNUMC=$(grep ^processor /proc/cpuinfo | wc -l) && echo $(($MLXNUMC<16?$MLXNUMC:16)))
			;;
		esac
	],
	NJOBS=1
)

MLNX_PROG_LINUX
LB_CONDITIONALS

#
#       cleanup auto-generated defines
#
sed -i '/\<PACKAGE\>/d' $PWD/config.h
sed -i '/\<PACKAGE_BUGREPORT\>/d' $PWD/config.h
sed -i '/\<PACKAGE_NAME\>/d' $PWD/config.h
sed -i '/\<PACKAGE_STRING\>/d' $PWD/config.h
sed -i '/\<PACKAGE_TARNAME\>/d' $PWD/config.h
sed -i '/\<PACKAGE_URL\>/d' $PWD/config.h
sed -i '/\<PACKAGE_VERSION\>/d' $PWD/config.h
sed -i '/\<VERSION\>/d' $PWD/config.h

#
cat << 'END_CONFIG' >> $PWD/config.h

/* Make sure LINUX_BACKPORT macro is defined for all external users */
#ifndef LINUX_BACKPORT
#define LINUX_BACKPORT(__sym) backport_ ##__sym
#endif

/* Assembled defines section */

/* Define HAVE_TC_SETUP_FLOW_ACTION from other flags */
#if defined(HAVE_TC_SETUP_FLOW_ACTION_FUNC) || \
    defined(HAVE_TC_SETUP_OFFLOAD_ACTION_FUNC) || \
    defined(HAVE_TC_SETUP_FLOW_ACTION_WITH_RTNL_HELD)
#define HAVE_TC_SETUP_FLOW_ACTION 1
#else
#undef HAVE_TC_SETUP_FLOW_ACTION
#endif

/* Define HAVE_HMM_RANGE_FAULT_SUPPORT from other flags */
#if defined(HAVE_HMM_RANGE_FAULT_HAS_ONE_PARAM) && \
    defined(HAVE_HMM_RANGE_HAS_HMM_PFNS) && \
    defined(HAVE_HMM_PFN_TO_MAP_ORDER) && \
    defined(CONFIG_HMM_MIRROR)
#define HAVE_HMM_RANGE_FAULT_SUPPORT 1
#else
#undef HAVE_HMM_RANGE_FAULT_SUPPORT
#endif

/* Define HAVE_DEVLINK_HEALTH_REPORT_SUPPORT from other flags */
#if defined(HAVE_DEVLINK_HEALTH_REPORT_BASE_SUPPORT) && \
    (defined(HAVE_DEVLINK_HEALTH_REPORTER_CREATE_4_ARGS) || \
     defined(HAVE_DEVLINK_HEALTH_REPORTER_CREATE_5_ARGS))
#define HAVE_DEVLINK_HEALTH_REPORT_SUPPORT 1
#else
#undef HAVE_DEVLINK_HEALTH_REPORT_SUPPORT
#endif

/* Define HAVE_KTLS_RX_SUPPORT from other flags */
#if defined(HAVE_TLS_OFFLOAD_RX_FORCE_RESYNC_REQUEST) || \
    defined(HAVE_TLS_OFFLOAD_RX_RESYNC_ASYNC_REQUEST_START)
#define HAVE_KTLS_RX_SUPPORT 1
#else
#undef HAVE_KTLS_RX_SUPPORT
#endif

/* Define HAVE_DEVLINK_PORT_ATRRS_SET_GET_SUPPORT from other flags */
#if defined(HAVE_DEVLINK_PORT_ATRRS_SET_GET_5_PARAMS) || \
    defined(HAVE_DEVLINK_PORT_ATRRS_SET_GET_7_PARAMS) || \
    defined(HAVE_DEVLINK_PORT_ATRRS_SET_GET_2_PARAMS)
#define HAVE_DEVLINK_PORT_ATRRS_SET_GET_SUPPORT 1
#else
#undef HAVE_DEVLINK_PORT_ATRRS_SET_GET_SUPPORT
#endif

/* Define HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET from other flags */
#if defined(HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_4_PARAMS) || \
    defined(HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_2_PARAMS) || \
    defined(HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_CONTROLLER_NUM)
#define HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET 1
#else
#undef HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET
#endif

/* Define HAVE_XDP_SUPPORT from other flags */
#if defined(CONFIG_ENABLE_XDP) \
	&& defined(HAVE_XDP_REDIRECT)
#define HAVE_XDP_SUPPORT 1
#else
#undef HAVE_XDP_SUPPORT
#endif

/* Define HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS from other flags */
#if defined(HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS_IN_SOCK_DRV) || \
	defined(HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS_IN_SOCK)
#define HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS 1
#else
#undef HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS
#endif

/* Define HAVE_XSK_ZERO_COPY_SUPPORT from other flags */
#if (defined(HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS) || \
    defined(HAVE_XSK_BUFF_ALLOC)) \
    && defined(HAVE_XDP_SUPPORT)
#define HAVE_XSK_ZERO_COPY_SUPPORT 1
#else
#undef HAVE_XSK_ZERO_COPY_SUPPORT
#endif

/* Define HAVE_SVC_FILL_WRITE_VECTOR from other flags */
#if defined(HAVE_SVC_FILL_WRITE_VECTOR_4_PARAMS) || \
	defined(HAVE_SVC_FILL_WRITE_VECTOR_3_PARAMS) || \
	defined(HAVE_SVC_FILL_WRITE_VECTOR_2_PARAMS)
#define HAVE_SVC_FILL_WRITE_VECTOR 1
#else
#undef HAVE_SVC_FILL_WRITE_VECTOR
#endif

/* Define HAVE_GET_USER_PAGES_GUP_FLAGS from other flags */
#if defined(HAVE_GET_USER_PAGES_5_PARAMS) || \
	defined(HAVE_GET_USER_PAGES_7_PARAMS)
#define HAVE_GET_USER_PAGES_GUP_FLAGS 1
#else
#undef HAVE_GET_USER_PAGES_GUP_FLAGS
#endif

/* Define HAVE_MMGET_NOT_ZERO from other flags */
#if defined(HAVE_SCHED_MM_MMGET_NOT_ZERO) || \
	defined(HAVE_SCHED_MMGET_NOT_ZERO)
#define HAVE_MMGET_NOT_ZERO 1
#else
#undef HAVE_MMGET_NOT_ZERO
#endif

/* Define HAVE_XDP_FRAME from other flags */
#if defined(HAVE_XDP_FRAME_IN_NET_XDP) || \
	defined(HAVE_XDP_FRAME_IN_UEK_KABI)
#define HAVE_XDP_FRAME 1
#else
#undef HAVE_XDP_FRAME
#endif

/* Define HAVE_XDP_RXQ_INFO from other flags */
#if defined(HAVE_XDP_RXQ_INFO_IN_NET_XDP) || \
	defined(HAVE_XDP_RXQ_INFO_IN_UEK_KABI)
#define HAVE_XDP_RXQ_INFO 1
#else
#undef HAVE_XDP_RXQ_INFO
#endif

/* Define HAVE_NET_XDP_H from other flags */
#if defined(HAVE_NET_XDP_HEADER) || \
	defined(HAVE_NET_XDP_HEADER_UEK_KABI)
#define HAVE_NET_XDP_H 1
#else
#undef HAVE_NET_XDP_H
#endif

/* Define HAVE_XDP_CONVERT_TO_XDP_FRAME from other flags */
#if defined(HAVE_XDP_CONVERT_TO_XDP_FRAME_IN_NET_XDP) || \
	defined(HAVE_XDP_CONVERT_TO_XDP_FRAME_IN_UEK_KABI)
#define HAVE_XDP_CONVERT_TO_XDP_FRAME 1
#else
#undef HAVE_XDP_CONVERT_TO_XDP_FRAME
#endif

/* Define HAVE_XDP_RXQ_INFO_REG_MEM_MODEL from other flags */
#if defined(HAVE_XDP_RXQ_INFO_REG_MEM_MODEL_IN_NET_XDP) || \
	defined(HAVE_XDP_RXQ_INFO_REG_MEM_MODEL_IN_UEK_KABI)
#define HAVE_XDP_RXQ_INFO_REG_MEM_MODEL 1
#else
#undef HAVE_XDP_RXQ_INFO_REG_MEM_MODEL
#endif

/* Define HAVE_SHAMPO_SUPPORT from other flags */
#if defined(HAVE_NET_PAGE_POOL_H)
#define HAVE_SHAMPO_SUPPORT 1
#else
#undef HAVE_SHAMPO_SUPPORT
#endif

/* Add new assembled defines ABOVE this note.
 * Newly added defines must contain #define else #undef
 * Please use existing defines as an example.
 */

END_CONFIG
