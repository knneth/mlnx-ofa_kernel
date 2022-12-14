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

/* Define HAVE_DEVLINK_HEALTH_REPORT_SUPPORT from other flags */
#if defined(HAVE_DEVLINK_HEALTH_REPORT_BASE_SUPPORT) && \
    (defined(HAVE_DEVLINK_HEALTH_REPORTER_CREATE_4_ARGS) || \
     defined(HAVE_DEVLINK_HEALTH_REPORTER_CREATE_5_ARGS))
#define HAVE_DEVLINK_HEALTH_REPORT_SUPPORT 1
#endif

/* Define HAVE_KTLS_RX_SUPPORT from other flags */
#if defined(HAVE_TLS_OFFLOAD_RX_FORCE_RESYNC_REQUEST) || \
    defined(HAVE_TLS_OFFLOAD_RX_RESYNC_ASYNC_REQUEST_START)
#define HAVE_KTLS_RX_SUPPORT 1
#endif

/* Define HAVE_DEVLINK_PORT_ATRRS_SET_GET_SUPPORT from other flags */
#if defined(HAVE_DEVLINK_PORT_ATRRS_SET_GET_5_PARAMS) || \
    defined(HAVE_DEVLINK_PORT_ATRRS_SET_GET_7_PARAMS) || \
    defined(HAVE_DEVLINK_PORT_ATRRS_SET_GET_2_PARAMS)
#define HAVE_DEVLINK_PORT_ATRRS_SET_GET_SUPPORT 1
#endif

/* Define HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET from other flags */
#if defined(HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_4_PARAMS) || \
    defined(HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_2_PARAMS) || \
    defined(HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_CONTROLLER_NUM)
#define HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET 1
#endif

/* Define HAVE_XSK_SUPPORT from other flags */
#if (defined(HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS) || \
    defined(HAVE_XSK_BUFF_ALLOC)) && \
    !defined(HAVE_XSK_BUFF_ALLOC_GET_XSK_BUFF_POOL)
#define HAVE_XSK_SUPPORT 1
#endif

END_CONFIG
