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

check_kerver_rh()
{
	perl -e '($v, $r) = split "-", "'$1'"; exit($v eq "3.10.0" && $r >= 1062 ? 0 : 1)'
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

SWITCH_SUPPORTED_KVERSION="4.9.0"
SWITCH_SUPPORTED_KVERSION_LIST="3.10.0-693 3.10.0-862 3.10.0-957 3.10.0-1062 3.10.0-1127 3.10.0-327 4.4.0+2"
CLS_ACT_SUPPORTED_KVERSION="4.12.0"
CLS_ACT_SUPPORTED_KVERSION_LIST="3.10.0-693 3.10.0-862 3.10.0-957 3.10.0-1062 3.10.0-1127"
RETPOLINE_MINIMAL_VERSION="4.15.0"
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
CONFIG_MLX5_SW_STEERING="y"
CONFIG_MLX5_MPFS="y"
CONFIG_MLX5_ACCEL="y"
CONFIG_MLX5_EN_ACCEL_FS="y"
CONFIG_MLX5_EN_TLS="y"
CONFIG_MLX5_TLS="y"
CONFIG_MLX5_SF="y"
CONFIG_MLX5_SF_MANAGER='y'
CONFIG_MLXDEVM='m'
CONFIG_MLXFW="m"
CONFIG_MLNX_BLOCK_REQUEST_MODULE=''
DEFINE_MLX5_CORE='#undef CONFIG_MLX5_CORE\n#define CONFIG_MLX5_CORE 1'
DEFINE_AUXILIARY_BUS='#undef CONFIG_AUXILIARY_BUS\n#define CONFIG_AUXILIARY_BUS 1'
DEFINE_MLX5_CORE_EN='#undef CONFIG_MLX5_CORE_EN\n#define CONFIG_MLX5_CORE_EN 1'
DEFINE_MLX5_CORE_EN_DCB='#undef CONFIG_MLX5_CORE_EN_DCB\n#define CONFIG_MLX5_CORE_EN_DCB 1'
DEFINE_MLX5_EN_ARFS='#undef CONFIG_MLX5_EN_ARFS\n#define CONFIG_MLX5_EN_ARFS 1'
DEFINE_MLX5_EN_RXNFC='#undef CONFIG_MLX5_EN_RXNFC\n#define CONFIG_MLX5_EN_RXNFC 1'
DEFINE_MLX5_ESWITCH='#undef CONFIG_MLX5_ESWITCH\n#define CONFIG_MLX5_ESWITCH 1'
DEFINE_MLX5_CLS_ACT='#undef CONFIG_MLX5_CLS_ACT\n#define CONFIG_MLX5_CLS_ACT 1'
DEFINE_MLX5_SW_STEERING='#undef CONFIG_MLX5_SW_STEERING\n#define CONFIG_MLX5_SW_STEERING 1'
DEFINE_MLX5_MPFS='#undef CONFIG_MLX5_MPFS\n#define CONFIG_MLX5_MPFS 1'
DEFINE_MLX5_ACCEL='#undef CONFIG_MLX5_ACCEL\n#define CONFIG_MLX5_ACCEL 1'
DEFINE_MLX5_EN_ACCEL_FS='#undef CONFIG_MLX5_EN_ACCEL_FS\n#define CONFIG_MLX5_EN_ACCEL_FS 1'
DEFINE_MLX5_EN_TLS='#undef CONFIG_MLX5_EN_TLS\n#define CONFIG_MLX5_EN_TLS 1'
DEFINE_MLX5_TLS='#undef CONFIG_MLX5_TLS\n#define CONFIG_MLX5_TLS 1'
DEFINE_MLX5_SF='#undef CONFIG_MLX5_SF\n#define CONFIG_MLX5_SF 1'
DEFINE_MLX5_SF_MANAGER='#undef CONFIG_MLX5_SF_MANAGER\n#define CONFIG_MLX5_SF_MANAGER 1'
DEFINE_MLXDEVM='#undef CONFIG_MLXDEVM\n#define CONFIG_MLXDEVM 1'
DEFINE_MLXFW='#undef CONFIG_MLXFW\n#define CONFIG_MLXFW 1'
DEFINE_CONFIG_MLNX_BLOCK_REQUEST_MODULE='#undef CONFIG_MLNX_BLOCK_REQUEST_MODULE'

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

CFLAGS_RETPOLINE=''
case "$ARCH" in i386 | x86_64)
	# Any kernel >= 4.15 is not interesting: we need to "patch" some
	# distribution kernels where the base version has no retpoline
	# but the updates do.
	if check_kerver ${RETPOLINE_MINIMAL_VERSION} ${KVERSION}; then
		check_autofconf CONFIG_RETPOLINE
		if [ "$CONFIG_RETPOLINE" != "1" ]; then
			CFLAGS_RETPOLINE="-mindirect-branch=thunk-inline -mindirect-branch-register -DRETPOLINE_MLNX"
		fi
	fi
	;;
esac

if ! check_kerver ${KVERSION} ${SWITCH_SUPPORTED_KVERSION}; then
	if ! check_kerver_rh ${KVERSION}; then
		if ! check_kerver_list $KVERSION $SWITCH_SUPPORTED_KVERSION_LIST; then
			CONFIG_MLX5_ESWITCH=
			CONFIG_MLX5_SW_STEERING=
			echo "Warning: CONFIG_MLX5_ESWITCH requires kernel version ${SWITCH_SUPPORTED_KVERSION} or higher (current: ${KVERSION}). Disabling."
		fi
	fi
fi

if ! check_kerver ${KVERSION} ${CLS_ACT_SUPPORTED_KVERSION}; then
	if ! check_kerver_rh ${KVERSION}; then
		if ! check_kerver_list $KVERSION $CLS_ACT_SUPPORTED_KVERSION_LIST; then
			CONFIG_MLX5_CLS_ACT=
			CONFIG_MLX5_TC_CT=
			CONFIG_MLX5_TC_SAMPLE=
			CONFIG_MLX5_SW_STEERING=
			echo "Warning: CONFIG_MLX5_CLS_ACT requires kernel version ${CLS_ACT_SUPPORTED_KVERSION} or higher (current: ${KVERSION})."
		fi
	fi
fi

if ! check_kerver ${KVERSION} ${MLXDEVM_SUPPORTED_KVERSION}; then
    CONFIG_MLXDEVM=
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

        # Create config.mk
        /bin/rm -f ${CWD}/${CONFIG}
        cat >> ${CWD}/${CONFIG} << EOFCONFIG
KVERSION=${KVERSION}
CONFIG_COMPAT_VERSION=${CONFIG_COMPAT_VERSION}
CONFIG_COMPAT_KOBJECT_BACKPORT=${CONFIG_COMPAT_KOBJECT_BACKPORT}
BACKPORT_INCLUDES=${BACKPORT_INCLUDES}
ARCH=${ARCH}

CFLAGS_RETPOLINE=${CFLAGS_RETPOLINE}

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
CONFIG_MLX5_CLS_ACT=${CONFIG_MLX5_CLS_ACT:-''}
CONFIG_MLX5_SW_STEERING:=${CONFIG_MLX5_SW_STEERING}
CONFIG_MLX5_ACCEL:=${CONFIG_MLX5_ACCEL}
CONFIG_MLX5_EN_ACCEL_FS:=${CONFIG_MLX5_EN_ACCEL_FS}
CONFIG_MLX5_MPFS:=${CONFIG_MLX5_MPFS}
CONFIG_MLX5_EN_TLS:=${CONFIG_MLX5_EN_TLS}
CONFIG_MLX5_TLS:=${CONFIG_MLX5_TLS}
CONFIG_MLX5_SF:=${CONFIG_MLX5_SF}
CONFIG_MLX5_SF_MANAGER:=${CONFIG_MLX5_SF_MANAGER}
CONFIG_MLXDEVM:=${CONFIG_MLXDEVM}
CONFIG_MLXFW:=${CONFIG_MLXFW}
CONFIG_MLNX_BLOCK_REQUEST_MODULE:=${CONFIG_MLNX_BLOCK_REQUEST_MODULE}
EOFCONFIG

echo "Created ${CONFIG}:"
cat ${CWD}/${CONFIG}

# Create autoconf.h
#/bin/rm -f ${CWD}/include/linux/autoconf.h
if (/bin/ls -1 ${KSRC_OBJ}/include/*/autoconf.h 2>/dev/null | head -1 | grep -q generated); then
    AUTOCONF_H="${CWD}/include/generated/autoconf.h"
    mkdir -p ${CWD}/include/generated
else
    AUTOCONF_H="${CWD}/include/linux/autoconf.h"
    mkdir -p ${CWD}/include/linux
fi

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

cat >> ${AUTOCONF_H}<< EOFAUTO
$(echo -e "${DEFINE_MLX5_CORE}")
$(echo -e "${DEFINE_MLX5_CORE_EN}")
$(echo -e "${DEFINE_MLX5_CORE_EN_DCB}")
$(echo -e "${DEFINE_MLX5_EN_ARFS}")
$(echo -e "${DEFINE_MLX5_EN_RXNFC}")
$(echo -e "${DEFINE_MLX5_ESWITCH}")
$(echo -e "${DEFINE_MLX5_CLS_ACT}")
$(echo -e "${DEFINE_MLX5_SW_STEERING}")
$(echo -e "${DEFINE_MLX5_MPFS}")
$(echo -e "${DEFINE_MLX5_ACCEL}")
$(echo -e "${DEFINE_MLX5_EN_ACCEL_FS}")
$(echo -e "${DEFINE_MLX5_EN_TLS}")
$(echo -e "${DEFINE_MLX5_TLS}")
$(echo -e "${DEFINE_MLX5_SF}")
$(echo -e "${DEFINE_MLX5_SF_MANAGER}")
$(echo -e "${DEFINE_MLXDEVM}")
$(echo -e "${DEFINE_MLXFW}")
$(echo -e "${DEFINE_COMPAT_OLD_VERSION}")
$(echo -e "${DEFINE_COMPAT_KOBJECT_BACKPORT}")
$(echo -e "${DEFINE_CONFIG_MLNX_BLOCK_REQUEST_MODULE}")
EOFAUTO

echo "Running configure..."
cd compat
if [[ ! -x configure ]]; then
    ex ./autogen.sh
fi

/bin/cp -f Makefile.real Makefile
/bin/cp -f Makefile.real Makefile.in

ex ./configure --with-linux-obj=$KSRC_OBJ --with-linux=$KSRC --with-njobs=$NJOBS

}

main $@
