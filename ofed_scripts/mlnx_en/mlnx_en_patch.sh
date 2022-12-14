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

usage()
{
cat << EOF

Usage: `basename $0` [--help]: Prints this message
		[--with-memtrack]: Compile with memtrack kernel module to debug memory leaks
		[-k|--kernel <kernel version>]: Build package for this kernel version. Default: $KER_UNAME_R
		[-s|--kernel-sources  <path to the kernel sources>]: Use these kernel sources for the build. Default: $KER_PATH
		[-j[N]|--with-njobs=[N]] : Allow N configure jobs at once; jobs as number of CPUs with no arg.
EOF
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
			--without-mlx4)
				CONFIG_MLX4_CORE=""
				CONFIG_MLX4_EN=""
				DEFINE_MLX4_CORE='#undef CONFIG_MLX4_CORE'
				DEFINE_MLX4_EN='#undef CONFIG_MLX4_EN'
			;;
			--without-mlx5)
				CONFIG_MLX5_CORE=""
				DEFINE_MLX5_CORE='#undef CONFIG_MLX5_CORE'
				CONFIG_MLX5_CORE_EN=""
				DEFINE_MLX5_CORE_EN='#undef CONFIG_MLX5_CORE_EN'
				CONFIG_MLX5_CORE_EN_DCB=""
				DEFINE_MLX5_CORE_EN_DCB='#undef CONFIG_MLX5_CORE_EN_DCB'
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
	VALUE=$(tac ${KSRC}/include/*/autoconf.h | grep -m1 ${VAR} | sed -ne 's/.*\([01]\)$/\1/gp')

	eval "export $VAR=$VALUE"
}

main() {

#Set default values
WITH_QUILT=${WITH_QUILT:-"yes"}
WITH_PATCH=${WITH_PATCH:-"yes"}
EXTRA_FLAGS=""
CONFIG_MEMTRACK=""
CONFIG_MLX4_EN_DCB=""
CONFIG_MLX4_CORE="m"
CONFIG_MLX4_EN="m"
CONFIG_MLX5_CORE="m"
CONFIG_MLX5_CORE_EN="y"
CONFIG_MLX5_CORE_EN_DCB="y"
DEFINE_MLX4_EN_DCB='#undef CONFIG_MLX4_EN_DCB'
DEFINE_MLX4_CORE='#undef CONFIG_MLX4_CORE\n#define CONFIG_MLX4_CORE 1'
DEFINE_MLX4_EN='#undef CONFIG_MLX4_EN\n#define CONFIG_MLX4_EN 1'
DEFINE_MLX5_CORE='#undef CONFIG_MLX5_CORE\n#define CONFIG_MLX5_CORE 1'
DEFINE_MLX5_CORE_EN='#undef CONFIG_MLX5_CORE_EN\n#define CONFIG_MLX5_CORE_EN 1'
DEFINE_MLX5_CORE_EN_DCB='#undef CONFIG_MLX5_CORE_EN_DCB\n#define CONFIG_MLX5_CORE_EN_DCB 1'

parseparams $@

KVERSION=${KVERSION:-$KER_UNAME_R}
KSRC=${KSRC:-"/lib/modules/${KVERSION}/build"}

QUILT=${QUILT:-$(/usr/bin/which quilt  2> /dev/null)}
CWD=$(pwd)
CONFIG="config.mk"
PATCH_DIR=${PATCH_DIR:-""}

if [ "X$CONFIG_MLX4_CORE" != "X" ]; then
	check_autofconf CONFIG_DCB
	if [ X${CONFIG_DCB} == "X1" ]; then
		CONFIG_MLX4_EN_DCB=y
		DEFINE_MLX4_EN_DCB="#undef CONFIG_MLX4_EN_DCB\n#define CONFIG_MLX4_EN_DCB 1"
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
        # Create config.mk
        /bin/rm -f ${CWD}/${CONFIG}
        cat >> ${CWD}/${CONFIG} << EOFCONFIG
KVERSION=${KVERSION}
CONFIG_COMPAT_VERSION=${CONFIG_COMPAT_VERSION}
CONFIG_COMPAT_KOBJECT_BACKPORT=${CONFIG_COMPAT_KOBJECT_BACKPORT}
BACKPORT_INCLUDES=${BACKPORT_INCLUDES}
ARCH=`uname -m`
MODULES_DIR:=/lib/modules/${KVERSION}/updates
KSRC:=${KSRC}
KLIB_BUILD=${KSRC}
CWD=${CWD}
MLNX_EN_EXTRA_CFLAGS:=${EXTRA_FLAGS}
CONFIG_MEMTRACK:=${CONFIG_MEMTRACK}
CONFIG_MLX4_EN_DCB:=${CONFIG_MLX4_EN_DCB}
CONFIG_MLX4_CORE:=${CONFIG_MLX4_CORE}
CONFIG_MLX4_EN:=${CONFIG_MLX4_EN}
CONFIG_MLX5_CORE:=${CONFIG_MLX5_CORE}
CONFIG_MLX5_CORE_EN:=${CONFIG_MLX5_CORE_EN}
CONFIG_MLX5_CORE_EN_DCB:=${CONFIG_MLX5_CORE_EN_DCB}
EOFCONFIG

echo "Created ${CONFIG}:"
cat ${CWD}/${CONFIG}

# Create autoconf.h
#/bin/rm -f ${CWD}/include/linux/autoconf.h
if (/bin/ls -1 $KSRC/include/*/autoconf.h 2>/dev/null | head -1 | grep -q generated); then
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

cat >> ${AUTOCONF_H}<< EOFAUTO
$(echo -e "${DEFINE_MLX4_CORE}")
$(echo -e "${DEFINE_MLX4_EN}")
$(echo -e "${DEFINE_MLX4_EN_DCB}")
$(echo -e "${DEFINE_MLX5_CORE}")
$(echo -e "${DEFINE_MLX5_CORE_EN}")
$(echo -e "${DEFINE_MLX5_CORE_EN_DCB}")
$(echo -e "${DEFINE_COMPAT_OLD_VERSION}")
$(echo -e "${DEFINE_COMPAT_KOBJECT_BACKPORT}")
EOFAUTO

echo "Running configure..."
cd compat
if [[ ! -x configure ]]; then
    ex ./autogen.sh
fi

/bin/cp -f Makefile.real Makefile
/bin/cp -f Makefile.real Makefile.in

build_KSRC=$(echo "$KSRC" | grep -w "build")
linux_obj_KSRC=$(echo "$KSRC" | grep -w "linux-obj")

if [[ -e "/etc/SuSE-release" && -n "$build_KSRC" ]] ||
   [[ -n "$build_KSRC" && -d ${KSRC/build/source} &&
       "X$(readlink -f $KSRC)" != "X$(readlink -f ${KSRC/build/source})" ]]; then
    ex ./configure --with-linux-obj=$KSRC --with-linux=${KSRC/build/source} --with-njobs=$NJOBS
elif [[ -e "/etc/SuSE-release" && -n "$linux_obj_KSRC" ]]; then
    sources_dir=$(readlink -f $KSRC 2>/dev/null | sed -e 's/-obj.*//g')
    ex ./configure --with-linux-obj=$KSRC --with-linux=${sources_dir} --with-njobs=$NJOBS
else
    ex ./configure --with-linux-obj=$KSRC --with-linux=$KSRC --with-njobs=$NJOBS
fi

}

main $@
