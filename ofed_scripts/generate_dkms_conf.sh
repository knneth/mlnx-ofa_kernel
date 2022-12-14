#!/bin/bash
#
# Copyright (c) 2012 Mellanox Technologies. All rights reserved.
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
#
#

cd ${0%*/*}

kernelver=${kernelver:-`uname -r`}
kernel_source_dir=${kernel_source_dir:-"/lib/modules/$kernelver/build"}
PACKAGE_NAME=${PACKAGE_NAME:-"mlnx-ofed-kernel"}
PACKAGE_VERSION=${PACKAGE_VERSION:-"5.4"}

echo STRIP_MODS=\${STRIP_MODS:-"yes"}
echo kernelver=\${kernelver:-\$\(uname -r\)}
echo kernel_source_dir=\${kernel_source_dir:-"/lib/modules/\$kernelver/build"}

modules=`./dkms_ofed $kernelver $kernel_source_dir get-modules`

echo 'i=0'

for module in $modules
do
	name=`echo ${module##*/} | sed -e "s/.ko.gz//" -e "s/.ko//"`
	if [ "$name" = 'auxiliary' ]; then
		echo "if [[ \$(VER \$kernelver) < \$(VER '5.11.0') ]]; then"
	fi
	if [ "$name" = 'mlxdevm' ]; then
		echo "if [[ ! \$(VER \$kernelver) < \$(VER '4.15.0') ]]; then"
	fi
	echo 'BUILT_MODULE_NAME[$i]='$name
	echo 'BUILT_MODULE_LOCATION[$i]='${module%*/*}
	echo 'DEST_MODULE_NAME[$i]='$name
	echo 'DEST_MODULE_LOCATION[$i]='/kernel/${module%*/*}
	echo 'STRIP[$i]="$STRIP_MODS"'
	echo 'let i++'
	case "$name" in auxiliary | mlxdevm)
		echo "fi";;
	esac
done

EXTRA_OPTIONS="--with-mlx5-ipsec --with-gds --without-gds --with-sf-cfg-drv"
for option in $EXTRA_OPTIONS; do
	if echo "$configure_options" | grep -q -- "$option"; then
		echo "#:# ExtraOption $option"
	fi
done

echo MAKE=\"./ofed_scripts/pre_build.sh \$kernelver \$kernel_source_dir $PACKAGE_NAME $PACKAGE_VERSION\"
echo CLEAN=\"make clean\"
echo PACKAGE_NAME=$PACKAGE_NAME
echo PACKAGE_VERSION=$PACKAGE_VERSION
echo REMAKE_INITRD=yes
echo AUTOINSTALL=yes
# W/A for DKMS parallel build on kernel update which causes ULP build to fail
echo POST_INSTALL=\"ofed_scripts/dkms_build_ulps.sh \$kernelver\"

#       POST_ADD=
#              The name of the script to be run after an add is performed.  The path should be given relative to the root directory of your source.
#
#       POST_BUILD=
#              The name of the script to be run after a build is performed. The path should be given relative to the root directory of your source.
#
#       POST_INSTALL=
#              The name of the script to be run after an install is performed. The path should be given relative to the root directory of your source.
#
#       POST_REMOVE=
#              The name of the script to be run after a remove is performed. The path should be given relative to the root directory of your source.
#
#       PRE_BUILD=
#              The name of the script to be run before a build is performed. The path should be given relative to the root directory of your source.
#
#       PRE_INSTALL=
#              The name of the script to be run before an install is performed. The path should be given relative to the root directory of your source.  If the script exits with a non-zero value, the  install  will
#              be aborted.  This is typically used to perform a custom version comparison.
