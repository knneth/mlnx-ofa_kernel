#!/bin/bash
#
# Copyright (c) 2017 Mellanox Technologies. All rights reserved.
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
set -e

ofa_build_src=/usr/src/ofa_kernel/default/
build_dir=$PWD/../build

echo "Copying build sources from '$build_dir' to '$ofa_build_src' ..."
if [ ! -e "$build_dir" ]; then
	echo "-E- Cannot find build folder at '$build_dir' !" >&2
	exit 1
fi

cd $build_dir

/bin/rm -rf /usr/src/ofa_kernel/default
mkdir -p /usr/src/ofa_kernel/default
/bin/cp -ar include/			$ofa_build_src
/bin/cp -ar config*				$ofa_build_src
/bin/cp -ar compat*				$ofa_build_src
/bin/cp -ar ofed_scripts		$ofa_build_src
/bin/cp -ar Module*.symvers		$ofa_build_src
