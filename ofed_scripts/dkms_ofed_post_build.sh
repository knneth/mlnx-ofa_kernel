#!/bin/bash
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
