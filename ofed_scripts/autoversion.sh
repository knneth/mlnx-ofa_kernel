#!/bin/bash

case "$AUTOVERSION" in
	1|2);;
	*) exit 0;;
esac

if [ ! -e .git ]; then
    exit
fi

if [ ! -e drivers/net/ethernet/mellanox/mlx5/core/mlx5_core.h ]; then
    exit
fi

git --version &>/dev/null
if [ $? -ne 0 ]; then
    exit
fi

d=`git describe --tags --abbrev=0`
if [[ "$d" == vmlnx-ofed-* ]]; then
    v="${d:11}"
else
    v="5.0-0"
fi
v="$v-$(git log --pretty=format:"%h" -1)"
if [ "$AUTOVERSION" == "2" ]; then
	v="$v-$(date +%Y%m%d_%H%M)"
fi
echo "Set autoversion to $v"
sed -i -e "s/.*define.*DRIVER_VERSION.*/#define DRIVER_VERSION \"$v\"/g" drivers/net/ethernet/mellanox/mlx5/core/mlx5_core.h
