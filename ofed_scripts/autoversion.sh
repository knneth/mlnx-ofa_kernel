#!/bin/bash

if [ "$AUTOVERSION" != "1" ]; then
    exit
fi

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

d=`git describe --tags`
if [[ "$d" == vmlnx-ofed-* ]]; then
    v=${d:11}
else
    v=`git log --pretty=format:"%h" -1`
    v="5.0-g$v"
fi
echo "Set autoversion to $v"
sed -i -e "s/DRIVER_VERSION \"5.0-0\"/DRIVER_VERSION \"$v\"/g" drivers/net/ethernet/mellanox/mlx5/core/mlx5_core.h
