#!/bin/bash

kernelver=${1:-$(uname -r)}

is_installed()
{
    if [ "X$(dpkg-query -l $1 2> /dev/null | awk '/^[rhi][iU]/{print $2}')" != "X" ]; then
        return 0
    else
        return 1
    fi
}

echo
echo ------------------------------------------
echo ----- mlnx-ofed-kernel post-install ------
for mod in srp iser isert mlnx-nfsrdma mlnx-nvme-rdma mlnx-nvmet-rdma mlnx-rdma-rxe
do
    echo
    if ! is_installed ${mod}-dkms ; then
        echo "Package '${mod}-dkms' is not installed, skipping module '$mod'."
        continue
    fi

    version=`dpkg-query -W -f='${Version}' "${mod}-dkms" | sed -e 's/[+-].*//'`
    isadded=`dkms status -m "$name" -v "$version" -k $kernelver`

    if (dkms status "$mod" -v "$version" -k $kernelver 2>/dev/null | grep -qwi installed); then
        echo "Module '$mod' is already installed for kernel $kernelver."
        continue
    fi

    echo "Going to build and install module '$mod' for kernel $kernelver."
    if [ "x${isadded}" = "x" ] ; then
        dkms add -m "$mod" -v "$version"
    fi
    # build it
    if ! (dkms build -m "$mod" -v "$version" -k $kernelver); then
        echo "Error! Module build failed for '$mod' $version !" >&2
        continue
    fi
    # install it
    if ! (dkms install -m "$mod" -v "$version" -k $kernelver --force); then
        echo "Error! Module install failed for '$mod' $version !" >&2
        continue
    fi
done
echo ------------------------------------------
echo
