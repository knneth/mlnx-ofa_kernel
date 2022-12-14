#!/bin/bash
# Usage: ofed_checkout.sh [branch]
#        must be launched from top of git repo

# get ref to "real" stdout
exec 3>&1

# Execute command w/ echo and exit if it fails
ex()
{
        echo "$@" >&3
        eval "$@"
        if [ $? -ne 0 ]; then
                printf "\nFailed executing $@\n" >&3
                exit 1
        fi
}

# Like ex above, but command is self echoing on stderr
xex()
{
        eval "$@" 2>&3
        if [ $? -ne 0 ]; then
                printf "\nFailed executing $@\n" >&3
                exit 1
        fi
}

# branch defaults to ofed_kernel
branch=${1:-ofed_kernel}

git checkout -f ${branch}

ex git update-ref HEAD ${branch}

ln -snf ofed_scripts/configure
ln -snf ofed_scripts/Makefile
ln -snf ofed_scripts/makefile
