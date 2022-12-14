#!/bin/bash

SCRIPTPATH=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd)

current_branch=`git rev-parse --abbrev-ref HEAD`
orig_branch=`echo $current_branch | sed -e 's/backport-//'`

if ! [[ "$current_branch" =~ ^backport-.* ]]; then
	echo "-E- You are not on backports branch!"
	exit 1
fi

rm -rf $SCRIPTPATH/../backports_new
$SCRIPTPATH/ofed_format_patch.sh $orig_branch
rm -f $SCRIPTPATH/../backports_new/*.orig
