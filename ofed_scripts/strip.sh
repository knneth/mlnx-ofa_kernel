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

tmpfile='mktemp' || exit 1

first=`head -1 $1`
if [ ! "${first:0:5}" == "From " ]; then
	echo Missing From at first line, abort
	exit 1
fi
last=`tail -3 $1 | head -1`
if [ ! "$last" == "-- " ]; then
	echo Missing -- at 3rd last line, abort
	exit 1
fi

head -n -3 $1 | \
	sed -e "s/^index [[:xdigit:]]*\.\.[[:xdigit:]]* [[:digit:]]*$/index xxxxxxx..xxxxxxx xxxxxx/" | \
	sed -e "s/^index [[:xdigit:]]*..[[:xdigit:]]*$/index xxxxxxx..xxxxxxx xxxxxx/" | \
	grep -v "^From " | \
	grep -v "^Date: " > $tmpfile && mv $1 $1.orig && mv $tmpfile $1

