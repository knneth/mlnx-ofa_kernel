#!/bin/bash

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
	grep -v "^From " | \
	grep -v "^Date: " > $tmpfile && mv $1 $1.orig && mv $tmpfile $1

