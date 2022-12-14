#!/bin/bash

cwd=`dirname $0`
out=backports_new

if [ -d $out ]; then 
	if [ "$(ls -A $out)" ]; then
		echo "output directory $out is not empty. Should delete all files in it?"
		read -p "Are you sure? " -n 1
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			echo "Removing $out"
			rm -fr $out
		else
			echo "Aborting"
			exit
		fi
	fi
fi

echo "Preparing patches"

git format-patch -o $out --subject-prefix="PATCH" --no-numbered $1

echo "Stripping id's from patches"
for f in $out/*.patch; do
	$cwd/strip.sh $f;
done
