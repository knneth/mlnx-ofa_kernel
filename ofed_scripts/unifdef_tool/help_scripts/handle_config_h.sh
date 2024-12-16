#!/bin/bash

sed -e 's/\/\*\s*\(#undef .*\) \*\//\1/g' \
	-e '/\/\*/d' -e '/\*\//d' \
	-e '/LINUX_BACKPORT/d' \
	-e '/based on/d' \
	-e '/#endif/d' \
	-e '/^\s*$/d'