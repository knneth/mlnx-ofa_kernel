#!/bin/bash

sed -e 's/\/\*\s*\(#undef .*\) \*\//\1/g' \
	-e '/\/\*/d' -e '/\*\//d' \
	-e '/#endif/d' \
	-e '/^\s*$/d'
