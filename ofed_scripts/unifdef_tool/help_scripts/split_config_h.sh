#!/bin/bash

SCRIPT_NAME=$(basename "$0")
COMPAT_FILE=$1
TEMP_DIR=$2
FOR_SED="splited00"
FOR_UNIFDEF="splited01"
CONFIG_PATH="${TEMP_DIR}/config.h"
CONFIGURE_PATH="${TEMP_DIR}/configure.ac"
SPLIT_LINE="Make sure LINUX_BACKPORT macro is defined for all external users"
echo "Splitting file.."
if [ ! -f "$COMPAT_FILE" ]; then
	echo "-E- ${SCRIPT_NAME}: File entered not exist"
	exit 1
fi
if ! grep -q "$SPLIT_LINE" "$COMPAT_FILE"; then
	echo "-E- ${SCRIPT_NAME}: Could not found where to split, Aborting.."
	echo "current split looks for '${SPLIT_LINE}' pattern"
	exit 1
fi

csplit -q --suppress-matched "$COMPAT_FILE" "/.*${SPLIT_LINE}.*/" -f splited '{*}'
mv -f "$FOR_SED" "$CONFIG_PATH"
mv -f "$FOR_UNIFDEF" "$CONFIGURE_PATH"
rm -rf splited0*
