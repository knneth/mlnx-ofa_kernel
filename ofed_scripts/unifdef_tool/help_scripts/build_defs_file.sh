#!/bin/bash
#
# Copyright (c) 2020 Mellanox Technologies. All rights reserved.
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
# Author: Roy Novich <royno@nvidia.com>
#
# Script usage: ./build_defs_file.sh <ofed_dir_path> <output_filename(optional)>
# This script uses to build config file unifdef can handle from given OFED dir

if [ -d "$1" ]; then
	IS_DIR=1
	WORK_DIR="$1"
	CONFIG_FILE="$WORK_DIR"/compat/config.h
else
	if [ -f "$1" ]; then
		IS_DIR=0
		CONFIG_FILE="$1"
		WORK_DIR="$(pwd)"
	else
		echo "-E- Argument 1 for script must be directory/file path"
		exit 1
	fi

fi
SCRIPTS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TEMP_DIR="$(mktemp -d ${WORK_DIR}/defs_XXXXXX)"
TMP_CONFIG="${TEMP_DIR}/config.h"
TMP_CONFIGURE="${TEMP_DIR}/configure.ac"
TMP_DEF="${TEMP_DIR}/defs_file.h"
MK_PATH="${WORK_DIR}/configure.mk.kernel"
FINAL_CONFIG="$2"
INCLUDE_MK_CONFIG="$3"

cleanup()
{
	echo "Clean tmp files"
	rm -rf "${TEMP_DIR}"
}
trap cleanup 0

if [ -z "$FINAL_CONFIG" ];then
	FINAL_CONFIG="${TEMP_DIR}/final_defs.h"
fi

echo "Start build compat file '$FINAL_CONFIG' for unifdef use"
"$SCRIPTS_DIR"/split_config_h.sh "$CONFIG_FILE" "${TEMP_DIR}"
if [ $? -ne 0 ]; then
	exit 1
fi
cat "$TMP_CONFIG" | "$SCRIPTS_DIR/handle_config_h.sh" > "$TMP_DEF"
if [ "$IS_DIR" -eq 0 ];then
	cat "$TMP_DEF" >> "$FINAL_CONFIG"
else
	cat "$TMP_CONFIGURE" | "$SCRIPTS_DIR/handle_configure_ac.sh" > "$TMP_CONFIGURE.bck1"
	cat "$TMP_CONFIGURE.bck1" | "$SCRIPTS_DIR/handle_config_h.sh" > "$TMP_CONFIGURE.bck"
	mv -f "$TMP_CONFIGURE.bck" "$TMP_CONFIGURE"

	echo "/*-----------------------*/" > $FINAL_CONFIG
	echo "/* config.h defs section */" >> $FINAL_CONFIG
	echo "/*-----------------------*/" >> $FINAL_CONFIG
	if [ "$INCLUDE_MK_CONFIG" -eq 1 ]; then
		echo "/*-----------------------*/" >> $TMP_DEF
		echo "/* configure.mk.kernel defs section */" >> $TMP_DEF
		echo "/*-----------------------*/" >> $TMP_DEF
		grep =y "${MK_PATH}" | sort | uniq | sed -e 's/=y/ 1/' | sed -e 's/^/#define /' >> "$TMP_DEF"
		grep -E "=$"  "${MK_PATH}" | sort | uniq | sed -e 's/=//' | sed -e 's/^/#undef /' >> "$TMP_DEF"
	fi
	cat "$TMP_DEF" >> "$FINAL_CONFIG"
	echo "/*---------------------------*/" >> "$FINAL_CONFIG"
	echo "/* configure.ac defs section */" >> "$FINAL_CONFIG"
	echo "/*---------------------------*/" >> "$FINAL_CONFIG"
	unifdef -f "$TMP_DEF" "$TMP_CONFIGURE" >> "$FINAL_CONFIG"
fi

echo "File '${FINAL_CONFIG}' fully created"

