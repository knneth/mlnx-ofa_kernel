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

SCRIPTS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SCRIPT_NAME="$(basename "$0")"
WORK_DIR="$(dirname $(dirname ${SCRIPTS_DIR}))"
CUSTOM_OFA_DIR=
CUSTOM_CONFIG=
INCLUDE_MK_CONFIG=0
COMMIT=1
CONFIG=$(mktemp "/tmp/final_defs_XXXXXX.h")
while [ ! -z "$1" ]
do
	case "$1" in
		-d | --directory)
		CUSTOM_OFA_DIR="$2"
		if [ ! -d "$CUSTOM_OFA_DIR" ]; then
			echo "Path '$CUSTOM_OFA_DIR' is not a directory,"
			echo "Please make sure to give mlnx_ofed directory path as argument."
			echo "Aborting.."
			exit 1
		fi
		shift;
		;;
		-c | --config-file)
		CUSTOM_CONFIG="$2"
		if [ ! -f "$CUSTOM_CONFIG" ]; then
			echo "Path '$CUSTOM_CONFIG' is not a file,"
			echo "Please make sure to give config.h file path as argument."
			echo "Aborting.."
			exit 1
		fi
		shift;
		;;
		--include_mk_config)
		INCLUDE_MK_CONFIG=1
		;;
		--without-commit)
		COMMIT=0
		;;
		-h | --help)
		echo "Usage: ${SCRIPT_NAME} [options]

	use this script to get OFED code without #ifdef.


		-h, --help 		Display this help message and exit.
		-d, --directory		Path to specific OFED directory,
					default is '$WORK_DIR'.
		-c, --config-file	Path to specific ready config file,
					script will not create new one.
		--include_mk_config	Include filtered configs found in
					configure.mk.kernel to be removed by
					unifdef.
		--without-commit	Script won't create commit at the
					end of the run.

	Requirements:
	-------------
	1. unifdef must be installed over setup.
	2. OFED must be after configure stage.

"
		exit 1
		;;
		*)
		echo "-E- Unsupported option: $1" >&2
		echo "use -h flag to display help menu"
		exit 1
		;;
	esac
	shift
done
if [ ! -z "$CUSTOM_OFA_DIR" ];then
	WORK_DIR="$CUSTOM_OFA_DIR"
fi
echo "Verify script requirements"
if ! command -v unifdef &> /dev/null; then
	echo "'unifdef' must be installed before script use, Aborting.." >&2
	exit 1
fi
dir_owner=$(stat -c '%U' "$WORK_DIR")
if [ ! "$USER" == "$dir_owner" ]; then
	echo "$USER, please run this script as given dir owner: $dir_owner" >&2
	echo "Aborting.." >&2
	exit 1
fi
cd "$WORK_DIR"
IS_GIT="$(git rev-parse --is-inside-work-tree 2>/dev/null)"
if [ ! "$IS_GIT" = true ];then
		echo "-E- The given directory: ${WORK_DIR} must be git repo, Aborting.." >&2
		exit 1
fi
if [ -z "$CUSTOM_CONFIG" ] && [ ! -f "compat/config.h" ]; then
	echo "-E- 'compat/config.h' is missing!" >&2
	echo "Script must be run after ./configure stage, Aborting.." >&2
	exit 1
fi
if [ ! -z "$CUSTOM_CONFIG" ] && [ ! -f "backports_applied" ]; then
	echo "-E- 'backports_applied' is missing!" >&2
	echo "Script must be run after './ofed_scripts/ofed_patch.sh' stage, Aborting.." >&2
	exit 1
fi
if [ -z "$CUSTOM_CONFIG" ];then
	"$SCRIPTS_DIR"/help_scripts/build_defs_file.sh "$WORK_DIR" "$CONFIG" "$INCLUDE_MK_CONFIG"
	if [ $? -ne 0 ]; then
		exit 1
	fi
else
	echo "Using custom config: $CUSTOM_CONFIG, parsing it without notes under $CONFIG"
	cat "$CUSTOM_CONFIG" | "$SCRIPTS_DIR/help_scripts/handle_config_h.sh" > "$CONFIG"
fi
if [ ! -f "${CONFIG}" ]; then
	echo "-E- Config file does not exist at '${CONFIG}'" >&2
	exit 1
fi
echo "Verify '${CONFIG}'"
file="$(mktemp ${WORK_DIR}/check_XXXXXX.c)"
trap "rm -rf $file" 0
unifdef -f "${CONFIG}" "$file"
if [ "$?" -eq 2 ]; then
	echo
	echo "-E- Config file need manual edit:
preprocessor directives [#if|#else|#endif] must be removed from file
Aborting..." >&2
	exit 1
fi
echo "Verification done, start running.."
# This part search & remove risk defines that can change their values during compilation
#if [ -z "$CUSTOM_CONFIG" ];then
#	echo "search & remove risk defines that can change their values during compilation"
#	for d in $(grep -rE "^#define.*HAVE_.*|^#undef.*HAVE_.*" | grep -v compat/config | grep -v compat/configure.ac | grep -v backports | grep -v output | grep -vi binary | sed 's/.*\(HAVE_[A-Z0-9_]*\).*/\1/' | sort | uniq)
#	do
#		sed -i "/\<${d}\>/d" "${CONFIG}"
#	done
#fi
echo "start cleaning files.."
MOD="tmp.txt"
for i in $(find "${WORK_DIR}" \( -name '*.c' -o \
			  -name '*.h' -o \
			  -name 'Kbuild' -o \
			  -name 'Makefile' \) )
do
	if echo "$i" | grep -qE ".*config\.h"; then
		echo "-I- Ignore $i file"
		continue
	fi
	echo "cleaning ${i} ..."
	perl -p -e 'next unless (/defined/); s/\\\n/ /' "${i}" > "$MOD"
	unifdef -f "${CONFIG}" "$MOD" -o "${i}".tmp
	mv -f "${i}".tmp "${i}"
done
rm -rf "$MOD"
if [ ${COMMIT} -eq 1 ]; then
	echo "Create git commit!"
	git add -u
	git commit -s -m "BASECODE: remove #ifdef from code"
else
	echo "No git commit created!"
fi

echo
echo "Script ended succsfully!"
echo "---------------------------------------------------------------------------"
echo "OFED plain basecode directory: '$WORK_DIR'"
echo "Config used: '$CONFIG'"
echo "---------------------------------------------------------------------------"
echo
echo "Revert changes by running 'git reset --hard HEAD^'"
