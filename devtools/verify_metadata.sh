#!/bin/bash
#
# Copyright (c) 2016 Mellanox Technologies. All rights reserved.
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
#
# Author: Alaa Hleihel - alaa@mellanox.com
#
#########################################################################

WDIR=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd | sed -e 's/devtools//')
ORIG_ARGS=$@
path=
check_commits=
list_no_metadata=
check_range=

FEATURES_DB="metadata/features_metadata_db.csv"
STATUS_DB="NA \
		   ignore \
		   in_progress \
		   sent
		   accepted \
		   rejected \
"

# Global constants for tracking issue IDs and validation patterns
IGNORE_TRACKING_ISSUE_ID="4468524"
NA_TRACKING_ISSUE_ID="4468530"

usage()
{
	cat <<EOF
Usage:
	${0##*/} [options]

Options:
	-p, --path <PATH>           Path to the metadata file to test

	-c, --check-commits [RANGE] Report commits that change C/H source files but
	                            have no metadata entry. Commits that don't touch
	                            any C/H file are not required to have metadata and
	                            are skipped.
	                            RANGE is optional: if omitted, the whole tree
	                            (all commits reachable from HEAD) is scanned; if
	                            given, it is any git revision range, e.g. 'BASE..'
	                            or 'origin/mlnx_ofed_26_07..HEAD'.

	-l, --list-no-metadata [RANGE]
	                            List ALL commits that have no metadata entry,
	                            whether or not they change C/H files. Each commit
	                            is tagged whether metadata is required (changes
	                            C/H) or not. RANGE is optional (whole tree if
	                            omitted). Informational - always exits 0.
EOF
}

while [ ! -z "$1" ]
do
	case "$1" in
		-p | --path)
		path="$2"
		shift
		;;
		-c | --check-commits)
		check_commits=1
		# RANGE is optional: consume the next argument as the range only if it
		# is present and is not another option. If omitted, scan the whole tree.
		if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
			check_range="$2"
			shift
		fi
		;;
		-l | --list-no-metadata)
		list_no_metadata=1
		# RANGE is optional, same handling as --check-commits.
		if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
			check_range="$2"
			shift
		fi
		;;
		-h | *help | *usage)
		echo "This script will verify the content of a metadata file."
		usage
		exit 0
		;;
		*)
		echo "-E- Unsupported option: $1" >&2
		exit 1
		;;
	esac
	shift
done


get_subject()
{
	local cid=$1; shift

	echo $(git log -1 --format="%s" $cid)
}

get_id_from_csv()
{
	local line=$1; shift

	echo $(echo "$line" | sed -r -e 's/.*Change-Id=\s*//' -e 's/;\s*subject=.*//')
}

get_commitID()
{
	local uid=$1; shift

	if (git log --format="%h" -1 $uid >/dev/null 2>&1); then
		echo "$uid"
	else
		echo $(git log --format="%h" -1 --grep="$uid" 2>/dev/null)
	fi
}

get_subject_from_csv()
{
	local line=$1; shift

	echo $(echo "$line" | sed -r -e 's/.*;\s*subject=\s*//' -e 's/;\s*feature.*//')
}

get_feature_from_csv()
{
	local line=$1; shift

	echo $(echo "$line" | sed -r -e 's/.*;\s*feature=\s*//' -e 's/;\s*upstream_status.*//')
}

get_upstream_from_csv()
{
	local line=$1; shift

	echo $(echo "$line" | sed -r -e 's/.*;\s*upstream_status=\s*//' -e 's/;\s*upstream_issue.*//')
}

get_tag_from_csv()
{
	local line=$1; shift

	echo "$line" | sed -e 's/.*tag://g' -e 's/;//g'
}

validate_revert_upstream_status()
{
	local revert_metadata_entry=$1
	local revert_upstream_status=$2

	if [[ "$revert_upstream_status" != "ignore" && "$revert_upstream_status" != "NA" ]]; then
		echo "- The following entry is of a Revert commit and must have upstream_status=ignore or NA: \n$revert_metadata_entry"
		return 1
	fi
	return 0
}

validate_revert_tracking_issue()
{
	local revert_commit_hash=$1
	local revert_commit_msg=$2
	local revert_upstream_status=$3

	# Skip validation for commits already in remote branches as we can't update the commit messages of merged commits
	if git branch --remotes --contains "$revert_commit_hash" | grep --quiet .; then
		return 0
	fi

	if [ "$revert_upstream_status" = "ignore" ]; then
		if ! echo "$revert_commit_msg" | grep --quiet --ignore-case "Issue: $IGNORE_TRACKING_ISSUE_ID"; then
			echo "- Commit $revert_commit_hash is a Revert commit with upstream_status=ignore, but is missing 'Issue: $IGNORE_TRACKING_ISSUE_ID'. Please insert this issue number to the commit message."
			return 1
		fi
	elif [ "$revert_upstream_status" = "NA" ]; then
		if ! echo "$revert_commit_msg" | grep --quiet --ignore-case "Issue: $NA_TRACKING_ISSUE_ID"; then
			echo "- Commit $revert_commit_hash is a Revert commit with upstream_status=NA, but is missing 'Issue: $NA_TRACKING_ISSUE_ID'. Please insert this issue number to the commit message."
			return 1
		fi
	fi
	return 0
}

validate_reverted_commit_status()
{
	local reverted_commit_change_id=$1
	local all_metadata_files=$2
	local revert_metadata_entry=$3

	for meta_file in $all_metadata_files; do
		if grep --quiet "Change-Id=$reverted_commit_change_id;" "$meta_file" && \
		   ! grep --quiet "Change-Id=$reverted_commit_change_id;.*upstream_status=ignore;" "$meta_file"; then
			# Find and print the actual reverted commit entry, not the revert entry
			local reverted_commit_entry=$(grep "Change-Id=$reverted_commit_change_id;" "$meta_file")
			echo "- In file '$meta_file': The following entry is of a reverted commit and must have upstream_status=ignore: \n$reverted_commit_entry"
			return 1
		fi
	done
	return 0
}

validate_revert_and_reverted_metadata()
{
	local revert_metadata_entry=$1
	local all_metadata_files=$2
	local revert_errors=""
	local revert_upstream_status=$(echo "$revert_metadata_entry" | grep --only-matching 'upstream_status=[^;]*' | cut --delimiter='=' --fields=2)
	local revert_change_id=$(echo "$revert_metadata_entry" | grep --only-matching 'Change-Id=[^;]*' | cut --delimiter='=' --fields=2)

	# Validate the Revert commit upstream status is ignore or NA
	local error_msg=$(validate_revert_upstream_status "$revert_metadata_entry" "$revert_upstream_status")
	if [ ! -z "$error_msg" ]; then
		revert_errors="$revert_errors\n$error_msg"
	fi

	# Validate the correct tracking issue is in the Revert commit message (ignore or NA tracking issues based on the Revert commit upstream status)
	local revert_commit_hash=$(git log --all --grep="Change-Id: $revert_change_id" --format='%H' | head --lines=1)
	local revert_commit_msg=$(git show --no-patch --format=%B "$revert_commit_hash")
	error_msg=$(validate_revert_tracking_issue "$revert_commit_hash" "$revert_commit_msg" "$revert_upstream_status")
	if [ ! -z "$error_msg" ]; then
		revert_errors="$revert_errors\n$error_msg"
	fi

	# Extract and validate the metadata entry of the commit that was reverted
	local reverted_commit_hash=$(echo "$revert_commit_msg" | grep --only-matching '[a-fA-F0-9]\{7,40\}' | head --lines=1)
	local reverted_commit_change_id=$(git show "$reverted_commit_hash" 2>/dev/null | grep "Change-Id:" | grep --only-matching 'I[a-fA-F0-9]\{40\}')
	error_msg=$(validate_reverted_commit_status "$reverted_commit_change_id" "$all_metadata_files" "$revert_metadata_entry")
	if [ ! -z "$error_msg" ]; then
		revert_errors="$revert_errors\n$error_msg"
	fi

	# Return accumulated errors if any
	if [ ! -z "$revert_errors" ]; then
		echo "$revert_errors"
		return 1
	fi
	return 0
}

# Returns 0 if the commit changes at least one C/H source file, 1 otherwise.
# Commits that don't touch any C/H file are not required to have metadata.
commit_touches_c_or_h()
{
	local cid=$1; shift

	for ff in $(git log -1 --name-only --pretty=format: $cid 2>/dev/null)
	do
		[ -z "$ff" ] && continue
		case $ff in
			*.c | *.h)
			return 0
			;;
		esac
	done
	return 1
}

# Returns 0 if the commit has a metadata entry in metadata/*.csv, 1 otherwise.
commit_has_metadata()
{
	local cid=$1; shift
	local changeID=$(git log -1 --format=%B $cid | grep -iE '^Change-Id:' | head -1 | sed -r -e 's/.*:\s*//')

	if [ -n "$changeID" ] && grep -q -- "Change-Id=$changeID;" $WDIR/metadata/*.csv 2>/dev/null; then
		return 0
	fi
	# Fall back to commit-Id, used for merged commits without a Change-Id.
	if grep -q -- "commit-Id=$cid" $WDIR/metadata/*.csv 2>/dev/null; then
		return 0
	fi
	return 1
}

##################################################################
#
# main
#

# --check-commits mode: list commits that require metadata (touch C/H files)
# but don't have a metadata entry yet. Scan the whole tree by default, or the
# given range if one was provided.
if [ -n "$check_commits" ]; then
	if [ -z "$check_range" ]; then
		echo "Checking metadata for the whole tree (all commits reachable from HEAD)..."
	else
		echo "Checking metadata for commits in range '$check_range'..."
	fi
	echo "(commits that don't change any C/H file don't require metadata and are skipped)"
	echo ----------------------------------------------------

	missing=
	missing_num=0
	skipped_num=0
	for cid in $(git log --no-merges --format="%h" $check_range 2>/dev/null)
	do
		[ -z "$cid" ] && continue
		if ! commit_touches_c_or_h $cid; then
			echo "-I- SKIP $cid '$(get_subject $cid)' (no C/H change, metadata not required)"
			skipped_num=$(( skipped_num + 1 ))
			continue
		fi
		if ! commit_has_metadata $cid; then
			echo "-E- $cid '$(get_subject $cid)' changes C/H files but has no metadata entry!"
			missing="$missing $cid"
			missing_num=$(( missing_num + 1 ))
		fi
	done

	echo ----------------------------------------------------
	echo "Skipped $skipped_num commit(s) that don't change any C/H file (metadata not required)."
	if [ -z "$missing" ]; then
		echo "All commits that change C/H files have metadata. All passed."
		exit 0
	fi
	echo "Found $missing_num commit(s) that change C/H files but are missing metadata."
	exit 1
fi

# --list-no-metadata mode: list ALL commits that have no metadata entry,
# whether or not they change C/H files. Informational only - always exits 0.
if [ -n "$list_no_metadata" ]; then
	if [ -z "$check_range" ]; then
		echo "Listing commits with no metadata entry in the whole tree..."
	else
		echo "Listing commits with no metadata entry in range '$check_range'..."
	fi
	echo ----------------------------------------------------

	none_num=0
	required_num=0
	for cid in $(git log --no-merges --format="%h" $check_range 2>/dev/null)
	do
		[ -z "$cid" ] && continue
		if commit_has_metadata $cid; then
			continue
		fi
		none_num=$(( none_num + 1 ))
		if commit_touches_c_or_h $cid; then
			echo "-E- $cid '$(get_subject $cid)' (changes C/H - REQUIRES metadata)"
			required_num=$(( required_num + 1 ))
		else
			echo "-I- $cid '$(get_subject $cid)' (no C/H change - metadata not required)"
		fi
	done

	echo ----------------------------------------------------
	echo "$none_num commit(s) have no metadata entry ($required_num of them change C/H files and require it)."
	exit 0
fi

if [ ! -e "$path" ]; then
	echo "-E- File doesn't exist '$path' !" >&2
	echo
	usage
	exit 1
fi

RC=0
echo "Scanning file..."
while read -r line
do
	case "$line" in
		*sep*)
		continue
		;;
	esac
	cerrs=

	uid=$(get_id_from_csv "$line")
	if [ "X$uid" == "X" ]; then
		cerrs="$cerrs\n-E- Missing unique ID!"
		RC=$(( $RC + 1))
		echo -n "At line --> '$line'"
		echo -e "$cerrs"
		continue
	fi
	if [ $(grep -wq -- "$uid" $path | wc -l) -gt 1 ]; then
		cerrs="$cerrs\n-E- unique ID '$uid' apprease twice in given csv file!"
		RC=$(( $RC + 1))
		echo -n "At line --> '$line'"
		echo -e "$cerrs"
		continue

	fi
	cid=$(get_commitID $uid)
	if [ -z "$cid" ]; then
		cerrs="$cerrs\n-E- Failed to get commit ID!"
		RC=$(( $RC + 1))
		echo -n "At line --> '$line'"
		echo -e "$cerrs"
		continue
	fi
	commit_subject=$(get_subject $cid)
	line_subject=$(get_subject_from_csv "$line")
	if [ "X$commit_subject" != "X$line_subject" ]; then
		cerrs="$cerrs\n-E- commit $cid subject is wrong (in csv:'$line_subject' vs. in commit:'$commit_subject') !"
		RC=$(( $RC + 1))
	fi

	feature=$(get_feature_from_csv "$line")
	if [ -z "$feature" ]; then
		cerrs="$cerrs\n-E- missing feature field!"
		RC=$(( $RC + 1))
	elif ! (grep -Ewq -- "name=\s*$feature" $WDIR/$FEATURES_DB); then
		cerrs="$cerrs\n-E- feature '$feature' does not exist in '$FEATURES_DB' !"
		RC=$(( $RC + 1))
	fi

	upstream=$(get_upstream_from_csv "$line")
	if [ -z "$upstream" ]; then
		cerrs="$cerrs\n-E- missing upstream_status field!"
		RC=$(( $RC + 1))
	elif ! (echo -e "$STATUS_DB" | grep -wq -- "$upstream"); then
		cerrs="$cerrs\n-E- invalid upstream_status '$upstream' !"
		RC=$(( $RC + 1))
	fi

	upstream=$(get_upstream_from_csv "$line")
	if (echo -e "accepted" | grep -wq -- "$upstream"); then
		tag=$(get_tag_from_csv "$line")
		if  [ -z "$tag" ] ; then
			cerrs="$cerrs\n-E- missing tag for the accepted commit!"
			RC=$(( $RC + 1))
		elif !   echo $tag | grep -Eq '^v?(2\.6|[3-9])\.[0-9]+(-rc[1-9]+(-s)?)?$'  ; then
			cerrs="$cerrs\n-E- tag: $tag has wrong format! Expected format like: v5.3-rc1 or v5.3"
			RC=$(( $RC + 1))
		fi
	fi

	if (echo $feature | grep -Eq "_bugs$"); then
		if (echo -e "in_progress NA" | grep -wq -- "$upstream"); then
			commit_msg=$(git log -1 --format="%b" $cid)
			if !(echo "$commit_msg"  | grep -Eq "^[F|f]ixes: [0-9a-f]{12,40}" ); then
				cerrs="$cerrs\n-E- Missing or wrong format of 'Fixes' line in commit message! Excpected format like: 'Fixes: <12+ chars of sha1>'"
				RC=$(( $RC + 1))
			fi
		fi
	fi

	# Check for revert commits and make sure that the metadata entries of both the Revert commit and the commit that was reverted are valid
	if echo "$line" | grep -q 'subject=Revert "'; then
		all_metadata_files=$(find metadata/ -name '*.csv' ! -name 'features_metadata_db.csv')
		revert_errors=$(validate_revert_and_reverted_metadata "$line" "$all_metadata_files")
		if [ ! -z "$revert_errors" ]; then
			cerrs="$cerrs\n$revert_errors"
			RC=$(( $RC + 1))
		fi
	fi

	if [ ! -z "$cerrs" ]; then
		echo -n "At line --> '$line'"
		echo -e "$cerrs"
		echo
	fi

done < <(cat $path)


# Check all metadata csv files to ensure upstream_issue is used in each entry
# in which upstream_status=in_progress.

all_metadata_files=$(find metadata/ -name '*.csv' ! -name 'features_metadata_db.csv')

for file in $all_metadata_files; do
    missing_upstream_issues=$(awk '!/sep=/ && /upstream_status=in_progress;/ && /upstream_issue=;/' "$file")
    if [ -n "$missing_upstream_issues" ]; then
        echo -e "-E- In file '$file': entries with upstream_status=in_progress but missing or empty upstream_issue:\n$missing_upstream_issues\n"
        RC=$((RC + $(echo "$missing_upstream_issues" | wc -l)))
    fi

done

echo "Found $RC issues."
if [ $RC -ne 0 ]; then
	echo "Please fix the above issues by manaully editing '$path'."
	echo "Then run the follwoing command to verify that all is OK:"
	echo "# $0 $ORIG_ARGS"
else
	echo "All passed."
fi
exit $RC
