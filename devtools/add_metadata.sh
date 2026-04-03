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

WDIR=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd | sed --expression 's/devtools//')

# Tracking issue constants for revert commits
readonly NA_TRACKING_ISSUE_ID="4468530"
readonly IGNORE_TRACKING_ISSUE_ID="4468524"

# Branch filtering: only process commits from maintained branches
# Maintained branches: mlnx_ofed_5_8 and newer (5.8, 23.xx, 24.xx, 25.xx, etc.)
is_commit_on_maintained_branch() {
	local commit_id=$1

	# Get all branches containing this commit
	local branches=$(git branch -r --contains "$commit_id" 2>/dev/null)

	if [ -z "$branches" ]; then
		return 1  # Commit not found in any remote branch
	fi

	# Check if any branch matches maintained patterns
	echo "$branches" | grep -qE "mlnx_ofed_(5_[89]|[2-9][0-9]_[0-9][0-9])($|[[:space:]])" && return 0

	return 1  # Not found on any maintained branch
}

# Check if author has commits only on old deprecated branches
should_skip_author_for_old_branches() {
	local author=$1

	# Get all commits by this author across all branches
	local author_commits=$(git log --all --format="%h" --author="$author" 2>/dev/null)

	if [ -z "$author_commits" ]; then
		return 1  # No commits found, don't skip
	fi

	# Check if ANY of the author's commits are on maintained branches
	for commit in $author_commits; do
		if is_commit_on_maintained_branch "$commit"; then
			return 1  # Author has commits on maintained branches, don't skip
		fi
	done

	return 0  # All author's commits are only on old branches, skip this author
}

base=
num=
dry_run=0
no_edit=0
no_verify=0
ref_db=
changeid_map=
def_feature=
def_ustatus=
def_uissue=
revert_track_issue=
revert_track_used=

usage()
{
	cat <<EOF
Usage:
	${0##*/} [options]

Options:
    -a, --after <BASE>              Add metadata for new commits after given base (commit ID)

    -n, --num <N>                   Add metadata for the last N commits in the current branch

    -f, --feature <NAME>            Feature name to assign to new commits.
                                    Must exist in: 'metadata/features_metadata_db.csv'

    -s, --upstream-status <STATUS>  Upstream status to assign to new commits.
                                    Valid values: [NA, ignore, in_progress, accepted]

    -i, --upstream-issue  <ISSUE>   Upstream issue to assign to new commits.

    -g, --general <TAG>	            Add current upsream delta tag to general(f.e v5.6-rc2).

    -t, --revert-track <ISSUE>      Avoid interactive choice window while adding revert patches metadata.
                                    Valid values: [4468524, 4468530] (for upstream_status=ignore and upstream_status=NA, respectively).

    --dry-run                       Just print, don't really change anything.

Description for upstream status:
    "NA" -----------> Patch is not applicable for upstream.
                      Examples: OFED-only patches, Reverts of accepted upstream patches...

    "ignore" -------> Patch that should be automatically dropped at next rebase.
                      Examples: Scripts changes, Makefiles, backports, Reverts of upstream patches that'll be safe to include in the next rebese...

    "in_progress" --> Being prepared for Upstream submission.

    "accepted" -----> Accepted upstream, should be automatically dropped at next rebase.
EOF
}

while [ ! -z "$1" ]
do
	case "$1" in
		-a | --after)
		base="$2"
		shift
		;;
		-n | --num)
		num="$2"
		shift
		;;
		--dry-run)
		dry_run=1
		;;
		--no-edit)
		no_edit=1
		;;
		--no-verify)
		no_verify=1
		;;
		-r | --ref-db)
		ref_db="$2"
		shift
		;;
		-m | --change-id-map)
		changeid_map="$2"
		shift
		;;
		-f | --feature)
		def_feature="$2"
		shift
		;;
		-g | --general)
		general="tag: $2"
		shift
		;;
		-s | --upstream-status)
		def_ustatus="$2"
		shift
		;;
		-i | --upstream-issue)
		def_uissue="$2"
		shift
		;;
		-t | --revert-track)
		revert_track_issue="$2"
		revert_track_used=1
		shift
		;;
		-h | *help | *usage)
		echo "This script will add metadata entries for given commits."
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


is_backports_change_only()
{
	local cid=$1; shift

	tgt=0
	other=0
	for ff in $(git log -1 --name-only --pretty=format: $cid 2>/dev/null)
	do
		if [ -z "$ff" ]; then
			continue
		fi
		case $ff in
			backports* | *compat*)
			tgt=1
			;;
			*)
			other=1
			;;
		esac
	done

	if [ $tgt -eq 1 -a $other -eq 0 ]; then
		return 0
	else
		return 1
	fi
}

is_scripts_change_only()
{
	local cid=$1; shift

	tgt=0
	other=0
	for ff in $(git log -1 --name-only --pretty=format: $cid 2>/dev/null)
	do
		if [ -z "$ff" ]; then
			continue
		fi
		case $ff in
			*ofed_scripts* | *debian* | *devtools*  | *metadata* | *scripts*)
			tgt=1
			;;
			*)
			other=1
			;;
		esac
	done

	if [ $tgt -eq 1 -a $other -eq 0 ]; then
		return 0
	else
		return 1
	fi
}

# Helper function to set tracking issue and upstream status
# Returns 0 if valid, 1 if invalid
set_revert_tracking() {
    local choice="$1"
    if [[ "$choice" == "1" || "$choice" == "NA" ]]; then
        commit_msg_tracking_issue="Issue: $NA_TRACKING_ISSUE_ID"
        upstream="NA"
    elif [[ "$choice" == "2" || "$choice" == "ignore" ]]; then
        commit_msg_tracking_issue="Issue: $IGNORE_TRACKING_ISSUE_ID"
        upstream="ignore"
    fi
}

# Validates if revert-track configuration is correct
# Returns 0 if valid, 1 if invalid
is_valid_revert_track_config() {
    [[ ("$revert_track_issue" == "$NA_TRACKING_ISSUE_ID" && "$def_ustatus" == "NA") ||
       ("$revert_track_issue" == "$IGNORE_TRACKING_ISSUE_ID" && "$def_ustatus" == "ignore") ]]
}

# Determines how to handle a revert commit based on --revert-track usage or user input
determine_revert_commit_handling() {

    echo ""
    echo "Revert commit detected: $revert_title"

    # Handle --revert-track usage
    if [ "$revert_track_used" ]; then
        if is_valid_revert_track_config; then
            set_revert_tracking "$def_ustatus"
            return 0
        else
            echo "-E- Invalid --revert-track or -t configuration detected!"
        fi
    fi

    cat <<EOF
Please choose how to handle the Revert commit in the next rebase:
  [1] Include this Revert in the next rebase.
              * Choosing this will set upstream_status=NA and will track this Revert under issue $NA_TRACKING_ISSUE_ID.
              * This is the right choice if we must keep the Revert in case the reverted patch is accepted upstream.
              * For example: This commit reverts an upstream patch that breaks an OFED-only patch/feature.
  [2] Don't include this Revert in the next rebase.
              * Choosing this will set upstream_status=ignore and will track this Revert under issue $IGNORE_TRACKING_ISSUE_ID.
              * This is the right choice if in the next rebase it will be safe to take the upstream implementation of the reverted patch.
              * For example: This commit reverts a problematic in_progress upstream patch that will be fixed upstream and will be
                              safe to include in the next rebase.

EOF

    while true; do
        read -p "Enter your choice [1/2]: " user_choice
        case $user_choice in
            1|2)
                set_revert_tracking "$user_choice"
                return 0
                ;;
            *)
                echo "-E- Invalid choice. Please enter 1 or 2."
                ;;
        esac
    done
}

# Updates commit message by inserting tracking issue before Change-Id and applies the commit
update_revert_commit_msg_with_tracking_issue() {

    # Check if the Issue line already exists in the commit message (case-insensitive)
    if grep --quiet --ignore-case "^$commit_msg_tracking_issue$" "$commit_msg_tmp_file"; then
        return 0
    fi

    # Insert tracking issue before Change-Id line using sed
    sed "/^Change-Id:/i\\$commit_msg_tracking_issue" "$commit_msg_tmp_file" > "${commit_msg_tmp_file}.new"

    # Apply the updated commit message
    git commit --amend --file="${commit_msg_tmp_file}.new" --date="$(git show --no-patch --format=%cD "$commit_id")" > /dev/null

    # Clean up only the .new file
    rm -f "${commit_msg_tmp_file}.new"
    echo "Commit message for $commit_id updated with: '$commit_msg_tracking_issue'"
}

# Extracts reverted commit hash and Change-Id from commit message with error handling
# Sets global variables reverted_hash and reverted_change_id directly
extract_reverted_commit_info() {

    # Extract reverted commit hash - look for long hex sequence after "This reverts commit"
    reverted_hash=$(grep --ignore-case 'This reverts commit' "$commit_msg_tmp_file" | sed 's/.*This reverts commit \([a-fA-F0-9]\{7,40\}\).*/\1/I')

    if [ -z "$reverted_hash" ]; then
        echo "-E- Could not extract reverted commit hash from commit message."
        while [ -z "$reverted_hash" ]; do
            read -rp "Please enter the reverted commit hash manually: " input_hash
            if git cat-file -e "${input_hash}" 2>/dev/null; then
                reverted_hash="$input_hash"
            else
                echo "-E- '$input_hash' is not a valid commit hash."
            fi
        done
    fi

    # Extract Change-Id from the reverted commit
    reverted_change_id=$(git show "$reverted_hash" 2>/dev/null | grep "Change-Id:" | sed 's/.*Change-Id: *\(I[a-fA-F0-9]\{7,40\}\).*/\1/')

    if [ -z "$reverted_change_id" ]; then
        echo "-E- Could not find Change-Id for reverted commit $reverted_hash."
        while [ -z "$reverted_change_id" ]; do
            read -rp "Please enter the Change-Id manually (must start with 'I'): " input_change_id
            if [[ "$input_change_id" =~ ^I[a-fA-F0-9]{7,40}$ ]]; then
                reverted_change_id="$input_change_id"
            else
                echo "-E- Invalid Change-Id format. Expected format: I followed by 7 to 40 hex digits (e.g. I1234abcd...)."
            fi
        done
    fi
}

# Ensures metadata entry for reverted commit exists (restores if deleted by revert)
ensure_reverted_metadata_entry_exists() {

    # Check if Change-Id existed in previous commit but not in current commit
    local found_in_prev=$(git grep "Change-Id=$reverted_change_id;" HEAD~1 -- metadata/*.csv 2>/dev/null || true)
    local found_in_current=$(git grep "Change-Id=$reverted_change_id;" HEAD -- metadata/*.csv 2>/dev/null || true)

    # If found in previous but not in current, it was deleted by the revert
    if [[ -n "$found_in_prev" && -z "$found_in_current" ]]; then
        # Extract the file path and entry from the previous commit
        local prev_file=$(echo "$found_in_prev" | cut --delimiter=: --fields=2)
        local deleted_entry=$(echo "$found_in_prev" | cut --delimiter=: --fields=3-)

        # Restore entry to the same file (status will be set to ignore later)
        local metadata_file="${WDIR}/$prev_file"
        echo "Metadata entry was deleted in Revert commit. Restoring it."
        echo "$deleted_entry" >> "$metadata_file"
        echo "Re-added line to $metadata_file"

        # Add file to the list if not already present
        local filename=$(basename "$metadata_file")
        if ! echo "$reverted_metadata_files" | grep --quiet "$filename" && [ "$filename" != "$revert_metadata_filename" ]; then
            reverted_metadata_files+=" $metadata_file"$'\n'
        fi
    fi
}

# Updates all metadata entries for reverted commit to have upstream_status=ignore
# Processes all CSV files in metadata/ directory
set_reverted_metadata_status_ignore() {

    for metadata_file in "${WDIR}"/metadata/*.csv; do
        # Check if file exists (in case no .csv files found)
        [ -f "$metadata_file" ] || continue

        # Check if this file contains the Change-Id
        if grep --quiet "Change-Id=$reverted_change_id;" "$metadata_file"; then
            echo "Metadata entry of the reverted commit in $metadata_file was updated with upstream_status=ignore."

            # Update upstream_status to ignore using sed in-place - only for the specific Change-Id line
            sed --in-place "/Change-Id=$reverted_change_id;/s/upstream_status=[^;]*/upstream_status=ignore/" "$metadata_file"

            # Add file to the list if not already present
            local filename=$(basename "$metadata_file")
            if ! echo "$reverted_metadata_files" | grep --quiet "$filename" && [ "$filename" != "$revert_metadata_filename" ]; then
                reverted_metadata_files+=" $metadata_file"$'\n'
            fi
        fi
    done
}

# Checks if a commit is a revert commit by examining its subject line
# Returns 0 if it's a revert commit, 1 if not
is_revert_commit() {
	local commit_id=$1
	local subject=$(git log -1 --format="%s" "$commit_id")

	if echo "$subject" | grep --quiet '^Revert "'; then
		return 0
	fi
	return 1
}

handle_revert_commit() {
    local commit_id=$1
    local revert_metadata_csvfile="$2"
    revert_title=$(git log -1 --oneline "$commit_id")
    revert_metadata_filename=$(basename "$revert_metadata_csvfile")
    commit_msg_tmp_file=$(mktemp)
    commit_msg_tracking_issue=""
    reverted_hash=""
    reverted_change_id=""
    reverted_metadata_files=""

    # Ensure valid usage of --revert-track/-t if it's used, and ask the user for a valid upstream_status value (NA or ignore) if not.
    determine_revert_commit_handling

    # Extract reverted commit hash and Change-Id (do this BEFORE modifying commit message)
    git show --no-patch --format=%B "$commit_id" > "$commit_msg_tmp_file"
    extract_reverted_commit_info

    # Update the Revert commit message with tracking issue (NA tracking issue or ignore tracking issue).
    update_revert_commit_msg_with_tracking_issue

    # Ensure reverted commit metadata entry exists (restore if deleted by revert)
    ensure_reverted_metadata_entry_exists

    # Ensure the reverted commit metadata entry has ignore status
    set_reverted_metadata_status_ignore

    # Clean up temporary file
    rm -f "$commit_msg_tmp_file"
}

# get value of given tag if available in the commit message
get_by_tag()
{
	local cid=$1; shift
	local tag=$1; shift

	echo $(git log -1 $cid | grep -iE -- "${tag}\s*:" | head -1 | cut -d":" -f"2" | sed -r -e 's/^\s//g')
}

get_subject()
{
	local cid=$1; shift

	echo $(git log -1 --format="%s" $cid)
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

get_issue_from_csv()
{
	local line=$1; shift

	echo $(echo "$line" | sed -r -e 's/.*;\s*upstream_issue=\s*//' -e 's/;\s*general.*//')
}

get_general_from_csv()
{
	local line=$1; shift

	echo $(echo "$line" | sed -r -e 's/.*;\s*general=\s*//' -e 's/;.*//')
}

get_line_from_ref()
{
	local uniqID=$1; shift
	local ref_db=$1; shift
	local subject=$1; shift
	local line=""

	if [ "X$changeid_map" != "X" ]; then
		uniqID=$(map_id_new_to_old $uniqID $changeid_map "$subject")
		line=$(grep --no-filename -wr -- "$uniqID" ${ref_db}/*csv 2>/dev/null)
	else
		line=$(grep --no-filename -wr -- "subject=$subject;" ${ref_db}/*csv 2>/dev/null | tail -1)
	fi
	if [ "X$line" == "X" ]; then
		return
	fi
	echo "$line"
}

map_id_new_to_old()
{
	local newid=$1; shift
	local changeid_map=$1; shift
	local subject=$1; shift

	newid=$(echo -e "$newid" | sed -r -e 's/.*=\s*//g')
	local line=$(grep --no-filename -wr -- "$newid" $changeid_map 2>/dev/null)
	local oldid=$(echo "$line" | cut -d':' -f'1')
	if [ "X$oldid" != "X" ]; then
		echo "$oldid"
	else
		local line=$(grep --no-filename -wr -- "$subject" ${ref_db}/*csv 2>/dev/null | tail -1)
		local oldid=$(echo "$line" | cut -d':' -f'1')
		if [ "X$oldid" != "X" ]; then
			echo "$oldid"
		else
			echo "$newid"
		fi
	fi
}

get_feature_from_ref()
{
	local uniqID=$1; shift
	local ref_db=$1; shift
	local subject=$1; shift

	local line=$(get_line_from_ref "$uniqID" "$ref_db" "$subject")
	if [ "X$line" == "X" ]; then
		echo ""
		return
	fi
	get_feature_from_csv "$line"
}

get_upstream_status_from_ref()
{
	local uniqID=$1; shift
	local ref_db=$1; shift
	local subject=$1; shift

	local line=$(get_line_from_ref "$uniqID" "$ref_db" "$subject")
	if [ "X$line" == "X" ]; then
		echo ""
		return
	fi
	local status=$(get_upstream_from_csv "$line")
	if [ "X$status" == "X-1" ]; then
		status=NA
	fi
	echo $status
}

get_upstream_issue_from_ref()
{
	local uniqID=$1; shift
	local ref_db=$1; shift
	local subject=$1; shift

	local line=$(get_line_from_ref "$uniqID" "$ref_db" "$subject")
	if [ "X$line" == "X" ]; then
		echo ""
		return
	fi
	local issue=$(get_issue_from_csv "$line")
	if [ "X$issue" == "X-1" ]; then
		echo ""
		return
	fi
	echo $issue
}

get_general_from_ref()
{
	local uniqID=$1; shift
	local ref_db=$1; shift
	local subject=$1; shift

	local line=$(get_line_from_ref "$uniqID" "$ref_db" "$subject")
	if [ "X$line" == "X" ]; then
		echo ""
		return
	fi
	local tag=$(get_general_from_csv "$line")
	if [ "X$tag" == "X-1" ]; then
		echo ""
		return
	fi
	echo $tag
}

##################################################################
#
# main
#

filter=
if [ "X$base" != "X" ]; then
	filter="${base}.."
fi
if [ "X$num" != "X" ]; then
	filter="-${num}"
fi
if [ "X$filter" == "X" ]; then
	echo "-E- Missing arguments!" >&2
	echo
	usage
	exit 1
fi

if [ "X$ref_db" != "X" ] && ! test -d "$ref_db"; then
	echo "-E- Giving --ref-db does not exist: '$ref_db' !" >&2
	exit 1
fi

commitIDs=$(git log --no-merges --format="%h" $filter | tac)
if [ -z "$commitIDs" ]; then
	echo "-E- Failed to get list of commit IDs." >&2
	exit 1
fi
if [ ! -z "$def_ustatus" ]; then
	case $def_ustatus in
		NA|accepted|in_progress|ignore)
			;; # Valid status
		*)	echo "-E- Valid status is one of the follow options: 'NA'|'rejected'|'accepted'|'in_progress'|'ignore'"
			exit 1
			;;
	esac
fi

if [ "X$def_ustatus" = "Xaccepted" ];then
	if [ "X$general" = "X" ]; then
		echo "-E- -g|--general must be used in case of status accepted"
		exit 1
	fi
else
	if [ ! -z "$general" ]; then
		echo "-E- -g|--general can be used only in case of status accepted"
		exit 1
	fi
fi

echo "Getting info about commits..."
echo ----------------------------------------------------
csvfiles=
for cid in $commitIDs
do
	if [ "X$cid" == "X" ]; then
		continue
	fi
	author=$(git log --format="%aN" $cid| head -1 | sed -e 's/ /_/g')

	# Skip authors who only have commits on old deprecated branches
	if should_skip_author_for_old_branches "$author"; then
		echo "-I- Skipping author '$author' (only has commits on deprecated branches older than mlnx_ofed_5_8)"
		continue
	fi

	changeID=
	subject=
	feature=
	upstream=
	upstream_iss=

	uniqID=
	changeID=$(get_by_tag $cid "change-id")
	if [ -z "$changeID" ]; then
		# for merged commits w/o change ID take the commit ID
		if (git branch -a --contains $cid 2>/dev/null | grep -qEi -- "remote|origin"); then
			uniqID="commit-Id=${cid}"
		else
			echo "-E- Failed to get Change-Id for commit ID: $cid" >&2
			echo "Please add Change-Id and re-run the script." >&2
			exit 1
		fi
	else
		uniqID="Change-Id=${changeID}"
	fi
	if [ -z "$uniqID" ]; then
		echo "-E- Failed to get unique Id for commit ID: $cid" >&2
		exit 1
	fi
	subject=$(get_subject $cid)
	feature=$(get_by_tag $cid "feature")
	upstream=$(get_by_tag $cid "upstream(.*status)")
	upstream_iss=$(get_by_tag $cid "upstream(.*issue)")
	if [ -z "$general" ]
	then
		general=$(get_by_tag $cid "general")
	fi

	# If the commit is a revert commit, present the two possible scenarios
	# and allow the user to choose the appropriate one.
	if is_revert_commit "$cid" && [[ "$no_verify" == 0 && "$no_edit" == 0 ]]; then
		csvfile="${WDIR}/metadata/${author}.csv"
		handle_revert_commit "$cid" "$csvfile"
	fi

	# auto-detect commits that changes only backports, ofed-scripts
	if is_backports_change_only $cid ;then
		feature="backports"
		upstream="ignore"
		upstream_iss=""
	fi
	if is_scripts_change_only $cid ;then
		feature="ofed_scripts"
		upstream="ignore"
		upstream_iss=""
	fi

	if [ "X$upstream" = "Xin_progress" ];then
		if [ -z "$upstream_iss" ]; then
			echo "-i|--upsrteam_issue must be used in case of status in_progress (can be filled later)"
		fi
	else
		upstream_iss=$def_uissue
	fi

	if [ "X$ref_db" != "X" ]; then
		if [ "X$feature" == "X" ]; then
			feature=$(get_feature_from_ref "$uniqID" "$ref_db" "$subject")
		fi
		if [ "X$upstream" == "X" ]; then
			upstream=$(get_upstream_status_from_ref "$uniqID" "$ref_db" "$subject")
		fi
		if [ "X$upstream_iss" == "X" ]; then
			upstream_iss=$(get_upstream_issue_from_ref "$uniqID" "$ref_db" "$subject")
		fi
		general=$(get_general_from_ref "$uniqID" "$ref_db" "$subject")
	fi

	if [ "X$feature" == "X" ]; then
		feature=$def_feature
	fi
	if [ "X$upstream" == "X" ]; then
		upstream=$def_ustatus
	fi

	entry="$uniqID; subject=${subject}; feature=${feature}; upstream_status=${upstream}; upstream_issue=${upstream_iss}; general=${general};"
	if [ "X$ref_db" != "X" ]; then
		general="" #remove for each iteration
	fi
	echo "'$entry' to metadata/${author}.csv"
	csvfile="${WDIR}/metadata/${author}.csv"
	if [ $dry_run -eq 0 ]; then
		mkdir -p $WDIR/metadata
		if [ ! -e $csvfile ]; then
			echo "sep=;" > $csvfile
		fi
		if (grep -q -- "$uniqID" $csvfile); then
			echo "-W- $cid '${subject}' already exists in ${author}.csv , skipping..." >&2
			echo >&2
		else
			echo "$entry" >> $csvfile
			if ! (echo $csvfiles | grep -q -- "$csvfile"); then
				csvfiles="$csvfiles $csvfile"
			fi
		fi
	fi
done

if [ $dry_run -eq 0 ]; then
	if [ ! -z "$csvfiles" ]; then
		if [ $no_edit -eq 0 ]; then
			vim -o $csvfiles
		fi
		echo ----------------------------------------------------
		echo "Done, please amend these files to your last commit:"
		echo "$csvfiles"
		if [ -n "$reverted_metadata_files" ]; then
			echo "$reverted_metadata_files"
		fi
		echo ----------------------------------------------------
		echo
		if [ $no_verify -eq 0 ]; then
			echo "Going to verify content of metadata files..."
			sleep 3
			for ff in $csvfiles
			do
				cmd="$WDIR/devtools/verify_metadata.sh -p $ff"
				echo "Going to run '$cmd'"
				sleep 2
				$cmd
			done
		fi
	else
		echo "-E- no csv files were updated!"
		exit 3
	fi
fi

