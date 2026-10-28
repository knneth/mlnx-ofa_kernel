#!/bin/bash
#
# skip-passed.sh - Drop kernels this commit has already passed on.
#
# Reads a matrix from resolve-kernels.sh on stdin and prints it on stdout
# with the entries removed whose install test already passed for the same
# commit and kernel package version. Each remaining entry gets a "marker":
# the name of the artifact the install job uploads when it passes.
#
# Set FORCE=true to keep all entries. Needs GITHUB_TOKEN with actions:read.
#

set -euo pipefail

passed() {
	curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" \
		"$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/actions/artifacts?name=$(jq -rn --arg n "$1" '$n | @uri')" |
		jq -e '[.artifacts[] | select(.expired | not)] | length > 0' > /dev/null
}

matrix='{"include": []}'
while read -r e; do
	marker=$(jq -r --arg sha "$GITHUB_SHA" '"pass-\($sha)-\(.kver)-\(.version)"' <<< "$e")
	if [ "${FORCE:-false}" != true ] && passed "$marker"; then
		echo "$(jq -r .name <<< "$e"): already passed on $GITHUB_SHA, skipping" >&2
		continue
	fi
	matrix=$(jq -c --argjson e "$e" --arg m "$marker" '.include += [$e + {marker: $m}]' <<< "$matrix")
done < <(jq -c '.include[]')

echo "$matrix"
