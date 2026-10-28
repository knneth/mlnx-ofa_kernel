#!/bin/bash
#
# resolve-kernels.sh - Find the Ubuntu kernels to run the install test against.
#
# Prints a GitHub Actions matrix (JSON) on stdout with one entry per kernel:
#   - the released GA kernel       (linux-headers-generic)
#   - the released HWE kernel      (linux-headers-generic-hwe-<VERSION_ID>)
#   - the same two from -proposed, if -proposed has a newer version
#
# Must run on the Ubuntu release being tested, with -proposed enabled
# (see enable-proposed.sh) and an up to date apt cache.
#

set -euo pipefail

. /etc/os-release

flavours=(
	"GA:linux-headers-generic"
	"HWE:linux-headers-generic-hwe-${VERSION_ID}"
)

# Newest version of package $1 outside (-v) or inside -proposed.
# apt-cache madison lists versions newest first.
newest() {
	apt-cache madison "$1" | { grep $2 -e "-proposed/" || true; } |
		awk -F'|' 'NR == 1 { gsub(/ /, "", $2); print $2 }'
}

# Kernel release a headers meta package version points to,
# e.g. linux-headers-generic=6.8.0-85.85 -> 6.8.0-85-generic
kver_of() {
	apt-cache show "$1=$2" | sed -n 's/^Depends: //p' | tr ',' '\n' |
		{ grep -oE 'linux-headers-[0-9][^ ]*-generic' || true; } |
		sed -n '1s/^linux-headers-//p'
}

entry() {
	jq -cn --arg name "$1" --arg kver "$2" --arg version "$3" --argjson proposed "$4" \
		'{name: $name, kver: $kver, version: $version, proposed: $proposed}'
}

entries=()
for f in "${flavours[@]}"; do
	label=${f%%:*}
	meta=${f#*:}

	released=$(newest "$meta" -v)
	if [ -z "$released" ]; then
		echo "ERROR: no released version of $meta found" >&2
		exit 1
	fi
	kver=$(kver_of "$meta" "$released")
	if [ -z "$kver" ]; then
		echo "ERROR: cannot find kernel version for $meta=$released" >&2
		exit 1
	fi
	echo "$label released: $meta $released -> $kver" >&2
	entries+=("$(entry "$label $kver" "$kver" "$released" false)")

	proposed=$(newest "$meta" "")
	if [ -n "$proposed" ] && dpkg --compare-versions "$proposed" gt "$released"; then
		kver=$(kver_of "$meta" "$proposed")
		if [ -z "$kver" ]; then
			echo "ERROR: cannot find kernel version for $meta=$proposed" >&2
			exit 1
		fi
		echo "$label proposed: $meta $proposed -> $kver" >&2
		entries+=("$(entry "$label $kver (proposed)" "$kver" "$proposed" true)")
	else
		echo "$label proposed: nothing newer than released" >&2
	fi
done

# GA and HWE may point at the same kernel; test each kernel once.
printf '%s\n' "${entries[@]}" | jq -cs '{include: unique_by(.kver)}'
