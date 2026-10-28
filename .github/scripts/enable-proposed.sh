#!/bin/bash
#
# enable-proposed.sh - Add the <series>-proposed pocket to apt on Ubuntu.
#
# The pocket is pinned low so that nothing is upgraded from it implicitly;
# packages are only taken from -proposed when requested by exact name/version.
#

set -euo pipefail

. /etc/os-release

# Reuse the configured mirror (archive.ubuntu.com, or ports.ubuntu.com on
# architectures other than amd64/i386).
uri=$(sed -n 's/^URIs: *//p' /etc/apt/sources.list.d/ubuntu.sources | head -n1)

cat > /etc/apt/sources.list.d/proposed.sources << EOF
Types: deb
URIs: ${uri}
Suites: ${VERSION_CODENAME}-proposed
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF

cat > /etc/apt/preferences.d/proposed-pin << EOF
Package: *
Pin: release a=${VERSION_CODENAME}-proposed
Pin-Priority: 100
EOF
