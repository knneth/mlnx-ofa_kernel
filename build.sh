#!/bin/bash
#
# build.sh - Configure and build MLNX OFED kernel modules.
#
# By default (no arguments):
#   ofed_scripts/configure -j<nproc> --all --without-memtrack
#   make -j<nproc>
#
# Any arguments are passed directly to ofed_scripts/configure,
# replacing the default module-selection flags (--all --without-memtrack).
# The -j parallelism flag is always injected unless you supply your own.
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIGURE="${SCRIPT_DIR}/ofed_scripts/configure"

if [ ! -x "${CONFIGURE}" ]; then
    echo "ERROR: cannot find ${CONFIGURE}" >&2
    exit 1
fi

# Use all available CPUs; override with -j or --with-njobs
NJOBS=$(nproc)

# Default configure flags applied when no arguments are given
DEFAULT_CONFIGURE_ARGS=(--all --without-memtrack)

# Exit codes
E_CONFIGURE=1
E_BUILD=2

usage() {
    cat << EOF
Usage: $(basename "$0") [CONFIGURE-OPTIONS]

Configure and build MLNX OFED kernel modules.

When called with no options, the following defaults are used:
  -j${NJOBS} --all --without-memtrack

Any CONFIGURE-OPTIONS given replace the default module-selection flags
(--all --without-memtrack) and are passed directly to ofed_scripts/configure.
The -j parallelism flag is always set to nproc (${NJOBS}) unless you
supply your own -j or --with-njobs.

EXAMPLES
  # Default build: all modules, memtrack disabled (${NJOBS} jobs)
  $(basename "$0")

  # All modules with memtrack enabled (omit --without-memtrack)
  $(basename "$0") --all

  # Override job count
  $(basename "$0") -j4 --all --without-memtrack

  # All modules, no storage drivers (NVMe-oF, SRP, iSER, iSERT, NFS/RDMA)
  $(basename "$0") --all --without-memtrack --without-nvmf_host-mod --without-nvmf_target-mod --without-srp-mod --without-iser-mod --without-isert-mod --without-nfsrdma-mod

  # Select only mlx5 and IPoIB modules
  $(basename "$0") --with-core-mod --with-mlx5-mod --with-ipoib-mod

EXIT CODES
  0   Build succeeded
  ${E_CONFIGURE}   Configure step failed
  ${E_BUILD}   Build (make) step failed

CONFIGURE OPTIONS
  Run 'ofed_scripts/configure --help' for the full list of module flags.

EOF
}

# Handle --help / -h before anything else
for arg in "$@"; do
    case "$arg" in
        -h|--help)
            usage
            exit 0
            ;;
    esac
done

# Detect whether the caller already supplied a -j / --with-njobs flag
has_jobs=0
for arg in "$@"; do
    case "$arg" in
        -j[0-9]*|-j|--with-njobs|--with-njobs=*)
            has_jobs=1
            break
            ;;
    esac
done

# Build the final configure argument list
configure_args=()

if [ "${has_jobs}" -eq 0 ]; then
    configure_args+=("-j${NJOBS}")
fi

if [ "$#" -eq 0 ]; then
    # No user arguments: apply defaults
    configure_args+=("${DEFAULT_CONFIGURE_ARGS[@]}")
else
    # User arguments override the default module-selection flags
    configure_args+=("$@")
fi

# ── Configure ────────────────────────────────────────────────────────────────

echo "========================================================"
echo " MLNX OFED build"
echo "========================================================"
echo " Configure : ${CONFIGURE}"
echo " Arguments : ${configure_args[*]}"
echo " Make jobs : ${NJOBS}"
echo "========================================================"
echo

# ofed_scripts/configure does `cd $(dirname $0)` internally and then constructs
# paths as ${CWD}/ofed_scripts/....  If invoked directly as ofed_scripts/configure,
# dirname resolves to ofed_scripts/ and every subsequent path is doubled.
# Fix: place a temporary symlink at the repo root so dirname $0 == repo root.
_configure_link="${SCRIPT_DIR}/.configure.$$"
ln -sf "${CONFIGURE}" "${_configure_link}"
trap 'rm -f "${_configure_link}"' EXIT

"${_configure_link}" "${configure_args[@]}"
configure_rc=$?
rm -f "${_configure_link}"
trap - EXIT

if [ "${configure_rc}" -ne 0 ]; then
    echo
    echo "ERROR: configure step failed." >&2
    exit ${E_CONFIGURE}
fi

# ── Build ────────────────────────────────────────────────────────────────────

echo
echo "========================================================"
echo " Running: make -j${NJOBS}"
echo "========================================================"
echo

if ! make -j"${NJOBS}" -C "${SCRIPT_DIR}"; then
    echo
    echo "ERROR: build step failed." >&2
    exit ${E_BUILD}
fi

echo
echo "========================================================"
echo " Build completed successfully."
echo "========================================================"
exit 0
