#!/usr/bin/env bash
# Managed node deployment acceptance requires the owned Ubuntu provider VM.
# Docker's Debian contract nodes remain useful for API/mail behavior, while
# filesystem quotas, reboot persistence and the managed baseline use this leg.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${NATIVE_VM_MANIFEST:?Set NATIVE_VM_MANIFEST to the private disposable Ubuntu VM manifest}"
: "${NATIVE_DNS_ZONE:?Set NATIVE_DNS_ZONE to the approved disposable lab DNS zone}"

case "${NATIVE_VM_MANIFEST}" in
    /*) ;;
    *) NATIVE_VM_MANIFEST="${PWD}/${NATIVE_VM_MANIFEST}" ;;
esac
export NATIVE_VM_MANIFEST NATIVE_DNS_ZONE

make -C "${REPO_ROOT}" --no-print-directory \
    native-vm-prepare native-vm-register test-virtualmin-quotas test-virtualmin-native-workflow \
    test-virtualmin-native-fresh-deployment
