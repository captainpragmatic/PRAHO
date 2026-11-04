#!/usr/bin/env bash
# Managed node deployment acceptance requires the owned Ubuntu provider VM.
# Docker's Debian contract nodes remain useful for API/mail behavior, while
# filesystem quotas, reboot persistence and the managed baseline use this leg.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${NATIVE_VM_MANIFEST:?Set NATIVE_VM_MANIFEST to the private disposable Ubuntu VM manifest}"
: "${NATIVE_DNS_ZONE:?Set NATIVE_DNS_ZONE to the approved disposable lab DNS zone}"
: "${NATIVE_S3_MANIFEST:?Set NATIVE_S3_MANIFEST to the private verified storage fixture manifest}"
: "${PRAHO_NATIVE_S3_ENDPOINT_URL:?Load the exact owned storage fixture environment}"
: "${PRAHO_NATIVE_S3_BUCKET:?Load the exact owned storage fixture bucket}"
: "${PRAHO_NATIVE_S3_ACCESS_KEY_ID:?Load the private owned storage fixture identity}"
: "${PRAHO_NATIVE_S3_SECRET_ACCESS_KEY:?Load the private owned storage fixture identity}"

case "${NATIVE_VM_MANIFEST}" in
    /*) ;;
    *) NATIVE_VM_MANIFEST="${PWD}/${NATIVE_VM_MANIFEST}" ;;
esac
case "${NATIVE_S3_MANIFEST}" in
    /*) ;;
    *) NATIVE_S3_MANIFEST="${PWD}/${NATIVE_S3_MANIFEST}" ;;
esac
export NATIVE_VM_MANIFEST NATIVE_DNS_ZONE NATIVE_S3_MANIFEST

# Require completed public deployment/native evidence before the composite gate:
# supplied intent alone never authorizes this full run to provision a new VM.
# Raw registration-resume is a separate run/database and never supplies fresh proof.
# Separate Make invocations preserve admission order even with inherited parallel MAKEFLAGS.
for phase in test-virtualmin-native-fresh-deployment native-vm-migrate native-vm-fresh-deploy native-vm-register test-virtualmin-quotas \
    test-virtualmin-native-fresh-deployment native-s3-verify test-virtualmin-native-workflow; do
    make -C "${REPO_ROOT}" --no-print-directory "${phase}"
done
