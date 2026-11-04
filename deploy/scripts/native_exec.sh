#!/usr/bin/env bash
# Load credentials on the target; Ansible environment values enter SSH argv.
set -euo pipefail
if [[ $# -lt 3 ]]; then
    printf '%s\n' 'Usage: native_exec.sh ENV_FILE [--console] [--https-api-probe] [--loopback] -- COMMAND ...' >&2
    exit 2
fi
native_environment=$1
shift
set -a
# The controller serializes this private file with native_systemd_env.+# shellcheck disable=SC1090
source "$native_environment"
set +a
export NATIVE_PROBE_LOOPBACK=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --console) export PORTAL_LOG_DIR='' ;;
        --https-api-probe) export PLATFORM_API_BASE_URL="https://${PLATFORM_DOMAIN:?}/api" ;;
        --loopback) export NATIVE_PROBE_LOOPBACK=true ;;
        --) shift; break ;;
        *) printf '%s\n' 'Unknown native execution option' >&2; exit 2 ;;
    esac
    shift
done
[[ $# -gt 0 ]] || exit 2
exec "$@"
