#!/bin/bash
# Check local containers for the selected deployment topology; optional public URLs probe the edge.
set -euo pipefail

TOPOLOGY="${1:-single-server}"
if [ $# -gt 0 ]; then shift; fi
WITH_DB=false
CADDY_MODE=optional
CADDY=praho_caddy
case "$TOPOLOGY" in
    single-server) REQUIRED=(praho_db praho_platform praho_portal praho_qcluster); CADDY_MODE=required ;;
    platform-only) REQUIRED=(praho_platform praho_qcluster) ;;
    portal-only) REQUIRED=(praho_portal); CADDY=praho_portal_caddy ;;
    container-service) REQUIRED=(praho_platform praho_portal praho_qcluster); CADDY_MODE=none ;;
    *) echo 'Usage: health-check.sh [single-server|platform-only|portal-only|container-service] [--with-db] [--with-caddy|--without-caddy]' >&2; exit 1 ;;
esac
while [ $# -gt 0 ]; do
    case "$1" in
        --with-db) WITH_DB=true ;;
        --with-caddy) CADDY_MODE=required ;;
        --without-caddy) CADDY_MODE=none ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done
if $WITH_DB && [ "$TOPOLOGY" != single-server ]; then REQUIRED+=(praho_db); fi
if ! INVENTORY=$(docker ps -a --format '{{.Names}}'); then
    echo '[FAIL] Cannot read Docker container inventory' >&2
    exit 1
fi
present() { printf '%s\n' "$INVENTORY" | grep -Fxq "$1"; }
if [ "$CADDY_MODE" = required ] || { [ "$CADDY_MODE" = optional ] && present "$CADDY"; }; then
    REQUIRED+=("$CADDY")
fi

check_container() {
    local name="$1" state health status
    if ! present "$name"; then echo "[FAIL] $name: missing"; return 1; fi
    if ! status=$(docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$name"); then
        echo "[FAIL] $name: inspect failed"; return 1
    fi
    read -r state health <<< "$status"
    if [ "$state" != running ]; then echo "[FAIL] $name: ${state:-unknown}"; return 1; fi
    case "$health" in
        healthy) echo "[OK] $name: healthy" ;;
        no-healthcheck)
            case "$name" in
                praho_qcluster) echo "[OK] $name: running (job execution requires a separate queue check)" ;;
                praho_caddy|praho_portal_caddy) echo "[OK] $name: running" ;;
                *) echo "[FAIL] $name: missing healthcheck"; return 1 ;;
            esac ;;
        *) echo "[FAIL] $name: ${health:-unknown}"; return 1 ;;
    esac
}
check_route() {
    if curl --max-time 10 -fsS "$2" > /dev/null; then echo "[OK] $1: responding";
    else echo "[FAIL] $1: not responding"; return 1; fi
}
EXIT_CODE=0
for container in "${REQUIRED[@]}"; do check_container "$container" || EXIT_CODE=1; done
if [ -n "${PLATFORM_URL:-}" ]; then check_route Platform "${PLATFORM_URL}/api/users/health/" || EXIT_CODE=1; fi
if [ -n "${PORTAL_URL:-}" ]; then check_route Portal "${PORTAL_URL}/status/" || EXIT_CODE=1; fi
exit "$EXIT_CODE"
