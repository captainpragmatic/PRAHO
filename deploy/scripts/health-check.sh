#!/bin/bash
# =============================================================================
# PRAHO - Health Check Script
# =============================================================================
# Checks the health of all PRAHO services

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# The stacks publish no application ports (only Caddy's 80/443), so container health is the
# check. Set PLATFORM_URL / PORTAL_URL (e.g. https://platform.example.com) to also probe the
# public routes through Caddy.
PLATFORM_URL="${PLATFORM_URL:-}"
PORTAL_URL="${PORTAL_URL:-}"

check_service() {
    local NAME=$1
    local URL=$2

    if curl -sf "${URL}" > /dev/null 2>&1; then
        echo -e "${GREEN}[OK]${NC} ${NAME} is healthy"
        return 0
    else
        echo -e "${RED}[FAIL]${NC} ${NAME} is not responding"
        return 1
    fi
}

check_container() {
    local NAME=$1

    if docker ps --format '{{.Names}}' | grep -q "^${NAME}$"; then
        local STATUS
        # Caddy has no healthcheck: running is all it can report.
        STATUS=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$NAME" 2>/dev/null || echo "unknown")
        case $STATUS in
            healthy)
                echo -e "${GREEN}[OK]${NC} Container ${NAME}: healthy"
                return 0
                ;;
            no-healthcheck)
                # Only Caddy ships without one; any other PRAHO container without it is misconfigured.
                if [ "$NAME" = praho_caddy ]; then
                    echo -e "${GREEN}[OK]${NC} Container ${NAME}: running (no healthcheck)"
                    return 0
                fi
                echo -e "${RED}[FAIL]${NC} Container ${NAME}: running without its healthcheck"
                return 1
                ;;
            unhealthy)
                echo -e "${RED}[FAIL]${NC} Container ${NAME}: unhealthy"
                return 1
                ;;
            *)
                echo -e "${YELLOW}[WARN]${NC} Container ${NAME}: ${STATUS}"
                return 0
                ;;
        esac
    else
        echo -e "${RED}[FAIL]${NC} Container ${NAME}: not running"
        return 1
    fi
}

echo "================================"
echo "PRAHO Health Check"
echo "================================"
echo ""

EXIT_CODE=0

echo "Containers:"
check_container "praho_db" || EXIT_CODE=1
check_container "praho_platform" || EXIT_CODE=1
check_container "praho_portal" || EXIT_CODE=1
check_container "praho_caddy" || EXIT_CODE=1

if [ -n "$PLATFORM_URL" ] || [ -n "$PORTAL_URL" ]; then
    echo ""
    echo "Public routes:"
    if [ -n "$PLATFORM_URL" ]; then
        check_service "Platform" "${PLATFORM_URL}/api/users/health/" || EXIT_CODE=1
    fi
    if [ -n "$PORTAL_URL" ]; then
        check_service "Portal" "${PORTAL_URL}/status/" || EXIT_CODE=1
    fi
fi

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}All services are healthy!${NC}"
else
    echo -e "${RED}Some services are not healthy.${NC}"
fi

exit $EXIT_CODE
