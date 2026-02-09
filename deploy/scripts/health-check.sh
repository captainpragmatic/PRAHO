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

PLATFORM_URL="${PLATFORM_URL:-http://localhost:8700}"
PORTAL_URL="${PORTAL_URL:-http://localhost:8701}"

check_service() {
    local NAME=$1
    local URL=$2

    if curl -sf "${URL}/health/" > /dev/null 2>&1; then
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
        local STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$NAME" 2>/dev/null || echo "unknown")
        case $STATUS in
            healthy)
                echo -e "${GREEN}[OK]${NC} Container ${NAME}: healthy"
                return 0
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

echo ""
echo "Services:"
check_service "Platform" "$PLATFORM_URL" || EXIT_CODE=1
check_service "Portal" "$PORTAL_URL" || EXIT_CODE=1

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}All services are healthy!${NC}"
else
    echo -e "${RED}Some services are not healthy.${NC}"
fi

exit $EXIT_CODE
