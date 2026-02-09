#!/bin/bash
# =============================================================================
# PRAHO - Rollback Script
# =============================================================================
# Rolls back to a previous version or database state
#
# Usage:
#   ./rollback.sh version <tag>    # Roll back to specific version
#   ./rollback.sh database         # Restore latest database backup
#   ./rollback.sh full <tag>       # Version rollback + database restore

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$DEPLOY_DIR")"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "[INFO] $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    echo "PRAHO Rollback Script"
    echo ""
    echo "Usage: $0 <type> [options]"
    echo ""
    echo "Types:"
    echo "  version <tag>    Roll back to specific image version"
    echo "  database         Restore latest database backup"
    echo "  full <tag>       Version rollback + database restore"
    echo ""
    echo "Examples:"
    echo "  $0 version v1.2.3"
    echo "  $0 database"
    echo "  $0 full v1.2.0"
    exit 1
}

rollback_version() {
    local VERSION="$1"

    log_info "Rolling back to version: ${VERSION}"

    echo -e "${YELLOW}WARNING: This will restart services with version ${VERSION}${NC}"
    read -p "Continue? (yes/no): " CONFIRM

    if [ "$CONFIRM" != "yes" ]; then
        log_info "Rollback cancelled"
        exit 0
    fi

    # Create backup before rollback
    log_info "Creating pre-rollback backup..."
    "${SCRIPT_DIR}/backup.sh" || log_warn "Backup failed"

    cd "$PROJECT_ROOT"

    # Update .env with new version
    if grep -q "^VERSION=" .env 2>/dev/null; then
        sed -i "s/^VERSION=.*/VERSION=${VERSION}/" .env
    else
        echo "VERSION=${VERSION}" >> .env
    fi

    # Pull and restart
    log_info "Stopping services..."
    docker compose -f deploy/docker-compose.single-server.yml down

    log_info "Starting services with version ${VERSION}..."
    export VERSION="${VERSION}"
    docker compose -f deploy/docker-compose.single-server.yml up -d

    log_info "Waiting for services..."
    sleep 30

    # Verify
    if curl -sf http://localhost:8700/health/ > /dev/null; then
        log_success "Rollback to ${VERSION} completed successfully!"
    else
        log_error "Services are not healthy. Check logs: docker compose logs"
        exit 1
    fi
}

rollback_database() {
    log_info "Rolling back database to latest backup..."
    "${SCRIPT_DIR}/restore.sh" --latest
}

rollback_full() {
    local VERSION="$1"

    log_info "Performing full rollback to version ${VERSION}"
    echo -e "${RED}WARNING: This will roll back both code AND database!${NC}"
    read -p "Are you absolutely sure? Type 'yes' to confirm: " CONFIRM

    if [ "$CONFIRM" != "yes" ]; then
        log_info "Rollback cancelled"
        exit 0
    fi

    rollback_database
    rollback_version "$VERSION"
}

if [ $# -eq 0 ]; then
    usage
fi

case "$1" in
    version)
        [ -z "${2:-}" ] && { log_error "Version tag required"; usage; }
        rollback_version "$2"
        ;;
    database)
        rollback_database
        ;;
    full)
        [ -z "${2:-}" ] && { log_error "Version tag required"; usage; }
        rollback_full "$2"
        ;;
    *)
        log_error "Unknown rollback type: $1"
        usage
        ;;
esac
