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
#
# Add --env staging or --env-file PATH to use an env file other than .env.prod (see lib/compose.sh).
# The tag applies to this run only; the env file is never edited.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$DEPLOY_DIR")"
# shellcheck source=SCRIPTDIR/lib/compose.sh
source "${SCRIPT_DIR}/lib/compose.sh"
# Outlasts the platform healthcheck's 600s start period plus its failed-check retries.
WAIT_TIMEOUT=900

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
    echo "Usage: $0 <type> [--env prod|staging | --env-file PATH]"
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

    # Validate version format to prevent sed injection
    if [[ ! "$VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
        log_error "Invalid version format: ${VERSION} (expected vX.Y.Z or X.Y.Z)"
        exit 1
    fi

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

    praho_load_env
    # A shell variable beats the env file in Compose interpolation, so VERSION picks the image tag
    # for these calls only. Pull first so the images are local before anything is replaced; a tag
    # built on this host (no registry) is used as is, and a tag found nowhere fails `up`. Only the
    # application images: a newer postgres or caddy image would recreate those containers too.
    log_info "Pulling version ${VERSION}..."
    VERSION="$VERSION" praho_compose single-server pull --ignore-pull-failures platform portal

    log_info "Starting version ${VERSION} and waiting for health..."
    if VERSION="$VERSION" praho_compose single-server up -d --no-build --wait --wait-timeout "$WAIT_TIMEOUT"; then
        log_success "Rollback to ${VERSION} completed successfully!"
    else
        log_error "Services are not healthy. Inspect: ${SCRIPT_DIR}/deploy.sh single-server --logs"
        exit 1
    fi
}

rollback_database() {
    log_info "Rolling back database to latest backup..."
    "${SCRIPT_DIR}/restore.sh" --latest "${ENV_ARGS[@]}"
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

praho_parse_env_args "$@"
set -- ${PRAHO_ARGS[@]+"${PRAHO_ARGS[@]}"}
if [ -n "$PRAHO_ENV_PATH" ]; then
    ENV_ARGS=(--env-file "$PRAHO_ENV_PATH")
else
    ENV_ARGS=(--env "$PRAHO_ENV_NAME")
fi

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
