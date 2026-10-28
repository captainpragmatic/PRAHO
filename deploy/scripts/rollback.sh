#!/bin/bash
# =============================================================================
# PRAHO - Rollback Script
# =============================================================================
# Rolls back to a previous version or database state
#
# Usage:
#   ./rollback.sh version <tag>    # Roll back to specific version
#   ./rollback.sh database         # Restore latest database backup
#   ./rollback.sh full <tag> --backup PATH [--topology single-server|platform-only]       # Version rollback + database restore
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
    echo "  full <tag> --backup PATH  Restore an explicit compatible pair with the target image"
    echo ""
    echo "Examples:"
    echo "  $0 version v1.2.3"
    echo "  $0 database"
    echo "  $0 full v1.2.0 --backup /private/backups/praho_backup_SELECTED.sql.gz"
    exit 1
}

rollback_version() {
    local VERSION="$1"

    # Validate version format to prevent sed injection
    if [[ ! "$VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
        log_error "Invalid version format: ${VERSION} (expected vX.Y.Z or X.Y.Z)"
        exit 1
    fi
    # Before the prompt, the backup and any pull: an incomplete production file would only
    # replace the running version with one that cannot start.
    praho_load_env
    praho_require_production_keys
    # Rollback starts containers, so a missing variable is refused rather than given a placeholder.
    praho_require_stack_vars single-server

    log_info "Rolling back to version: ${VERSION}"

    echo -e "${YELLOW}WARNING: This will restart services with version ${VERSION}${NC}"
    read -r -p "Continue? (yes/no): " CONFIRM

    if [ "$CONFIRM" != "yes" ]; then
        log_info "Rollback cancelled"
        exit 0
    fi

    # Create backup before rollback
    log_info "Creating pre-rollback backup..."
    "${SCRIPT_DIR}/backup.sh" || log_warn "Backup failed"

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
    "${SCRIPT_DIR}/restore-platform.sh" --latest "${ENV_ARGS[@]}"
}

rollback_full() {
    local VERSION="$1" backup="" topology=single-server argument names server_version major role reference expected digest
    local portal_flag=()
    shift
    [[ "$VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]] || praho_die 'Invalid version format'
    praho_load_env
    praho_require_production_keys
    while [ $# -gt 0 ]; do
        argument="$1"
        case "$argument" in
            --backup) [ $# -ge 2 ] || praho_die '--backup needs a path'; backup="$2"; shift 2 ;;
            --topology) [ $# -ge 2 ] || praho_die '--topology needs a value'; topology="$2"; shift 2 ;;
            *) praho_die "Unknown full rollback option: $argument" ;;
        esac
    done
    [ -n "$backup" ] || praho_die 'Full rollback requires --backup PATH and its media/metadata companions; --latest is not a compatibility decision'
    case "$topology" in single-server) portal_flag=(--portal) ;; platform-only) ;; *) praho_die 'Full rollback topology must be single-server or platform-only' ;; esac
    praho_require_stack_vars "$topology"
    if ! names=$(docker ps -a --format '{{.Names}}'); then praho_die 'Cannot determine local topology'; fi
    printf '%s\n' "$names" | grep -Fxq praho_platform || praho_die 'Local Platform container required'
    printf '%s\n' "$names" | grep -Fxq praho_db || praho_die 'Full rollback requires the bundled local database'
    FULL_SERVICES=(platform)
    FULL_NAMES=(praho_platform)
    if [ "$topology" = single-server ]; then
        printf '%s\n' "$names" | grep -Fxq praho_portal || praho_die 'Topology mismatch: local Portal is missing'
        FULL_SERVICES+=(portal); FULL_NAMES+=(praho_portal)
    elif printf '%s\n' "$names" | grep -Fxq praho_portal; then
        praho_die 'Topology mismatch: a local Portal exists'
    fi
    if printf '%s\n' "$names" | grep -Fxq praho_qcluster; then FULL_SERVICES+=(qcluster); FULL_NAMES+=(praho_qcluster); fi
    if [ ! -f "$backup" ]; then backup="${BACKUP_DIR:-$PROJECT_ROOT/backups}/$backup"; fi
    FULL_STAGE=$(mktemp -d "${TMPDIR:-/tmp}/praho-full-rollback.XXXXXX")
    trap 'if [ -n "${FULL_STAGE:-}" ]; then rm -rf -- "$FULL_STAGE"; fi' EXIT
    # Preserve the explicit pair and metadata before any retention or downtime.
    cp -- "$backup" "${backup%.sql.gz}.media.tar.gz" "${backup%.sql.gz}.metadata.json" "$FULL_STAGE/"
    backup="$FULL_STAGE/$(basename "$backup")"
    server_version=$(docker exec praho_db psql -U praho -d praho -Atc 'SHOW server_version_num')
    [[ "$server_version" =~ ^[0-9]+$ ]] && [ "$server_version" -ge 100000 ] || praho_die 'Cannot determine database major'
    major=$((server_version / 10000))
    python3 "$SCRIPT_DIR/backup_manifest.py" validate "$backup" --database-major "$major" ${portal_flag[@]+"${portal_flag[@]}"} > "$FULL_STAGE/expected"
    "$SCRIPT_DIR/restore-platform.sh" "$backup" --check "${ENV_ARGS[@]}"
    # Only image references leave the parser; Compose's secret-bearing environment stays in-process.
    VERSION="$VERSION" praho_compose "$topology" config --format json |
        python3 "$SCRIPT_DIR/backup_manifest.py" images ${portal_flag[@]+"${portal_flag[@]}"} > "$FULL_STAGE/images"
    while IFS='=' read -r role reference; do
        expected=$(awk -F= -v role="$role" '$1 == role {print $2}' "$FULL_STAGE/expected")
        if ! digest=$(docker image inspect --format '{{.Id}}' "$reference" 2>/dev/null) || [ "$digest" != "$expected" ]; then
            docker pull "$reference" || praho_die 'Target image unavailable; applications and data unchanged'
            digest=$(docker image inspect --format '{{.Id}}' "$reference")
        fi
        [ "$digest" = "$expected" ] || praho_die 'Target image does not match the backup source; applications and data unchanged'
    done < "$FULL_STAGE/images"
    read -r -p "Restore the explicit backup and start ${VERSION}? (yes/no): " CONFIRM
    if [ "$CONFIRM" != yes ]; then log_info 'Rollback cancelled'; return 0; fi
    # Restore never starts the current entrypoint: the old image is selected before any application starts.
    printf 'yes\n' | "$SCRIPT_DIR/restore-platform.sh" "$backup" --leave-stopped "${ENV_ARGS[@]}"
    if ! VERSION="$VERSION" praho_compose "$topology" up -d --no-build --no-deps --wait --wait-timeout "$WAIT_TIMEOUT" "${FULL_SERVICES[@]}"; then
        docker stop "${FULL_NAMES[@]}" || log_error 'Could not hold every application offline; operator intervention required'
        praho_die 'Target startup failed; recover from the safety backup before restarting applications'
    fi
    log_success "Full rollback to ${VERSION} completed successfully"
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
        FULL_VERSION="$2"
        shift 2
        rollback_full "$FULL_VERSION" "$@"
        ;;
    *)
        log_error "Unknown rollback type: $1"
        usage
        ;;
esac
