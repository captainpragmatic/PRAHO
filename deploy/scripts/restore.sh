#!/bin/bash
# =============================================================================
# PRAHO - Database and Media Restore Script
# =============================================================================
# Restores the database from a backup file, and the media archive backup.sh wrote next to it
#
# Usage:
#   ./restore.sh                           # Interactive - choose from list
#   ./restore.sh <backup_file>             # Restore specific file
#   ./restore.sh --latest                  # Restore latest backup
#
# Add --env staging or --env-file PATH to use an env file other than .env.prod (see lib/compose.sh).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$DEPLOY_DIR")"
BACKUP_DIR="${BACKUP_DIR:-${PROJECT_ROOT}/backups}"
# shellcheck source=SCRIPTDIR/lib/compose.sh
source "${SCRIPT_DIR}/lib/compose.sh"
# Outlasts the platform healthcheck's 600s start period plus its failed-check retries.
WAIT_TIMEOUT=900
# MEDIA_ROOT inside the platform container: the media_files volume (see backup.sh).
MEDIA_CONTAINER="${MEDIA_CONTAINER:-praho_platform}"
MEDIA_PATH="${MEDIA_PATH:-/app/media}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "[INFO] $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# The stacks publish no application ports, so health comes from each container's healthcheck.
wait_healthy() {
    local name status deadline=$((SECONDS + WAIT_TIMEOUT))
    for name in "$@"; do
        while true; do
            status="$(docker inspect --format '{{.State.Health.Status}}' "$name" 2>/dev/null || echo missing)"
            [ "$status" = healthy ] && break
            if [ "$status" = unhealthy ] || [ "$SECONDS" -ge "$deadline" ]; then
                log_warn "${name} is ${status}. Inspect: docker logs ${name}"
                return 1
            fi
            sleep 5
        done
    done
}

get_latest_backup() {
    ls -t "${BACKUP_DIR}"/praho_backup_*.sql.gz 2>/dev/null | head -n1
}

# Everything but the chosen path goes to stderr: the caller captures stdout as the file to restore.
list_and_select_backup() {
    local BACKUPS=($(ls -t "${BACKUP_DIR}"/praho_backup_*.sql.gz 2>/dev/null))

    if [ ${#BACKUPS[@]} -eq 0 ]; then
        log_error "No backups found in ${BACKUP_DIR}" >&2
        exit 1
    fi

    {
        echo "Available backups:"
        echo ""
        for i in "${!BACKUPS[@]}"; do
            local SIZE=$(du -h "${BACKUPS[$i]}" | cut -f1)
            local DATE=$(basename "${BACKUPS[$i]}" .sql.gz)
            DATE="${DATE#praho_backup_}"
            # YYYYMMDD_HHMMSS, without the process id that newer names end in.
            echo "  $((i+1))) ${DATE:0:15} (${SIZE})"
        done
        echo ""
    } >&2

    read -p "Select backup number (1-${#BACKUPS[@]}): " SELECTION

    if [[ ! "$SELECTION" =~ ^[0-9]+$ ]] || [ "$SELECTION" -lt 1 ] || [ "$SELECTION" -gt ${#BACKUPS[@]} ]; then
        log_error "Invalid selection" >&2
        exit 1
    fi

    echo "${BACKUPS[$((SELECTION-1))]}"
}

# The archive holds the media directory itself, so it is unpacked into its parent. Files the backup
# does not hold are kept: nothing is deleted. docker cp writes into a stopped container's volume.
restore_media() {
    local MEDIA_FILE="${1%.sql.gz}.media.tar.gz"
    if [ -f "$MEDIA_FILE" ]; then
        log_info "Restoring media from ${MEDIA_FILE}..."
        gunzip -c "$MEDIA_FILE" | docker cp - "${MEDIA_CONTAINER}:$(dirname "$MEDIA_PATH")"
    else
        log_warn "No media archive for this backup; the media was left as it is"
    fi
}

restore_backup() {
    local BACKUP_FILE="$1"

    if [ ! -f "$BACKUP_FILE" ]; then
        # Try with backup dir prefix
        if [ -f "${BACKUP_DIR}/${BACKUP_FILE}" ]; then
            BACKUP_FILE="${BACKUP_DIR}/${BACKUP_FILE}"
        else
            log_error "Backup file not found: ${BACKUP_FILE}"
            exit 1
        fi
    fi

    log_info "Restore file: ${BACKUP_FILE}"
    echo ""
    echo -e "${RED}WARNING: This will OVERWRITE the current database!${NC}"
    read -p "Are you sure? Type 'yes' to confirm: " CONFIRM

    if [ "$CONFIRM" != "yes" ]; then
        log_info "Restore cancelled"
        exit 0
    fi

    # Create pre-restore backup
    log_info "Creating pre-restore backup..."
    "${SCRIPT_DIR}/backup.sh" || log_warn "Pre-restore backup failed"

    # Stop application services
    log_info "Stopping services..."
    cd "$PROJECT_ROOT"
    docker stop praho_platform praho_portal 2>/dev/null || true

    # Drop and recreate database
    log_info "Preparing database..."
    docker exec praho_db psql -U praho -d praho -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO praho; GRANT ALL ON SCHEMA public TO PUBLIC;"

    # Restore
    log_info "Restoring database..."
    gunzip -c "${BACKUP_FILE}" | docker exec -i praho_db psql -U praho praho

    restore_media "${BACKUP_FILE}"

    # Restart services
    log_info "Starting services and waiting for health..."
    docker start praho_platform praho_portal 2>/dev/null || \
        praho_compose single-server up -d --wait --wait-timeout "$WAIT_TIMEOUT" || true

    if wait_healthy praho_platform praho_portal; then
        log_success "Restore completed successfully!"
    else
        # The data is restored, but the services did not come back; callers (rollback.sh) must know.
        log_error "The database was restored, but the services did not become healthy."
        exit 1
    fi
}

praho_parse_env_args "$@"
set -- ${PRAHO_ARGS[@]+"${PRAHO_ARGS[@]}"}
# Resolve and check the env file before anything is dropped: the restart may need it, and a
# production file without its keys could not start the platform again.
praho_load_env
praho_require_production_keys

case "${1:-}" in
    --latest)
        LATEST=$(get_latest_backup)
        if [ -z "$LATEST" ]; then
            log_error "No backups found"
            exit 1
        fi
        restore_backup "$LATEST"
        ;;
    "")
        SELECTED=$(list_and_select_backup)
        restore_backup "$SELECTED"
        ;;
    *)
        restore_backup "$1"
        ;;
esac
