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
RESTORE_TMP_DIR=""
trap 'if [ -n "$RESTORE_TMP_DIR" ]; then rm -rf "$RESTORE_TMP_DIR"; fi' EXIT

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
# -a preserves the ownership recorded in the archive.
restore_media() {
    local MEDIA_FILE="${1%.sql.gz}.media.tar.gz"
    if [ -f "$MEDIA_FILE" ]; then
        log_info "Restoring media from ${MEDIA_FILE}..."
        gunzip -c "$MEDIA_FILE" | docker cp -a - "${MEDIA_CONTAINER}:$(dirname "$MEDIA_PATH")"
    else
        log_warn "No media archive for this backup; the media was left as it is"
    fi
}

# Check a private copy: the safety backup's retention must not delete an old selected backup,
# and the bytes checked here must be the ones restored. This checks the pg_dump envelope and
# compression, not whether every SQL statement can execute against the target PostgreSQL.
stage_and_check_archives() {
    local source="$1" media="${1%.sql.gz}.media.tar.gz"
    RESTORE_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/praho-restore.XXXXXX")"
    if [ ! -r "$source" ] || ! cp "$source" "$RESTORE_TMP_DIR/backup.sql.gz"; then
        log_error "Cannot read the database backup; nothing was restored"
        exit 1
    fi
    if ! gzip -t "$RESTORE_TMP_DIR/backup.sql.gz" 2>/dev/null ||
        ! gunzip -c "$RESTORE_TMP_DIR/backup.sql.gz" | LC_ALL=C awk '
            /^-- PostgreSQL database dump$/ { header = 1; next }
            /^-- PostgreSQL database dump complete$/ { complete = 1; next }
            header && !/^--/ && /[^[:space:]]/ { content = 1 }
            END { exit !(header && complete && content) }
        '; then
        log_error "The database archive is damaged, empty or not a complete plain pg_dump backup; nothing was restored"
        exit 1
    fi
    if [ -e "$media" ] || [ -L "$media" ]; then
        if [ ! -r "$media" ] || ! cp "$media" "$RESTORE_TMP_DIR/backup.media.tar.gz"; then
            log_error "Cannot read the media archive; nothing was restored"
            exit 1
        fi
    fi
    check_media_restorable "$RESTORE_TMP_DIR/backup.sql.gz"
}

# Before anything is dropped: the companion must be an intact tar archive, and its volume present.
check_media_restorable() {
    local MEDIA_FILE="${1%.sql.gz}.media.tar.gz"
    local media_root
    media_root="$(basename "$MEDIA_PATH")"
    [ -f "$MEDIA_FILE" ] || return 0
    # GNU tar accepts some short non-tar payloads as empty archives. docker cp always writes
    # the source directory entry, even for empty media, so require that structural evidence too.
    if ! gzip -t "$MEDIA_FILE" 2>/dev/null ||
        ! tar -tzf "$MEDIA_FILE" > "$RESTORE_TMP_DIR/media-members" 2>/dev/null ||
        ! grep -Fxq -e "$media_root" -e "$media_root/" "$RESTORE_TMP_DIR/media-members"; then
        log_error "The media archive ${MEDIA_FILE} is damaged or not a tar archive; nothing was restored"
        exit 1
    fi
    if ! docker container inspect "$MEDIA_CONTAINER" >/dev/null 2>&1; then
        log_error "${MEDIA_CONTAINER} does not exist, so its media volume cannot be restored; nothing was restored."
        log_error "Bring the stack up first (deploy.sh), then run the restore again."
        exit 1
    fi
}

# A split host has no local portal; older installations may have no worker yet. A failed
# inventory query must abort, rather than treating an unknown container state as absence.
find_local_services() {
    local containers name
    if ! containers="$(docker ps -a --format '{{.Names}}')"; then
        log_error "Cannot determine the local application containers; nothing was restored"
        exit 1
    fi
    if ! printf '%s\n' "$containers" | grep -Fxq praho_platform; then
        log_error "The local platform container does not exist; nothing was restored"
        exit 1
    fi
    LOCAL_SERVICES=()
    HEALTH_SERVICES=(praho_platform)
    for name in praho_platform praho_portal praho_qcluster; do
        if printf '%s\n' "$containers" | grep -Fxq "$name"; then
            LOCAL_SERVICES+=("$name")
            [ "$name" != praho_portal ] || HEALTH_SERVICES+=("$name")
        fi
    done
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

    stage_and_check_archives "${BACKUP_FILE}"
    BACKUP_FILE="$RESTORE_TMP_DIR/backup.sql.gz"
    find_local_services

    # Create pre-restore backup
    log_info "Creating pre-restore backup..."
    if ! "${SCRIPT_DIR}/backup.sh"; then
        log_error "Pre-restore backup failed; services and the database were left unchanged"
        exit 1
    fi

    # Stop application services
    log_info "Stopping services..."
    cd "$PROJECT_ROOT"
    # The task worker too: it writes to the same database and media volume.
    if ! docker stop "${LOCAL_SERVICES[@]}"; then
        log_error "Could not stop every local application service; the database was left unchanged. Some services may already be stopped; check container state."
        exit 1
    fi

    # Drop and recreate database
    log_info "Preparing database..."
    if ! docker exec praho_db psql -U praho -d praho --set=ON_ERROR_STOP=1 -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO praho; GRANT ALL ON SCHEMA public TO PUBLIC;"; then
        log_error "Database preparation failed. Applications remain stopped; recover using the pre-restore backup before restarting."
        exit 1
    fi

    # Restore
    log_info "Restoring database..."
    if ! gunzip -c "${BACKUP_FILE}" | docker exec -i praho_db psql -U praho praho --set=ON_ERROR_STOP=1; then
        log_error "Database restore failed and may be partial. Applications remain stopped; recover using the pre-restore backup before restarting."
        exit 1
    fi

    # A media failure must not leave the services down: they restart, and the run fails at the end.
    local MEDIA_FAILED=0
    restore_media "${BACKUP_FILE}" || MEDIA_FAILED=1

    # Restart services
    log_info "Starting services and waiting for health..."
    if ! docker start "${LOCAL_SERVICES[@]}"; then
        log_error "The database was restored, but starting the local services failed. Inspect their state and restart them using this host's deployment configuration."
        exit 1
    fi

    if ! wait_healthy "${HEALTH_SERVICES[@]}"; then
        # The data is restored, but the services did not come back; callers (rollback.sh) must know.
        log_error "The database was restored, but the services did not become healthy."
        exit 1
    fi
    if [ "$MEDIA_FAILED" -ne 0 ]; then
        log_error "The database was restored and the services are up, but restoring the media failed."
        exit 1
    fi
    log_success "Restore completed successfully!"
}

praho_parse_env_args "$@"
set -- ${PRAHO_ARGS[@]+"${PRAHO_ARGS[@]}"}
# Resolve and check the env file before anything is dropped: a production file without its
# keys could not start the platform again.
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
