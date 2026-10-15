#!/bin/bash
# =============================================================================
# PRAHO - Database and Media Backup Script
# =============================================================================
# Creates a timestamped PostgreSQL backup, and next to it an archive of the media volume
# (uploads and generated documents such as ANAF's e-Factura response archives).
#
# Usage:
#   ./backup.sh                    # Create backup
#   ./backup.sh --list             # List existing backups
#   ./backup.sh --cleanup [days]   # Remove backups older than N days

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$DEPLOY_DIR")"
BACKUP_DIR="${BACKUP_DIR:-${PROJECT_ROOT}/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
# MEDIA_ROOT inside the platform container: the media_files volume (see the compose files).
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

mkdir -p "$BACKUP_DIR"

list_backups() {
    echo "Available backups in ${BACKUP_DIR}:"
    echo ""
    if ls "${BACKUP_DIR}"/praho_backup_*.sql.gz 1> /dev/null 2>&1; then
        ls -lh "${BACKUP_DIR}"/praho_backup_*.sql.gz | awk '{print $9, $5, $6, $7, $8}'
    else
        echo "No backups found."
    fi
}

# A killed backup skips its EXIT trap. A partial untouched for a day (1440 minutes) is abandoned;
# one being written changes as the dump streams in.
remove_abandoned_partials() {
    find "${BACKUP_DIR}" -name "praho_backup_*.partial" -mmin +1440 -delete
}

cleanup_backups() {
    local DAYS=${1:-$RETENTION_DAYS}
    log_info "Removing backups older than ${DAYS} days..."
    remove_abandoned_partials

    local COUNT=$(find "${BACKUP_DIR}" -name "praho_backup_*.sql.gz" -mtime +${DAYS} | wc -l)
    # Metadata and media go with their dump.
    find "${BACKUP_DIR}" -maxdepth 1 -type f -user "$(id -un)" -name "praho_backup_*.metadata.json" -mtime "+${DAYS}" -delete
    find "${BACKUP_DIR}" -name "praho_backup_*.media.tar.gz" -mtime "+${DAYS}" -delete

    if [ "$COUNT" -gt 0 ]; then
        find "${BACKUP_DIR}" -name "praho_backup_*.sql.gz" -mtime +${DAYS} -delete
        log_success "Removed ${COUNT} old backup(s)"
    else
        log_info "No old backups to remove"
    fi
}

# docker cp reads a stopped container too, so the media is archived whether or not the platform runs.
backup_media() {
    log_info "Archiving media (${MEDIA_CONTAINER}:${MEDIA_PATH})..."
    if docker cp "${MEDIA_CONTAINER}:${MEDIA_PATH}" - | gzip > "${MEDIA_PARTIAL}" && [ -s "${MEDIA_PARTIAL}" ]; then
        mv "${MEDIA_PARTIAL}" "${MEDIA_FILE}"
        log_success "Media archived: ${MEDIA_FILE} ($(du -h "${MEDIA_FILE}" | cut -f1))"
    else
        # The database dump is complete and kept; the run still fails, so cron and callers notice.
        # Retention still runs, so a lasting media failure does not pile dumps up.
        log_error "Media archive failed; the database backup ${BACKUP_FILE} is complete"
        cleanup_backups
        exit 1
    fi
}

create_backup() {
    # The process id keeps two backups started in the same second apart: no two running processes share one.
    local BACKUP_FILE="${BACKUP_DIR}/praho_backup_${TIMESTAMP}_$$.sql.gz"
    # Written under another name and renamed once complete, so a failed dump never matches
    # praho_backup_*.sql.gz, which restore --latest picks from. Global: the EXIT trap reads it.
    PARTIAL_FILE="${BACKUP_FILE}.partial"
    # The media archive sits next to its dump, so a restore finds the pair by name.
    MEDIA_FILE="${BACKUP_FILE%.sql.gz}.media.tar.gz"
    MEDIA_PARTIAL="${MEDIA_FILE}.partial"
    trap 'rm -f "${PARTIAL_FILE}" "${MEDIA_PARTIAL}"' EXIT
    # Before the dump, so a string of interrupted runs cannot pile partials up either.
    remove_abandoned_partials

    log_info "Creating database backup..."
    log_info "Backup file: ${BACKUP_FILE}"

    # Check if database container is running
    if ! docker ps --format '{{.Names}}' | grep -q "praho_db"; then
        log_error "Database container (praho_db) is not running"
        exit 1
    fi

    # Create backup
    docker exec praho_db pg_dump -U praho praho | gzip > "${PARTIAL_FILE}"

    # Verify backup
    if [ -s "${PARTIAL_FILE}" ]; then
        mv "${PARTIAL_FILE}" "${BACKUP_FILE}"
        local SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
        log_success "Backup created successfully"
        log_info "Size: ${SIZE}"

        backup_media
        # Metadata is published only for a complete pair; it contains no credentials.
        if ! python3 "${SCRIPT_DIR}/backup_manifest.py" create "$BACKUP_FILE"; then
            log_error "Backup pair retained, but recovery metadata could not be written"
            cleanup_backups
            exit 1
        fi

        # Auto cleanup
        cleanup_backups
    else
        log_error "Backup failed - file is empty or missing"
        exit 1
    fi
}

case "${1:-}" in
    --list)
        list_backups
        ;;
    --cleanup)
        cleanup_backups "${2:-}"
        ;;
    *)
        create_backup
        ;;
esac
