#!/bin/bash
# =============================================================================
# PRAHO - Database Backup Script
# =============================================================================
# Creates a timestamped PostgreSQL backup
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

cleanup_backups() {
    local DAYS=${1:-$RETENTION_DAYS}
    log_info "Removing backups older than ${DAYS} days..."

    local COUNT=$(find "${BACKUP_DIR}" -name "praho_backup_*.sql.gz" -mtime +${DAYS} | wc -l)

    if [ "$COUNT" -gt 0 ]; then
        find "${BACKUP_DIR}" -name "praho_backup_*.sql.gz" -mtime +${DAYS} -delete
        log_success "Removed ${COUNT} old backup(s)"
    else
        log_info "No old backups to remove"
    fi
}

create_backup() {
    local BACKUP_FILE="${BACKUP_DIR}/praho_backup_${TIMESTAMP}.sql.gz"

    log_info "Creating database backup..."
    log_info "Backup file: ${BACKUP_FILE}"

    # Check if database container is running
    if ! docker ps --format '{{.Names}}' | grep -q "praho_db"; then
        log_error "Database container (praho_db) is not running"
        exit 1
    fi

    # Create backup
    docker exec praho_db pg_dump -U praho praho | gzip > "${BACKUP_FILE}"

    # Verify backup
    if [ -f "${BACKUP_FILE}" ] && [ -s "${BACKUP_FILE}" ]; then
        local SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
        log_success "Backup created successfully"
        log_info "Size: ${SIZE}"

        # Auto cleanup
        cleanup_backups
    else
        log_error "Backup failed - file is empty or missing"
        rm -f "${BACKUP_FILE}"
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
