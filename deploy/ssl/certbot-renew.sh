#!/bin/bash
# ===============================================================================
# PRAHO Platform - Automated SSL Certificate Renewal
# ===============================================================================
# Automatic certificate renewal with nginx reload
#
# Setup cron job for automation:
#   0 3 * * * /path/to/certbot-renew.sh >> /var/log/certbot-renew.log 2>&1
#
# Or use systemd timer (recommended):
#   See certbot-renew.timer and certbot-renew.service
# ===============================================================================

set -euo pipefail

# Configuration
CERT_PATH="/etc/letsencrypt"
WEBROOT_PATH="/var/www/certbot"
NGINX_CONTAINER="${NGINX_CONTAINER:-nginx}"
LOG_FILE="/var/log/praho/certbot-renew.log"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting certificate renewal check..."

# Run certbot renewal
RENEWAL_OUTPUT=$(docker run --rm \
    -v "$CERT_PATH:/etc/letsencrypt" \
    -v "$WEBROOT_PATH:/var/www/certbot" \
    certbot/certbot renew \
    --webroot \
    --webroot-path=/var/www/certbot \
    --quiet \
    --deploy-hook "touch /etc/letsencrypt/renewed" \
    2>&1) || true

log "$RENEWAL_OUTPUT"

# Check if certificates were renewed
if [[ -f "$CERT_PATH/renewed" ]]; then
    log "Certificates were renewed. Reloading nginx..."
    rm -f "$CERT_PATH/renewed"

    # Reload nginx to pick up new certificates
    if docker exec "$NGINX_CONTAINER" nginx -t 2>/dev/null; then
        docker exec "$NGINX_CONTAINER" nginx -s reload
        log "Nginx reloaded successfully"
    else
        log "ERROR: Nginx config test failed. Not reloading."
        exit 1
    fi
else
    log "No certificates needed renewal"
fi

# Cleanup old renewal logs (keep 30 days)
find "$CERT_PATH/renewal-hooks" -name "*.log" -mtime +30 -delete 2>/dev/null || true

log "Renewal check complete"
