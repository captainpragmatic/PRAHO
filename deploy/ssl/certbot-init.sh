#!/bin/bash
# ===============================================================================
# PRAHO Platform - Let's Encrypt Certificate Initialization
# ===============================================================================
# Initial SSL certificate setup using certbot with DNS or HTTP challenge
#
# Usage:
#   ./certbot-init.sh example.com [staging|production]
#
# Prerequisites:
#   - Docker and docker-compose installed
#   - Port 80 accessible from internet (for HTTP challenge)
#   - Domain DNS pointing to this server
#
# Environment Variables:
#   CERTBOT_EMAIL - Email for Let's Encrypt notifications
#   DOMAIN - Primary domain name
# ===============================================================================

set -euo pipefail

# Configuration
DOMAIN="${1:-${DOMAIN:-}}"
ENVIRONMENT="${2:-staging}"  # Use staging for testing to avoid rate limits
CERTBOT_EMAIL="${CERTBOT_EMAIL:-admin@${DOMAIN}}"
WEBROOT_PATH="/var/www/certbot"
CERT_PATH="/etc/letsencrypt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Validate inputs
if [[ -z "$DOMAIN" ]]; then
    log_error "Domain name required. Usage: $0 example.com [staging|production]"
    exit 1
fi

log_info "Initializing SSL certificates for: $DOMAIN"
log_info "Environment: $ENVIRONMENT"
log_info "Email: $CERTBOT_EMAIL"

# Create webroot directory for ACME challenge
mkdir -p "$WEBROOT_PATH"

# Determine certbot flags
CERTBOT_FLAGS=""
if [[ "$ENVIRONMENT" == "staging" ]]; then
    CERTBOT_FLAGS="--staging"
    log_warn "Using Let's Encrypt STAGING environment (certificates will not be trusted)"
fi

# Check if certificate already exists
if [[ -f "$CERT_PATH/live/$DOMAIN/fullchain.pem" ]]; then
    log_warn "Certificate already exists for $DOMAIN"
    read -p "Do you want to force renewal? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Keeping existing certificate"
        exit 0
    fi
    CERTBOT_FLAGS="$CERTBOT_FLAGS --force-renewal"
fi

# Run certbot with HTTP-01 challenge (webroot mode)
log_info "Requesting certificate from Let's Encrypt..."

docker run --rm \
    -v "$CERT_PATH:/etc/letsencrypt" \
    -v "$WEBROOT_PATH:/var/www/certbot" \
    certbot/certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email "$CERTBOT_EMAIL" \
    --agree-tos \
    --no-eff-email \
    -d "$DOMAIN" \
    -d "www.$DOMAIN" \
    $CERTBOT_FLAGS

# Verify certificate
if [[ -f "$CERT_PATH/live/$DOMAIN/fullchain.pem" ]]; then
    log_info "Certificate obtained successfully!"

    # Display certificate info
    log_info "Certificate details:"
    openssl x509 -in "$CERT_PATH/live/$DOMAIN/fullchain.pem" -noout -subject -dates

    # Set permissions
    chmod 755 "$CERT_PATH/live"
    chmod 755 "$CERT_PATH/archive"

    log_info "SSL setup complete. Reload nginx to apply changes."
else
    log_error "Certificate generation failed"
    exit 1
fi
