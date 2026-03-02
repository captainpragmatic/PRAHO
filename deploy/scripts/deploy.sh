#!/bin/bash
# =============================================================================
# PRAHO - Main Deployment Script
# =============================================================================
# Unified deployment script for all scenarios
#
# Usage:
#   ./deploy.sh single-server          # Deploy all services on one server
#   ./deploy.sh platform-only          # Deploy platform only
#   ./deploy.sh portal-only            # Deploy portal only
#   ./deploy.sh container-service      # Deploy for managed container platforms

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$DEPLOY_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    echo "PRAHO Deployment Script"
    echo ""
    echo "Usage: $0 <deployment-type> [options]"
    echo ""
    echo "Deployment Types:"
    echo "  single-server      Deploy all services (Platform + Portal + DB + Caddy)"
    echo "  platform-only      Deploy Platform service only"
    echo "  portal-only        Deploy Portal service only"
    echo "  container-service  Deploy for DigitalOcean/AWS container services"
    echo ""
    echo "Options:"
    echo "  --build            Force rebuild images"
    echo "  --no-cache         Build without Docker cache"
    echo "  --migrate          Run database migrations"
    echo "  --help             Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 single-server --build --migrate"
    echo "  $0 platform-only --build"
    echo "  $0 portal-only"
    exit 1
}

check_requirements() {
    log_info "Checking requirements..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not available"
        exit 1
    fi

    if [ ! -f "${PROJECT_ROOT}/.env" ]; then
        log_warn ".env file not found. Creating from .env.example..."
        if [ -f "${PROJECT_ROOT}/.env.example" ]; then
            cp "${PROJECT_ROOT}/.env.example" "${PROJECT_ROOT}/.env"
            log_warn "Please edit .env with your configuration"
        else
            log_error ".env.example not found"
            exit 1
        fi
    fi
}

deploy_single_server() {
    local BUILD_FLAG=""
    local CACHE_FLAG=""
    local MIGRATE=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --build) BUILD_FLAG="--build"; shift ;;
            --no-cache) CACHE_FLAG="--no-cache"; shift ;;
            --migrate) MIGRATE=true; shift ;;
            *) shift ;;
        esac
    done

    log_info "Deploying PRAHO - Single Server (all services)"

    cd "$PROJECT_ROOT"

    log_info "Starting services..."
    docker compose -f deploy/docker-compose.single-server.yml up -d $BUILD_FLAG $CACHE_FLAG

    log_info "Waiting for services to be healthy..."
    sleep 30

    if [ "$MIGRATE" = true ]; then
        log_info "Running database migrations..."
        docker exec praho_platform python manage.py migrate --noinput
    fi

    log_info "Collecting static files..."
    docker exec praho_platform python manage.py collectstatic --noinput || true

    log_info "Running post-deploy setup commands..."
    docker exec praho_platform python manage.py setup_categories || log_warn "setup_categories failed"
    docker exec praho_platform python manage.py setup_default_settings || log_warn "setup_default_settings failed"
    docker exec praho_platform python manage.py setup_email_templates || log_warn "setup_email_templates failed"
    docker exec praho_platform python manage.py setup_tax_rules || log_warn "setup_tax_rules failed"
    docker exec praho_platform python manage.py setup_dunning_policies || log_warn "setup_dunning_policies failed"
    docker exec praho_platform python manage.py setup_scheduled_tasks || log_warn "setup_scheduled_tasks failed"

    verify_deployment "single-server"
}

deploy_platform_only() {
    local BUILD_FLAG=""
    local PROFILE=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --build) BUILD_FLAG="--build"; shift ;;
            --with-db) PROFILE="--profile with-db"; shift ;;
            --with-caddy) PROFILE="--profile with-caddy"; shift ;;
            --full) PROFILE="--profile full"; shift ;;
            *) shift ;;
        esac
    done

    log_info "Deploying PRAHO - Platform Only"

    cd "$PROJECT_ROOT"
    docker compose -f deploy/docker-compose.platform-only.yml $PROFILE up -d $BUILD_FLAG

    log_info "Waiting for platform..."
    sleep 20

    verify_deployment "platform-only"
}

deploy_portal_only() {
    local BUILD_FLAG=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --build) BUILD_FLAG="--build"; shift ;;
            --with-caddy) PROFILE="--profile with-caddy"; shift ;;
            *) shift ;;
        esac
    done

    log_info "Deploying PRAHO - Portal Only"

    if [ -z "${PLATFORM_API_BASE_URL:-}" ]; then
        log_error "PLATFORM_API_BASE_URL must be set for portal-only deployment"
        exit 1
    fi

    cd "$PROJECT_ROOT"
    docker compose -f deploy/docker-compose.portal-only.yml up -d $BUILD_FLAG

    log_info "Waiting for portal..."
    sleep 15

    verify_deployment "portal-only"
}

deploy_container_service() {
    local BUILD_FLAG=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --build) BUILD_FLAG="--build"; shift ;;
            *) shift ;;
        esac
    done

    log_info "Building images for container service deployment..."

    cd "$PROJECT_ROOT"

    # Build images
    docker compose -f deploy/docker-compose.container-service.yml build

    log_success "Images built. Push to registry with:"
    echo "  docker push \${REGISTRY}praho-platform:\${VERSION}"
    echo "  docker push \${REGISTRY}praho-portal:\${VERSION}"
}

verify_deployment() {
    local TYPE=$1
    log_info "Verifying deployment..."

    case $TYPE in
        single-server)
            if curl -sf http://localhost:8700/health/ > /dev/null; then
                log_success "Platform is healthy"
            else
                log_warn "Platform health check failed"
            fi
            if curl -sf http://localhost:8701/health/ > /dev/null; then
                log_success "Portal is healthy"
            else
                log_warn "Portal health check failed"
            fi
            ;;
        platform-only)
            if curl -sf http://localhost:8700/health/ > /dev/null; then
                log_success "Platform is healthy"
            else
                log_warn "Platform health check failed"
            fi
            ;;
        portal-only)
            if curl -sf http://localhost:8701/health/ > /dev/null; then
                log_success "Portal is healthy"
            else
                log_warn "Portal health check failed"
            fi
            ;;
    esac

    log_success "Deployment complete!"
    echo ""
    echo "Services:"
    docker compose -f deploy/docker-compose.${TYPE}.yml ps 2>/dev/null || docker ps --filter "name=praho"
}

# Main
if [ $# -eq 0 ]; then
    usage
fi

DEPLOYMENT_TYPE="$1"
shift

check_requirements

case $DEPLOYMENT_TYPE in
    single-server)
        deploy_single_server "$@"
        ;;
    platform-only)
        deploy_platform_only "$@"
        ;;
    portal-only)
        deploy_portal_only "$@"
        ;;
    container-service)
        deploy_container_service "$@"
        ;;
    --help|-h)
        usage
        ;;
    *)
        log_error "Unknown deployment type: $DEPLOYMENT_TYPE"
        usage
        ;;
esac
