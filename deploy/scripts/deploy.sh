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
#
# Every Compose call reads the operator's env file: .env.prod by default, .env.staging with
# --env staging, or any path with --env-file (see lib/compose.sh).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$DEPLOY_DIR")"
# shellcheck source=SCRIPTDIR/lib/compose.sh
source "${SCRIPT_DIR}/lib/compose.sh"

# Outlasts the platform healthcheck's 600s start period (a first boot migrates a fresh database)
# plus its failed-check retries.
WAIT_TIMEOUT=900

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
    echo "Usage: $0 <deployment-type> [--env prod|staging | --env-file PATH] [options]"
    echo ""
    echo "Deployment Types:"
    echo "  single-server      Deploy all services (Platform + Portal + DB + Caddy)"
    echo "  platform-only      Deploy Platform service only"
    echo "  portal-only        Deploy Portal service only"
    echo "  container-service  Deploy for DigitalOcean/AWS container services"
    echo ""
    echo "Env file (never the repo-root .env, which is the development file):"
    echo "  --env prod         Read .env.prod (the default)"
    echo "  --env staging      Read .env.staging"
    echo "  --env-file PATH    Read PATH"
    echo ""
    echo "Options:"
    echo "  --build            Force rebuild images"
    echo "  --no-cache         Rebuild images without Docker cache"
    echo "  --migrate          Run database migrations"
    echo "  --with-db          platform-only: also run the bundled PostgreSQL"
    echo "  --with-caddy       platform-only, portal-only: also run Caddy"
    echo "  --full             platform-only: --with-db and --with-caddy"
    echo "  --stop             Stop this deployment's services"
    echo "  --logs             Follow this deployment's logs"
    echo "  --help             Show this help"
    echo ""
    echo "Examples:"
    echo "  cp .env.example.prod .env.prod   # then fill it in"
    echo "  $0 single-server --build --migrate"
    echo "  $0 single-server --env staging --build"
    echo "  $0 platform-only --with-db --build"
    echo "  $0 single-server --stop"
    exit "${1:-1}"
}

check_requirements() {
    log_info "Checking requirements..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    # `up --wait` needs Compose v2.
    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose v2 is not available"
        exit 1
    fi
}

# compose_up TYPE [--profile NAME ...]: start TYPE and wait until every service with a healthcheck
# reports healthy and the rest (Caddy) are running.
compose_up() {
    local type="$1"
    shift
    local up=(up -d --wait --wait-timeout "$WAIT_TIMEOUT")
    if [ "$NO_CACHE" = true ]; then
        praho_compose "$type" "$@" build --no-cache
    elif [ "$BUILD" = true ]; then
        up+=(--build)
    fi

    log_info "Starting services and waiting for them to be healthy..."
    if ! praho_compose "$type" "$@" "${up[@]}"; then
        log_error "Services did not become healthy. Inspect: $0 $type --logs (or docker logs <container>)"
        praho_compose "$type" "$@" ps || true
        exit 1
    fi
}

deploy_single_server() {
    log_info "Deploying PRAHO - Single Server (all services)"
    compose_up single-server

    if [ "$MIGRATE" = true ]; then
        log_info "Running database migrations..."
        docker exec praho_platform python manage.py migrate --noinput
    fi

    log_info "Collecting static files..."
    docker exec praho_platform python manage.py collectstatic --noinput || true

    log_info "Running initial data setup..."
    docker exec praho_platform python manage.py setup_initial_data || log_warn "setup_initial_data failed"

    verify_deployment single-server
}

deploy_platform_only() {
    log_info "Deploying PRAHO - Platform Only"
    # The bundled PostgreSQL is `db` and speaks no TLS. The env file is shared with native deploys
    # (DB_HOST=localhost, DB_SSLMODE=require), and a shell variable beats it in Compose's
    # substitution. An external database keeps the file's settings.
    if [ "$BUNDLED_DB" = true ]; then
        log_info "Bundled database: DB_HOST=db, DB_SSLMODE=disable"
        export DB_HOST=db DB_SSLMODE=disable
    fi
    compose_up platform-only ${PROFILES[@]+"${PROFILES[@]}"}
    verify_deployment platform-only ${PROFILES[@]+"${PROFILES[@]}"}
}

deploy_portal_only() {
    log_info "Deploying PRAHO - Portal Only"
    # PLATFORM_API_BASE_URL comes from the env file; Compose refuses to start without it.
    compose_up portal-only ${PROFILES[@]+"${PROFILES[@]}"}
    verify_deployment portal-only ${PROFILES[@]+"${PROFILES[@]}"}
}

deploy_container_service() {
    log_info "Building images for container service deployment..."
    if [ "$NO_CACHE" = true ]; then
        praho_compose container-service build --no-cache
    else
        praho_compose container-service build
    fi

    log_success "Images built. Push to registry with:"
    echo "  docker push \${REGISTRY}praho-platform:\${VERSION}"
    echo "  docker push \${REGISTRY}praho-portal:\${VERSION}"
}

# Health was already proven by `up --wait`; show what is running.
verify_deployment() {
    local type="$1"
    shift
    log_success "Deployment complete! Every service is running, and those with a healthcheck report healthy."
    echo ""
    echo "Services:"
    praho_compose "$type" "$@" ps
}

# Main
if [ $# -eq 0 ]; then
    usage
fi
for arg in "$@"; do
    case "$arg" in
        --help | -h) usage 0 ;;
    esac
done

DEPLOYMENT_TYPE="$1"
shift
case "$DEPLOYMENT_TYPE" in
    single-server | platform-only | portal-only | container-service) ;;
    *)
        log_error "Unknown deployment type: $DEPLOYMENT_TYPE"
        usage
        ;;
esac

praho_parse_env_args "$@"
BUILD=false
NO_CACHE=false
MIGRATE=false
BUNDLED_DB=false
ACTION=deploy
PROFILES=()
for arg in ${PRAHO_ARGS[@]+"${PRAHO_ARGS[@]}"}; do
    case "$arg" in
        --build) BUILD=true ;;
        --no-cache) NO_CACHE=true ;;
        --migrate) MIGRATE=true ;;
        --with-db) PROFILES+=(--profile with-db); BUNDLED_DB=true ;;
        --with-caddy) PROFILES+=(--profile with-caddy) ;;
        --full) PROFILES+=(--profile full); BUNDLED_DB=true ;;
        --stop) ACTION=stop ;;
        --logs) ACTION=logs ;;
        *)
            log_error "Unknown option: $arg"
            usage
            ;;
    esac
done

check_requirements
praho_load_env
log_info "Env file: ${PRAHO_ENV_FILE} (${PRAHO_SETTINGS_MODULE})"

case "$ACTION" in
    stop)
        praho_compose "$DEPLOYMENT_TYPE" ${PROFILES[@]+"${PROFILES[@]}"} down
        exit 0
        ;;
    logs)
        praho_compose "$DEPLOYMENT_TYPE" ${PROFILES[@]+"${PROFILES[@]}"} logs -f
        exit 0
        ;;
esac

# Only the stacks that run the platform need its keys: a portal-only host must not hold them, and
# container-service only builds images.
case "$DEPLOYMENT_TYPE" in
    single-server | platform-only) praho_require_production_keys ;;
esac

case "$DEPLOYMENT_TYPE" in
    single-server) deploy_single_server ;;
    platform-only) deploy_platform_only ;;
    portal-only) deploy_portal_only ;;
    container-service) deploy_container_service ;;
esac
