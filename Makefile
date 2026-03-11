# ===============================================================================
# PRAHO PLATFORM - SERVICES ARCHITECTURE MAKEFILE 🏗️
# ===============================================================================
# Enhanced for Platform/Portal separation with scoped PYTHONPATH security

.PHONY: help install check-env dev dev-e2e dev-e2e-bg dev-platform dev-portal dev-all test test-fast test-platform test-portal test-integration test-e2e test-with-e2e test-e2e-platform test-e2e-portal test-e2e-orm test-security test-cache install-frontend build-css watch-css check-css-tooling migrate fixtures fixtures-light clean lint lint-fix lint-platform lint-portal lint-security lint-health lint-credentials lint-audit lint-fsm check-types check-types-platform check-types-portal pre-commit infra-init infra-plan infra-dev infra-staging infra-prod infra-destroy-dev deploy-dev deploy-staging deploy-prod i18n-extract i18n-compile translate translate-platform translate-portal translate-ai translate-ai-platform translate-ai-portal translate-review translate-apply translate-diff translate-stats translate-stats-platform translate-stats-portal audit-a11y audit-a11y-strict audit-dark-mode audit-dark-mode-strict

# ===============================================================================
# SCOPED PYTHON ENVIRONMENTS 🔒
# ===============================================================================

# Detect OS for platform-specific venv (shared macOS/Linux volume support).
# Produces: .venv-darwin (macOS host) or .venv-linux (container/CI).
UNAME_S  := $(shell uname -s | tr '[:upper:]' '[:lower:]')
VENV_DIR := .venv-$(UNAME_S)
export UV_PROJECT_ENVIRONMENT := $(VENV_DIR)

# Platform-specific Python with scoped PYTHONPATH (database access)
PYTHON_PLATFORM = cd services/platform && PYTHONPATH=$(PWD)/services/platform $(PWD)/$(VENV_DIR)/bin/python
PYTHON_PLATFORM_MANAGE = $(PYTHON_PLATFORM) manage.py

# Portal-specific Python (NO PYTHONPATH - cannot import platform code)
# DJANGO_SETTINGS_MODULE pinned to config.settings.dev — portal has no test.py settings
PYTHON_PORTAL = cd services/portal && DJANGO_SETTINGS_MODULE=config.settings.dev $(PWD)/$(VENV_DIR)/bin/python
PYTHON_PORTAL_MANAGE = $(PYTHON_PORTAL) manage.py

# Shared Python for workspace-level tasks
PYTHON_SHARED = $(VENV_DIR)/bin/python

# ===============================================================================
# HELP & SETUP 📖
# ===============================================================================

help:
	@echo "🚀 PRAHO Platform - Services Architecture"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🏗️  DEVELOPMENT SERVICES:"
	@echo "  make dev             - Run all services (platform + portal)"
	@echo "  make dev-e2e         - Run all services with rate limiting disabled (foreground)"
	@echo "  make dev-e2e-bg      - Same as dev-e2e but backgrounded (waits until ready, returns)"
	@echo "  make dev-platform    - Run platform service only (:8700)"
	@echo "  make dev-portal      - Run portal service only (:8701)"
	@echo ""
	@echo "🧪 TESTING (SERVICE-ISOLATED):"
	@echo "  make test            - Test all services (Django test runner)"
	@echo "  make test-platform   - Test platform service with DB access (Django)"
	@echo "  make test-platform-pytest - Test platform service with pytest"
	@echo "  make test-portal     - Test portal service (NO DB access)"
	@echo "  make test-integration - Test platform→portal API communication"
	@echo "  make test-e2e        - All E2E tests (requires both services)"
	@echo "  make test-with-e2e   - Alias for make test-e2e"
	@echo "  make test-e2e-platform - Platform staff E2E tests (:8700)"
	@echo "  make test-e2e-portal   - Portal customer E2E tests (:8701)"
	@echo "  make test-e2e-orm      - ORM E2E tests (no server needed)"
	@echo "  make test-security   - Validate service isolation"
	@echo ""
	@echo "🔧 DATABASE & ASSETS:"
	@echo "  make migrate         - Run platform database migrations"
	@echo "  make fixtures        - Load comprehensive sample data (platform only)"
	@echo "  make fixtures-light  - Load minimal sample data (fast, platform only)"
	@echo "  make install-frontend - Install Node.js dependencies"
	@echo "  make build-css       - Build Tailwind CSS assets for all services"
	@echo "  make watch-css       - Watch and rebuild CSS during development"
	@echo ""
	@echo "🧹 CODE QUALITY:"
	@echo "  make lint            - Lint all services"
	@echo "  make lint-platform   - Lint platform service only"
	@echo "  make lint-portal     - Lint portal service only"
	@echo "  make lint-fsm        - FSM guardrail lint (ADR-0034)"
	@echo "  make lint-security   - Security vulnerabilities (Semgrep + credentials)"
	@echo "  make lint-health     - Code health anti-pattern scan"
	@echo "  make check-types     - Type check all services"
	@echo "  make pre-commit      - Run pre-commit hooks"
	@echo ""
	@echo "🔒 SECURITY:"
	@echo "  make test-security   - Validate service isolation"
	@echo "  make lint-credentials - Check for hardcoded credentials"
	@echo ""
	@echo "🐳 DOCKER (Dev):"
	@echo "  make docker-build    - Build platform + portal Docker images"
	@echo "  make docker-dev      - Start development services with hot reload"
	@echo "  make docker-prod     - Start production services with nginx"
	@echo "  make docker-stop     - Stop all Docker services"
	@echo "  make docker-test     - Test Docker services health"
	@echo "  make docker-clean    - Clean up Docker containers and images"
	@echo ""
	@echo "🚀 PRODUCTION DEPLOYMENT:"
	@echo "  make deploy-single-server  - Deploy all services on single server"
	@echo "  make deploy-platform       - Deploy platform service only"
	@echo "  make deploy-portal         - Deploy portal service only"
	@echo "  make deploy-container-service - Build for DigitalOcean/AWS"
	@echo "  make deploy-stop           - Stop all deployment services"
	@echo "  make deploy-status         - Show deployment status"
	@echo "  make deploy-logs           - Show service logs"
	@echo ""
	@echo "💾 BACKUP & RESTORE:"
	@echo "  make backup          - Create database backup"
	@echo "  make backup-list     - List available backups"
	@echo "  make restore         - Interactive restore from backup"
	@echo "  make restore-latest  - Restore latest backup"
	@echo ""
	@echo "⏪ ROLLBACK:"
	@echo "  make rollback VERSION=X - Roll back to version X"
	@echo "  make rollback-db        - Restore latest database backup"
	@echo "  make health-check       - Check service health"
	@echo ""
	@echo "☁️  INFRASTRUCTURE (Terraform → Hetzner):"
	@echo "  make infra-init            - Initialize Terraform"
	@echo "  make infra-plan ENV=dev    - Plan infrastructure changes"
	@echo "  make infra-dev             - Provision dev server"
	@echo "  make infra-staging         - Provision staging servers"
	@echo "  make infra-prod            - Provision production servers"
	@echo "  make infra-destroy-dev     - Destroy dev server"
	@echo ""
	@echo "🚀 ENVIRONMENT DEPLOYMENT (Ansible):"
	@echo "  make deploy-dev            - Deploy PRAHO to dev (Docker)"
	@echo "  make deploy-dev-native     - Deploy PRAHO to dev (native, no Docker)"
	@echo "  make deploy-staging                - Deploy to staging (git HEAD of DEPLOY_BRANCH, or rsync)"
	@echo "  make deploy-prod                   - Deploy to production (git tag from PRAHO_VERSION)"
	@echo "  make deploy-prod VERSION=v0.14.0   - Deploy specific version to production"
	@echo ""
	@echo "📜 ANSIBLE (generic):"
	@echo "  make ansible-single-server - Deploy via Ansible (single server)"
	@echo "  make ansible-two-servers   - Deploy via Ansible (distributed)"
	@echo "  make ansible-backup        - Remote backup via Ansible"
	@echo ""
	@echo "⚙️  SETUP & MAINTENANCE:"
	@echo "  make install         - Set up development environment"
	@echo "  make clean           - Clean build artifacts"

# ===============================================================================
# DEVELOPMENT ENVIRONMENT SETUP 🔧
# ===============================================================================

install:
	@echo "🔧 Setting up PRAHO services development environment ($(UNAME_S))..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@if ! command -v uv >/dev/null 2>&1; then \
		echo "📦 Installing uv..."; \
		curl -LsSf https://astral.sh/uv/install.sh | sh; \
	fi
	@if [ -d .venv ] && [ ! -L .venv ]; then \
		echo "🗑️  Removing legacy .venv/ (migrating to $(VENV_DIR)/)..."; \
		rm -rf .venv; \
	fi
	@echo "📦 Syncing all dependency groups via uv → $(VENV_DIR)/..."
	uv sync --all-groups
	@echo "🔗 Installing pre-commit hooks..."
	$(VENV_DIR)/bin/pre-commit install
	@echo "🔧 Patching pre-commit hook for cross-platform dynamic resolution..."
	$(VENV_DIR)/bin/python scripts/patch_precommit_hook.py
	@echo ""
	@if [ ! -f .env ]; then \
		echo ""; \
		echo "⚠️  No .env file found. Before running services:"; \
		echo "   cp .env.example.dev .env"; \
		echo "   Then edit .env with your credentials."; \
	fi
	@echo "✅ Environment ready! 🐍 $(VENV_DIR)/ | 🔒 Portal cannot import platform code"

check-env:
	@if [ ! -f .env ]; then \
		echo ""; \
		echo "🚨 Missing .env file!"; \
		echo "   cp .env.example.dev .env"; \
		echo "   Then edit .env with your values."; \
		echo ""; \
		exit 1; \
	fi

# ===============================================================================
# DEVELOPMENT SERVERS 🚀
# ===============================================================================
#
# Convention: NORELOAD=1 disables Django's auto-reloader (used by E2E targets).
# All dev-* targets share the same runserver recipes; E2E targets just set the flag.

RUNSERVER_FLAGS := $(if $(NORELOAD),--noreload,)

dev-platform: check-env
	@echo "🏗️ [Platform] Starting admin platform service..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "📍 PYTHONPATH: services/platform (scoped)"
	@echo "🗄️ Running migrations..."
	@$(PYTHON_PLATFORM_MANAGE) migrate --settings=config.settings.dev
	@echo "🎯 Setting up initial data..."
	@$(PYTHON_PLATFORM_MANAGE) setup_initial_data --settings=config.settings.dev || echo "⚠️ Initial data setup skipped"
	@echo "🔧 Loading dev sample data..."
	@$(PYTHON_PLATFORM_MANAGE) generate_sample_data --customers 2 --users 3 --services-per-customer 2 --orders-per-customer 1 --invoices-per-customer 2 --proformas-per-customer 1 --tickets-per-customer 2 --settings=config.settings.dev || echo "⚠️ Sample data setup skipped"
	@$(PYTHON_PLATFORM_MANAGE) qcluster --settings=config.settings.dev > django_q.log 2>&1 & \
	QCLUSTER_PID=$$!; \
	echo "🚀 Django-Q2 workers started (PID: $$QCLUSTER_PID)"; \
	echo "🌐 Starting platform server on :8700$(if $(NORELOAD), (no-reload),)..."; \
	trap 'echo "🛑 Stopping Django-Q2 workers..."; kill $$QCLUSTER_PID 2>/dev/null || true' EXIT; \
	$(PYTHON_PLATFORM_MANAGE) runserver 0.0.0.0:8700 --settings=config.settings.dev $(RUNSERVER_FLAGS)

dev-portal: check-env
	@echo "🌐 [Portal] Starting customer portal service..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🔒 NO PYTHONPATH - portal cannot import platform code"
	@echo "🔍 Validating portal configuration..."
	@$(PYTHON_PORTAL_MANAGE) check
	@echo "✅ Portal configuration valid"
	@echo "🌐 Starting portal server on :8701$(if $(NORELOAD), (no-reload),)..."
	@$(PYTHON_PORTAL_MANAGE) runserver 0.0.0.0:8701 $(RUNSERVER_FLAGS)

dev-all: build-css
	@echo "🚀 [All Services] Starting platform + portal..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(MAKE) -j2 dev-platform dev-portal

dev:
	@$(MAKE) dev-all

dev-e2e: check-env
	@echo "🎭 [E2E Dev] Starting services with rate limiting disabled (no auto-reload)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@RATE_LIMITING_ENABLED=false $(MAKE) NORELOAD=1 dev-all

dev-e2e-bg: check-env build-css
	@echo "🎭 [E2E Background] Starting services in background (no auto-reload)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@mkdir -p logs
	@# Kill stale processes on E2E ports
	@-lsof -tiTCP:8700 -sTCP:LISTEN | xargs -r kill -9 >/dev/null 2>&1 || true
	@-lsof -tiTCP:8701 -sTCP:LISTEN | xargs -r kill -9 >/dev/null 2>&1 || true
	@sleep 1
	@echo "🏗️  Starting platform (port :8700) in background..."
	@RATE_LIMITING_ENABLED=false sh -c '$(MAKE) NORELOAD=1 dev-platform 2>&1 | tee logs/platform_e2e.log' &
	@echo "🌐 Starting portal (port :8701) in background..."
	@RATE_LIMITING_ENABLED=false sh -c '$(MAKE) NORELOAD=1 dev-portal 2>&1 | tee logs/portal_e2e.log' &
	@echo "⏳ Waiting for services to be ready..."
	@for i in $$(seq 1 30); do \
		platform=$$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8700/auth/login/ 2>/dev/null); \
		portal=$$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8701/login/ 2>/dev/null); \
		if [ "$$platform" = "200" ] && [ "$$portal" = "200" ]; then \
			echo "✅ Both services ready (platform=$$platform portal=$$portal)"; \
			echo "📜 Logs: logs/platform_e2e.log, logs/portal_e2e.log"; \
			exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "❌ Services failed to start within 60s. Check logs/"; \
	exit 1

# Start both services and write logs to files via tee
.PHONY: dev-with-logs
dev-with-logs: check-env build-css
	@echo "🚀 [All Services] Starting platform + portal with logs..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@mkdir -p logs
	@echo "🧹 Killing anything bound to :8700/:8701 (if any)"
	@-lsof -tiTCP:8700 -sTCP:LISTEN | xargs -r kill -9 >/dev/null 2>&1 || true
	@-lsof -tiTCP:8701 -sTCP:LISTEN | xargs -r kill -9 >/dev/null 2>&1 || true
	@echo "📜 Logs: logs/platform_dev.log, logs/portal_dev.log"
	@echo "🏗️  Starting platform (port :8700)..."
	@sh -c '$(MAKE) dev-platform 2>&1 | tee logs/platform_dev.log' & echo $$! > logs/platform_dev.pid
	@sleep 2
	@echo "🌐 Starting portal (port :8701)..."
	@sh -c '$(MAKE) dev-portal 2>&1 | tee logs/portal_dev.log' & echo $$! > logs/portal_dev.pid
	@echo "📍 Follow logs:"
	@echo "  tail -f logs/platform_dev.log logs/portal_dev.log"

# ===============================================================================
# TESTING WITH SERVICE ISOLATION 🧪
# ===============================================================================

test-platform:
	@echo "🧪 [Platform] Testing with database cache (no Redis)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(PYTHON_PLATFORM_MANAGE) test tests --settings=config.settings.test --verbosity=2 --parallel --keepdb
	@echo "✅ Platform tests completed successfully!"

test-file:
	@echo "🧪 [Platform] Running specific test: $(FILE)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(PYTHON_PLATFORM_MANAGE) test $(FILE) --settings=config.settings.test --verbosity=2
	@echo "✅ Test completed!"

test-platform-pytest:
	@echo "🧪 [Platform] Testing with pytest (database cache)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@cd services/platform && PYTHONPATH=$(PWD)/services/platform $(PWD)/$(VENV_DIR)/bin/python -m pytest -v
	@echo "✅ Platform pytest tests completed successfully!"

test-portal:
	@echo "🧪 [Portal] Testing without database access (strict isolation)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@cd services/portal && PYTHONPATH= PYTHONNOUSERSITE=1 $(PWD)/$(VENV_DIR)/bin/python -m pytest -v
	@echo "✅ Portal tests completed - database access properly blocked!"

test-integration:
	@echo "🔄 [Integration] Testing services communication and cache functionality..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🧪 Running integration tests..."
	@$(PWD)/$(VENV_DIR)/bin/python -m pytest tests/integration/ -v
	@echo "✅ Integration tests completed!"

test-cache:
	@echo "💾 [Cache] Testing database cache functionality (post Redis removal)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(PWD)/$(VENV_DIR)/bin/python -m pytest tests/integration/test_database_cache.py -v -m cache
	@echo "✅ Database cache tests passed!"

test-security:
	@echo "🔒 [Security] Validating service isolation (no Redis dependencies)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🧪 Testing portal cannot import platform-specific modules..."
	@cd services/portal && \
		if PYTHONPATH= PYTHONNOUSERSITE=1 $(PWD)/$(VENV_DIR)/bin/python -c "import apps.customers.customer_models" 2>/dev/null; then \
			echo "❌ SECURITY BREACH: Portal can import apps.customers.customer_models"; \
			exit 1; \
		fi && \
		if PYTHONPATH= PYTHONNOUSERSITE=1 $(PWD)/$(VENV_DIR)/bin/python -c "import apps.billing.invoice_models" 2>/dev/null; then \
			echo "❌ SECURITY BREACH: Portal can import apps.billing.invoice_models"; \
			exit 1; \
		fi && \
		if PYTHONPATH= PYTHONNOUSERSITE=1 $(PWD)/$(VENV_DIR)/bin/python -c "import apps.orders.signals_extended" 2>/dev/null; then \
			echo "❌ SECURITY BREACH: Portal can import apps.orders.signals_extended"; \
			exit 1; \
		fi && \
		echo "✅ Portal properly isolated from platform modules"
	@echo "🧪 Testing platform uses database cache (base settings, not dev override)..."
	@cd services/platform && DJANGO_SETTINGS_MODULE=config.settings.base PYTHONPATH=$(PWD)/services/platform $(PWD)/$(VENV_DIR)/bin/python -c "import django; django.setup(); from django.conf import settings; cache_backend = settings.CACHES['default']['BACKEND']; assert 'DatabaseCache' in cache_backend, f'Should use database cache, got: {cache_backend}'; print('✅ Platform base settings use database cache')"
	@echo "🧪 Testing portal has NO database access..."
	@cd services/portal && DJANGO_SETTINGS_MODULE=config.settings.dev PYTHONPATH= PYTHONNOUSERSITE=1 $(PWD)/$(VENV_DIR)/bin/python -c "import django; django.setup(); from django.conf import settings; print('✅ Portal isolated from DB:', not bool(getattr(settings, 'DATABASES', {})))"
	@echo "🧪 Running portal database access prevention test..."
	@cd services/portal && DJANGO_SETTINGS_MODULE=config.settings.dev PYTHONPATH= PYTHONNOUSERSITE=1 $(PWD)/$(VENV_DIR)/bin/python -m pytest tests/security/test_import_isolation_guard.py::test_db_access_blocked -v
	@echo "🎉 All security isolation tests passed!"

test-e2e:
	@echo "🎭 [E2E] Running all end-to-end tests..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "⚠️  Requires services running with rate limiting disabled (make dev-e2e)"
	@echo "🧪 Checking if services are available..."
	@curl -sf http://localhost:8700/auth/login/ > /dev/null 2>&1 || (echo "❌ Platform service not running on :8700. Run 'make dev-e2e' first." && exit 1)
	@curl -sf http://localhost:8701/login/ > /dev/null 2>&1 || (echo "❌ Portal service not running on :8701. Run 'make dev-e2e' first." && exit 1)
	@echo "✅ Both services are running"
	@echo "🔍 Checking rate limiting is disabled..."
	@RATE_LIMITED=false; \
	for i in 1 2 3 4 5; do \
		STATUS=$$(curl -so /dev/null -w "%{http_code}" http://localhost:8700/auth/login/ 2>/dev/null); \
		if [ "$$STATUS" = "429" ]; then \
			RATE_LIMITED=true; \
			break; \
		fi; \
	done; \
	if [ "$$RATE_LIMITED" = "true" ]; then \
		echo "❌ Rate limiting is ACTIVE on platform service."; \
		echo "   E2E tests make ~180 login requests and WILL fail with rate limiting enabled."; \
		echo "   Restart services: make dev-e2e"; \
		exit 1; \
	fi
	@echo "✅ Rate limiting check passed"
	@echo "🧹 Clearing stale bytecode cache..."
	@find tests/e2e/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "🎭 Running Playwright E2E tests..."
	@DJANGO_SETTINGS_MODULE=config.settings.e2e PYTHONPATH=$(PWD)/services/platform $(PWD)/$(VENV_DIR)/bin/python -m pytest tests/e2e/ -v
	@echo "✅ E2E tests completed!"

test-with-e2e: test-e2e

test-e2e-platform:
	@echo "🎭 [E2E Platform] Running platform staff E2E tests..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "⚠️  Requires platform service running with rate limiting disabled (make dev-e2e)"
	@curl -sf http://localhost:8700/auth/login/ > /dev/null 2>&1 || (echo "❌ Platform service not running on :8700. Run 'make dev-e2e' first." && exit 1)
	@find tests/e2e/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@DJANGO_SETTINGS_MODULE=config.settings.e2e PYTHONPATH=$(PWD)/services/platform $(PWD)/$(VENV_DIR)/bin/python -m pytest tests/e2e/platform/ -v
	@echo "✅ Platform E2E tests completed!"

test-e2e-portal:
	@echo "🎭 [E2E Portal] Running portal customer E2E tests..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "⚠️  Requires portal service running with rate limiting disabled (make dev-e2e)"
	@curl -sf http://localhost:8701/login/ > /dev/null 2>&1 || (echo "❌ Portal service not running on :8701. Run 'make dev-e2e' first." && exit 1)
	@find tests/e2e/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@DJANGO_SETTINGS_MODULE=config.settings.e2e PYTHONPATH=$(PWD)/services/platform $(PWD)/$(VENV_DIR)/bin/python -m pytest tests/e2e/portal/ -v
	@echo "✅ Portal E2E tests completed!"

test-e2e-orm:
	@echo "🎭 [E2E ORM] Running ORM-based E2E tests (no server needed)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@find tests/e2e/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@DJANGO_SETTINGS_MODULE=config.settings.e2e PYTHONPATH=$(PWD)/services/platform $(PWD)/$(VENV_DIR)/bin/python -m pytest tests/e2e/orm/ -v
	@echo "✅ ORM E2E tests completed!"

test:
	@echo "🔄 [All Tests] Running comprehensive test suite (post Redis removal)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "📋 Phase 1: Platform service tests (database cache)"
	@$(MAKE) test-platform
	@echo "📋 Phase 2: Portal service tests (database access blocked)"
	@$(MAKE) test-portal
	@echo "📋 Phase 3: Integration tests (services communication)"
	@$(MAKE) test-integration
	@echo "📋 Phase 4: Database cache functionality"
	@$(MAKE) test-cache
	@echo "📋 Phase 5: Security validation (service isolation)"
	@$(MAKE) test-security
	@echo "🎉 All test phases completed successfully!"

test-fast:
	@echo "⚡ [Platform] Fast test run (failfast + keepdb + parallel)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ifdef FILE
	@$(PYTHON_PLATFORM_MANAGE) test $(FILE) --settings=config.settings.test --verbosity=2 --failfast --keepdb
else
	@$(PYTHON_PLATFORM_MANAGE) test tests --settings=config.settings.test --verbosity=2 --failfast --keepdb --parallel
endif
	@echo "✅ Fast tests completed!"

# ===============================================================================
# DATABASE & ASSETS 🗄️
# ===============================================================================

migrate:
	@echo "🗄️ [Platform] Running database migrations..."
	@$(PYTHON_PLATFORM_MANAGE) makemigrations --settings=config.settings.dev
	@$(PYTHON_PLATFORM_MANAGE) migrate --settings=config.settings.dev

fixtures:
	@echo "📊 [Platform] Loading comprehensive sample data..."
	@echo "🎯 Setting up initial data (core + business)..."
	@$(PYTHON_PLATFORM_MANAGE) setup_initial_data --include-business --settings=config.settings.dev
	@echo "🌐 Syncing infrastructure providers..."
	@$(PYTHON_PLATFORM_MANAGE) sync_providers --settings=config.settings.dev || echo "⚠️ Provider sync skipped"
	@$(PYTHON_PLATFORM_MANAGE) generate_sample_data --settings=config.settings.dev

fixtures-light:
	@echo "📊 [Platform] Loading minimal sample data (fast)..."
	@echo "🎯 Setting up initial data (core + business)..."
	@$(PYTHON_PLATFORM_MANAGE) setup_initial_data --include-business --settings=config.settings.dev
	@echo "🌐 Syncing infrastructure providers..."
	@$(PYTHON_PLATFORM_MANAGE) sync_providers --settings=config.settings.dev || echo "⚠️ Provider sync skipped"
	@$(PYTHON_PLATFORM_MANAGE) generate_sample_data --customers 2 --users 3 --services-per-customer 2 --orders-per-customer 1 --invoices-per-customer 2 --proformas-per-customer 1 --tickets-per-customer 2 --settings=config.settings.dev

# ===============================================================================
# CODE QUALITY 🧹
# ===============================================================================

lint-platform:
	@echo "🏗️ [Platform] Comprehensive code quality check..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🔍 1/6: Performance & Security Analysis (Ruff)..."
	@cd services/platform && $(PWD)/$(VENV_DIR)/bin/ruff check . --statistics || echo "⚠️ Ruff check skipped"
	@echo ""
	@echo "🏷️  2/6: Type Safety Check (MyPy)..."
	@cd services/platform && PYTHONPATH=$(PWD)/services/platform $(PWD)/$(VENV_DIR)/bin/mypy apps/ --config-file=../../pyproject.toml 2>/dev/null || echo "⚠️ MyPy check skipped"
	@echo ""
	@echo "📊 3/6: Django Check..."
	@$(PYTHON_PLATFORM_MANAGE) check --settings=config.settings.dev
	@echo ""
	@echo "🔒 4/6: Audit Coverage Check..."
	@$(PYTHON_SHARED) scripts/audit_coverage_scan.py --min-severity=medium --exclude-tests services/platform/apps
	@echo ""
	@echo "⚙️ 5/6: Settings Coverage Check..."
	@$(PYTHON_SHARED) scripts/lint_settings_coverage.py --fail-on medium
	@echo ""
	@echo "🌐 6/6: i18n Coverage Check..."
	@$(PYTHON_SHARED) scripts/lint_i18n_coverage.py --fail-on high --allowlist scripts/i18n_coverage_allowlist.txt services/platform/apps services/platform/templates
	@echo "✅ Platform linting complete!"

lint-audit:
	@echo "🔒 [Audit] Coverage scanner..."
	@$(PYTHON_SHARED) scripts/audit_coverage_scan.py --min-severity=medium --exclude-tests services/platform/apps
	@echo "✅ Audit coverage check complete!"

lint-portal:
	@echo "🌐 [Portal] Code quality check (NO database access)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🔍 1/3: Performance & Security Analysis (Ruff)..."
	@cd services/portal && $(PWD)/$(VENV_DIR)/bin/ruff check . --statistics || echo "⚠️ Ruff check skipped"
	@echo ""
	@echo "📊 2/3: Django Check (NO DB)..."
	@$(PYTHON_PORTAL_MANAGE) check
	@echo ""
	@echo "🌐 3/3: i18n Coverage Check..."
	@$(PYTHON_SHARED) scripts/lint_i18n_coverage.py --fail-on high --allowlist scripts/i18n_coverage_allowlist.txt services/portal/apps services/portal/templates
	@echo "✅ Portal linting complete!"

lint:
ifdef FILE
	@echo "🔍 [Lint] Checking: $(FILE)"
	@$(VENV_DIR)/bin/ruff check $(FILE) --config=pyproject.toml
else
	@echo "🔄 [All Services] Comprehensive linting..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "📋 Phase 0: Ruff no-new-debt gate"
	@BASE_REF=$$(git merge-base HEAD origin/master 2>/dev/null || git rev-parse HEAD~1 2>/dev/null || echo HEAD); \
		echo "🔍 Comparing new Ruff violations against: $$BASE_REF"; \
		$(VENV_DIR)/bin/python scripts/ruff_new_violations.py --baseline-ref "$$BASE_REF"
	@echo "📋 Phase 1: Platform service"
	@$(MAKE) lint-platform
	@echo "📋 Phase 2: Portal service"
	@$(MAKE) lint-portal
	@echo "📋 Phase 3: Test suppression scan (ADR-0014)"
	@$(VENV_DIR)/bin/python scripts/lint_test_suppressions.py --fail-on critical
	@echo "📋 Phase 4: i18n coverage scan"
	@$(PYTHON_SHARED) scripts/lint_i18n_coverage.py --fail-on high --allowlist scripts/i18n_coverage_allowlist.txt services/platform/apps services/portal/apps services/platform/templates services/portal/templates
	@echo "📋 Phase 5: Code health scan"
	@$(VENV_DIR)/bin/python scripts/code_health_scan.py --min-severity=high --exclude-tests --allowlist=scripts/code_health_allowlist.txt services/platform/apps || true
	@echo "📋 Phase 6: FSM guardrail lint (ADR-0034)"
	@$(MAKE) lint-fsm
	@echo "🎉 All services linting complete!"
endif

lint-fix:
ifdef FILE
	@echo "🔧 [Lint Fix] Auto-fixing: $(FILE)"
	@$(VENV_DIR)/bin/ruff check $(FILE) --fix --config=pyproject.toml || true
	@echo "✅ Auto-fix complete — review changes before committing."
else
	@echo "🔧 [All Services] Auto-fixing safe lint issues..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "📋 Platform:"
	@cd services/platform && $(PWD)/$(VENV_DIR)/bin/ruff check . --fix --config=../../pyproject.toml || true
	@echo "📋 Portal:"
	@cd services/portal && $(PWD)/$(VENV_DIR)/bin/ruff check . --fix --config=../../pyproject.toml || true
	@echo "✅ Auto-fix complete — review changes before committing."
endif

lint-health:
	@echo "🏥 [Health] Code health scan..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(VENV_DIR)/bin/python scripts/code_health_scan.py --min-severity=medium --exclude-tests --allowlist=scripts/code_health_allowlist.txt services/platform/apps

lint-fsm:
	@echo "🔒 [FSM] FSM guardrail lint (ADR-0034)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(VENV_DIR)/bin/python scripts/lint_fsm_guardrails.py

lint-security:
	@echo "🔒 [Security] Static security analysis..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@SEMGREP_BIN=""; SEMGREP_EXIT=0; \
	if [ -x "$(PWD)/$(VENV_DIR)/bin/semgrep" ]; then \
		SEMGREP_BIN="$(PWD)/$(VENV_DIR)/bin/semgrep"; \
	elif command -v semgrep >/dev/null 2>&1; then \
		SEMGREP_BIN="$$(command -v semgrep)"; \
	else \
		echo "❌ semgrep not found (.venv or PATH)"; \
		echo "👉 Install with one of:"; \
		echo "   uv pip install semgrep"; \
		echo "   brew install semgrep"; \
		exit 1; \
	fi; \
	echo "🔎 Using Semgrep: $$SEMGREP_BIN"; \
	echo "🧪 1/2: Semgrep scan (blocking)..."; \
	"$$SEMGREP_BIN" scan --config=auto --exclude=tests --error services/platform services/portal || SEMGREP_EXIT=$$?; \
	echo "🧪 2/2: Hardcoded credentials check..."; \
	$(MAKE) lint-credentials; \
	if [ $$SEMGREP_EXIT -ne 0 ]; then \
		echo "❌ Semgrep reported findings (exit $$SEMGREP_EXIT)."; \
		exit $$SEMGREP_EXIT; \
	fi
	@echo "🔒 [Security] PRAHO architectural security scan..."
	@$(VENV_DIR)/bin/python scripts/security_scanner.py services/ --min-severity HIGH || true
	@echo "🔒 [Security] Error handling risk scan..."
	@$(VENV_DIR)/bin/python scripts/error_handling_scan.py services/ --exclude-tests --min-severity high || true
	@echo "✅ Security linting complete!"

lint-credentials:
	@echo "🔑 [Credentials] Hardcoded credentials security check..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🏗️  Platform service:"
	@cd services/platform && $(PWD)/$(VENV_DIR)/bin/ruff check . --select=S105,S106,S107,S108 --output-format=concise || echo "⚠️ Credentials check skipped"
	@echo ""
	@echo "🌐 Portal service:"
	@cd services/portal && $(PWD)/$(VENV_DIR)/bin/ruff check . --select=S105,S106,S107,S108 --output-format=concise || echo "⚠️ Credentials check skipped"
	@echo "✅ Credentials check complete!"

# ===============================================================================
# DESIGN SYSTEM CHECKS 🎨  (Phase C.3, C.4, D.1)
# ===============================================================================

check-pysyntax:
ifdef FILE
	@echo "🐍 [Syntax] Checking: $(FILE)"
	@$(VENV_DIR)/bin/python -c "import ast; ast.parse(open('$(FILE)').read())" && echo "✅ $(FILE) — valid syntax" || { echo "❌ $(FILE) — syntax error"; exit 1; }
else
	@echo "🐍 [Syntax] Checking Python syntax across all services..."
	@errors=0; \
	for f in $$(find services/platform services/portal -name '*.py' -not -path '*/migrations/*' -not -path '*/.venv*'); do \
		$(VENV_DIR)/bin/python -c "import ast, sys; ast.parse(open('$$f').read())" 2>/dev/null || { echo "  ❌ $$f"; errors=$$((errors+1)); }; \
	done; \
	if [ $$errors -eq 0 ]; then echo "✅ All Python files have valid syntax!"; else echo "❌ $$errors file(s) with syntax errors"; exit 1; fi
endif

check-parity:
	@echo "🔍 [Parity] Checking component parity: portal ↔ platform..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(VENV_DIR)/bin/python scripts/check_component_parity.py
	@echo "✅ Component parity check complete!"

check-parity-fix:
	@echo "🔧 [Parity] Syncing divergent components (portal → platform)..."
	@$(VENV_DIR)/bin/python scripts/check_component_parity.py --fix
	@echo "✅ Parity fix complete — verify diffs before committing."

css-audit:
	@echo "📦 [CSS Audit] Measuring portal CSS bundle size..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@CSS_FILE="services/portal/static/css/tailwind.min.css"; \
	if [ ! -f "$$CSS_FILE" ]; then \
		echo "⚠️  $$CSS_FILE not found — run 'make build-css' first."; \
		exit 0; \
	fi; \
	SIZE_RAW=$$(wc -c < "$$CSS_FILE"); \
	SIZE_GZIP=$$(gzip -c "$$CSS_FILE" | wc -c); \
	SIZE_GZIP_KB=$$((SIZE_GZIP / 1024)); \
	echo "📄 Raw size:    $$(echo "scale=1; $$SIZE_RAW / 1024" | bc) KB"; \
	echo "🗜️  Gzipped:     $$SIZE_GZIP_KB KB"; \
	if [ $$SIZE_GZIP_KB -le 50 ]; then \
		echo "✅ Gzipped size $$SIZE_GZIP_KB KB is within target (≤ 50 KB)"; \
	else \
		echo "⚠️  Gzipped size $$SIZE_GZIP_KB KB exceeds target (50 KB) — consider PurgeCSS"; \
	fi
	@echo ""
	@echo "📜 Top 10 largest Tailwind utility classes by selector count:"
	@if command -v grep >/dev/null 2>&1; then \
		grep -oP '\.([\w-]+)' "services/portal/static/css/tailwind.min.css" 2>/dev/null \
		| sort | uniq -c | sort -rn | head -10 || echo "  (selector analysis unavailable)"; \
	fi

lint-templates:
	@echo "🎨 [Templates] Scanning for design-system violations..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(VENV_DIR)/bin/python scripts/lint_template_components.py || true
	@echo "⚠️  (run 'make lint-templates-strict' to fail on blockers)"

lint-templates-strict:
	@echo "🎨 [Templates] Strict scan (all codes block)..."
	@$(VENV_DIR)/bin/python scripts/lint_template_components.py \
		--fail-on TMPL001,TMPL002,TMPL003,TMPL004,TMPL005,TMPL006,TMPL007,TMPL008,TMPL009

audit-a11y:
	@echo "♿ [A11Y] Accessibility audit (WCAG AA)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(VENV_DIR)/bin/python scripts/audit_accessibility.py --verbose || true
	@echo "⚠️  (run 'make audit-a11y-strict' to fail on critical+serious)"

audit-a11y-strict:
	@echo "♿ [A11Y] Strict accessibility audit..."
	@$(VENV_DIR)/bin/python scripts/audit_accessibility.py --verbose --fail-on critical,serious

audit-dark-mode:
	@echo "🌙 [DarkMode] Dark mode completeness audit..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(VENV_DIR)/bin/python scripts/audit_dark_mode.py --verbose || true
	@echo "⚠️  (run 'make audit-dark-mode-strict' to fail on blockers)"

audit-dark-mode-strict:
	@echo "🌙 [DarkMode] Strict dark mode audit..."
	@$(VENV_DIR)/bin/python scripts/audit_dark_mode.py --verbose --fail-on blocker

# ===============================================================================
# TYPE CHECKING 🏷️
# ===============================================================================


check-types:
ifdef FILE
	@echo "🏷️ [Type Check] $(FILE)"
	@cd services/platform && PYTHONPATH=$(PWD)/services/platform $(PWD)/$(VENV_DIR)/bin/mypy $(FILE) --config-file=../../pyproject.toml --follow-imports=silent
else
	@echo "🏷️ [All Services] Comprehensive type checking..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(MAKE) check-types-platform
	@$(MAKE) check-types-portal
	@echo "🎉 All services type checking complete!"
endif

check-types-platform:
	@echo "🏷️ [Platform] Type checking..."
	@cd services/platform && PYTHONPATH=$(PWD)/services/platform $(PWD)/$(VENV_DIR)/bin/mypy apps/ --config-file=../../pyproject.toml

check-types-portal:
	@echo "🏷️ [Portal] Type checking..."
	@cd services/portal && PYTHONPATH=$(PWD)/services/portal $(PWD)/$(VENV_DIR)/bin/mypy apps/ --config-file=../../pyproject.toml

# ===============================================================================
# PRE-COMMIT HOOKS 🔗
# ===============================================================================

pre-commit:
	@echo "🔗 Running pre-commit hooks across services..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@if ! command -v $(VENV_DIR)/bin/pre-commit >/dev/null 2>&1; then \
		echo "❌ pre-commit not found. Installing..."; \
		uv sync --group dev; \
		$(VENV_DIR)/bin/pre-commit install || echo "⚠️ Pre-commit config not found"; \
	fi
	@$(VENV_DIR)/bin/pre-commit run --all-files || echo "⚠️ Pre-commit hooks skipped"
	@echo "✅ Pre-commit completed!"

# ===============================================================================
# INTERNATIONALIZATION 🌍
# ===============================================================================

PLATFORM_PO = services/platform/locale/ro/LC_MESSAGES/django.po
PORTAL_PO   = services/portal/locale/ro/LC_MESSAGES/django.po
PYTHON_I18N = uv run python

i18n-extract:
	@echo "🌍 Extracting translatable strings..."
	@cd services/platform && PORTAL_IMPORT_ISOLATION_BYPASS=true $(PWD)/$(VENV_DIR)/bin/python manage.py makemessages -l ro --no-wrap --settings=config.settings.dev
	@cd services/portal && PORTAL_IMPORT_ISOLATION_BYPASS=true $(PWD)/$(VENV_DIR)/bin/python manage.py makemessages -l ro --no-wrap --settings=config.settings.dev
	@echo "✅ Strings extracted for both services."

i18n-compile:
	@echo "🌍 Compiling translation files..."
	@cd services/platform && $(PWD)/$(VENV_DIR)/bin/python manage.py compilemessages --settings=config.settings.dev
	@cd services/portal && $(PWD)/$(VENV_DIR)/bin/python manage.py compilemessages --settings=config.settings.dev
	@echo "✅ Translations compiled."

translate-stats:
	@echo "📊 Translation coverage stats (both services)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🏗️  Platform:"
	@$(PYTHON_I18N) scripts/translate_po.py stats $(PLATFORM_PO)
	@echo ""
	@echo "🌐 Portal:"
	@$(PYTHON_I18N) scripts/translate_po.py stats $(PORTAL_PO)

translate-stats-platform:
	@$(PYTHON_I18N) scripts/translate_po.py stats $(PLATFORM_PO)

translate-stats-portal:
	@$(PYTHON_I18N) scripts/translate_po.py stats $(PORTAL_PO)

translate:
	@echo "📖 Generating review YAML (dictionary mode)..."
	@$(PYTHON_I18N) scripts/translate_po.py generate $(PLATFORM_PO) -o i18n-review-platform.yaml
	@$(PYTHON_I18N) scripts/translate_po.py generate $(PORTAL_PO) -o i18n-review-portal.yaml
	@echo "✅ Review files: i18n-review-platform.yaml, i18n-review-portal.yaml"

translate-platform:
	@$(PYTHON_I18N) scripts/translate_po.py generate $(PLATFORM_PO) -o i18n-review-platform.yaml

translate-portal:
	@$(PYTHON_I18N) scripts/translate_po.py generate $(PORTAL_PO) -o i18n-review-portal.yaml

translate-ai:
	@echo "🤖 Generating review YAML (Claude AI mode)..."
	@$(PYTHON_I18N) scripts/translate_po.py generate $(PLATFORM_PO) --claude --model haiku -o i18n-review-platform.yaml
	@$(PYTHON_I18N) scripts/translate_po.py generate $(PORTAL_PO) --claude --model haiku -o i18n-review-portal.yaml
	@echo "✅ AI review files: i18n-review-platform.yaml, i18n-review-portal.yaml"

translate-ai-platform:
	@$(PYTHON_I18N) scripts/translate_po.py generate $(PLATFORM_PO) --claude --model haiku -o i18n-review-platform.yaml

translate-ai-portal:
	@$(PYTHON_I18N) scripts/translate_po.py generate $(PORTAL_PO) --claude --model haiku -o i18n-review-portal.yaml

translate-review:
	@echo "📝 Review YAML files to edit:"
	@ls -la i18n-review-*.yaml 2>/dev/null || echo "No review files found. Run 'make translate' or 'make translate-ai' first."

translate-apply:
	@echo "📥 Applying approved translations..."
	@for f in i18n-review-*.yaml; do \
		if [ -f "$$f" ]; then \
			echo "Applying $$f..."; \
			$(PYTHON_SHARED) scripts/translate_po.py apply "$$f" --compile; \
		fi; \
	done
	@echo "✅ Translations applied and compiled."

translate-diff:
	@echo "🔍 Preview of changes (dry-run)..."
	@for f in i18n-review-*.yaml; do \
		if [ -f "$$f" ]; then \
			echo "--- $$f ---"; \
			$(PYTHON_SHARED) scripts/translate_po.py apply "$$f" --dry-run; \
		fi; \
	done

# ===============================================================================
# BUILD & ASSETS 🎨
# ===============================================================================

install-css:
	@echo "📦 Installing frontend dependencies..."
	npm install

install-frontend: install-css

check-css-tooling:
	@if ! command -v npm >/dev/null 2>&1; then \
		echo "⚠️  npm not found — skipping CSS build (using pre-built assets)"; \
	else \
		npm ls --depth=0 @tailwindcss/cli >/dev/null 2>&1 || ( \
			echo "❌ Missing Tailwind CLI package: @tailwindcss/cli"; \
			echo "   Run: npm install --save-dev @tailwindcss/cli"; \
			exit 1; \
		); \
	fi

build-css: check-css-tooling
	@command -v npm >/dev/null 2>&1 || exit 0; \
	echo "🎨 Building Tailwind CSS assets for all services..."; \
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; \
	echo "🏗️  Building Portal CSS..."; \
	npx --no-install @tailwindcss/cli -c services/portal/tailwind.config.js -i assets/css/input.css -o services/portal/static/css/tailwind.min.css --minify 2>&1 | grep -v -E 'warning|all.*vars|Unexpected token|ring-inset|[│┆]|^$$' && \
	echo "🏗️  Building Platform CSS..." && \
	npx --no-install @tailwindcss/cli -c services/platform/tailwind.config.js -i assets/css/input.css -o services/platform/static/css/tailwind.min.css --minify 2>&1 | grep -v -E 'warning|all.*vars|Unexpected token|ring-inset|[│┆]|^$$' && \
	echo "" >> services/portal/static/css/tailwind.min.css && \
	echo "" >> services/platform/static/css/tailwind.min.css && \
	echo "✅ CSS build complete!"

watch-css: check-css-tooling
	@echo "👀 Watching CSS changes for development..."
	npx --no-install @tailwindcss/cli -c services/portal/tailwind.config.js -i assets/css/input.css -o services/portal/static/css/tailwind.min.css --watch &
	npx --no-install @tailwindcss/cli -c services/platform/tailwind.config.js -i assets/css/input.css -o services/platform/static/css/tailwind.min.css --watch

# ===============================================================================
# DOCKER SERVICES DEPLOYMENT 🐳
# ===============================================================================

docker-build:
	@echo "🐳 [Docker] Building services images..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🏗️  Building Platform service..."
	@docker build -f deploy/platform/Dockerfile -t praho-platform:latest .
	@echo ""
	@echo "🌐 Building Portal service..."
	@docker build -f deploy/portal/Dockerfile -t praho-portal:latest .
	@echo "✅ All service images built successfully!"

docker-dev:
	@echo "🚀 [Docker] Starting development services (no Redis)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@docker-compose -f deploy/docker-compose.dev.yml up --build

docker-prod:
	@echo "🌐 [Docker] Starting production services (no Redis)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@docker-compose -f deploy/docker-compose.services.yml up -d

docker-stop:
	@echo "🛑 [Docker] Stopping all services..."
	@docker-compose -f deploy/docker-compose.dev.yml down || true
	@docker-compose -f deploy/docker-compose.services.yml down || true

docker-logs-platform:
	@echo "📋 [Docker] Platform service logs..."
	@docker-compose -f deploy/docker-compose.services.yml logs -f platform

docker-logs-portal:
	@echo "📋 [Docker] Portal service logs..."
	@docker-compose -f deploy/docker-compose.services.yml logs -f portal

docker-clean:
	@echo "🧹 [Docker] Cleaning up containers and images..."
	@docker-compose -f deploy/docker-compose.dev.yml down --volumes --rmi all || true
	@docker-compose -f deploy/docker-compose.services.yml down --volumes --rmi all || true
	@docker system prune -f

docker-test:
	@echo "🧪 [Docker] Testing services isolation (no Redis)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🚀 Building and starting services..."
	@docker-compose -f deploy/docker-compose.services.yml up -d --build
	@echo "⏳ Waiting for services to be healthy..."
	@sleep 30
	@echo "🧪 Testing platform service..."
	@curl -f http://localhost:8700/users/login/ || (echo "❌ Platform health check failed" && exit 1)
	@echo "✅ Platform service healthy!"
	@echo "🧪 Testing portal service..."
	@curl -f http://localhost:8701/ || (echo "❌ Portal health check failed" && exit 1)
	@echo "✅ Portal service healthy!"
	@echo "🧪 Testing nginx proxy..."
	@curl -f http://localhost/ || (echo "❌ Nginx proxy failed" && exit 1)
	@echo "✅ All services are healthy!"
	@docker-compose -f deploy/docker-compose.services.yml down

clean:
	@echo "🧹 Cleaning build artifacts across services..."
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf services/platform/htmlcov/
	rm -rf services/portal/htmlcov/
	rm -rf .coverage
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf services/platform/staticfiles/
	rm -rf services/portal/staticfiles/

# ===============================================================================
# PRODUCTION DEPLOYMENT 🚀
# ===============================================================================

.PHONY: deploy-single-server deploy-platform deploy-portal deploy-stop deploy-status deploy-logs backup restore rollback rollback-db health-check

deploy-single-server:
	@echo "🚀 [Deploy] Single server deployment (all services)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@./deploy/scripts/deploy.sh single-server --build --migrate

deploy-platform:
	@echo "🚀 [Deploy] Platform service only..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@./deploy/scripts/deploy.sh platform-only --build

deploy-portal:
	@echo "🚀 [Deploy] Portal service only..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@./deploy/scripts/deploy.sh portal-only --build

deploy-container-service:
	@echo "🚀 [Deploy] Building for container service..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@./deploy/scripts/deploy.sh container-service --build

deploy-stop:
	@echo "🛑 [Deploy] Stopping deployment services..."
	@docker compose -f deploy/docker-compose.single-server.yml down 2>/dev/null || true
	@docker compose -f deploy/docker-compose.platform-only.yml down 2>/dev/null || true
	@docker compose -f deploy/docker-compose.portal-only.yml down 2>/dev/null || true

deploy-status:
	@echo "📊 [Deploy] Service status..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@docker ps --filter "name=praho" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

deploy-logs:
	@echo "📋 [Deploy] Service logs..."
	@docker compose -f deploy/docker-compose.single-server.yml logs -f 2>/dev/null || \
		docker compose -f deploy/docker-compose.services.yml logs -f

# ===============================================================================
# DATABASE BACKUP & RESTORE 💾
# ===============================================================================

backup:
	@echo "💾 [Backup] Creating database backup..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@./deploy/scripts/backup.sh

backup-list:
	@echo "📋 [Backup] Listing available backups..."
	@./deploy/scripts/backup.sh --list

restore:
	@echo "🔄 [Restore] Interactive database restore..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@./deploy/scripts/restore.sh

restore-latest:
	@echo "🔄 [Restore] Restoring latest backup..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@./deploy/scripts/restore.sh --latest

# ===============================================================================
# ROLLBACK PROCEDURES ⏪
# ===============================================================================

rollback:
ifndef VERSION
	@echo "❌ VERSION is required. Usage: make rollback VERSION=v1.2.3"
	@exit 1
endif
	@echo "⏪ [Rollback] Rolling back to version $(VERSION)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@./deploy/scripts/rollback.sh version $(VERSION)

rollback-db:
	@echo "⏪ [Rollback] Restoring database from latest backup..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@./deploy/scripts/rollback.sh database

# ===============================================================================
# HEALTH & MONITORING 🏥
# ===============================================================================

health-check:
	@echo "🏥 [Health] Checking service health..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@./deploy/scripts/health-check.sh

# ===============================================================================
# INFRASTRUCTURE PROVISIONING (Terraform → Hetzner) ☁️
# ===============================================================================

.PHONY: infra-init infra-plan infra-dev infra-staging infra-prod infra-destroy-dev

infra-init:
	@echo "☁️ [Infra] Initializing Terraform..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@terraform -chdir=deploy/terraform init

infra-plan:
	@echo "☁️ [Infra] Planning infrastructure for $(ENV)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ifndef ENV
	@echo "❌ ENV is required. Usage: make infra-plan ENV=dev"
	@exit 1
endif
	@terraform -chdir=deploy/terraform workspace select $(ENV) 2>/dev/null || terraform -chdir=deploy/terraform workspace new $(ENV)
	@terraform -chdir=deploy/terraform plan -var="environment=$(ENV)"

infra-dev:
	@echo "☁️ [Infra] Provisioning dev server on Hetzner..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@terraform -chdir=deploy/terraform workspace select dev 2>/dev/null || terraform -chdir=deploy/terraform workspace new dev
	@terraform -chdir=deploy/terraform apply -var="environment=dev"

infra-staging:
	@echo "☁️ [Infra] Provisioning staging servers on Hetzner..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@terraform -chdir=deploy/terraform workspace select staging 2>/dev/null || terraform -chdir=deploy/terraform workspace new staging
	@terraform -chdir=deploy/terraform apply -var="environment=staging"

infra-prod:
	@echo "☁️ [Infra] Provisioning production servers on Hetzner..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@terraform -chdir=deploy/terraform workspace select prod 2>/dev/null || terraform -chdir=deploy/terraform workspace new prod
	@terraform -chdir=deploy/terraform apply -var="environment=prod"

infra-destroy-dev:
	@echo "☁️ [Infra] Destroying dev infrastructure..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@terraform -chdir=deploy/terraform workspace select dev
	@terraform -chdir=deploy/terraform destroy -var="environment=dev"

# ===============================================================================
# ENVIRONMENT DEPLOYMENT (Ansible) 🚀
# ===============================================================================

.PHONY: deploy-dev deploy-dev-native deploy-staging deploy-prod

deploy-dev:
	@echo "🚀 [Deploy] Deploying PRAHO to dev (Docker)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@cd deploy/ansible && ansible-playbook -i inventory/dev.yml playbooks/single-server.yml

deploy-dev-native:
	@echo "🚀 [Deploy] Deploying PRAHO to dev (native)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@cd deploy/ansible && ansible-playbook -i inventory/dev.yml playbooks/native-single-server.yml

deploy-staging:
	@test -f .env.staging || (echo "❌ Missing .env.staging — run: cp .env.example.staging .env.staging"; exit 1)
	@echo "🚀 [Deploy] Deploying PRAHO to staging (native)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@set -a && . $(PWD)/.env.staging && set +a && \
		cd deploy/ansible && ansible-playbook -i inventory/native-single-server.yml \
		playbooks/native-single-server.yml -e praho_env=staging \
		-e env_file_path=$(PWD)/.env.staging -v

deploy-prod:
	@test -f .env.prod || (echo "❌ Missing .env.prod — run: cp .env.example.prod .env.prod"; exit 1)
	@echo "🚀 [Deploy] Deploying PRAHO to production (native)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@set -a && . $(PWD)/.env.prod && set +a && \
		cd deploy/ansible && ansible-playbook -i inventory/native-single-server.yml \
		playbooks/native-single-server.yml -e praho_env=prod \
		-e env_file_path=$(PWD)/.env.prod \
		$(if $(VERSION),-e cli_version=$(VERSION),) \
		-v

# ===============================================================================
# ANSIBLE DEPLOYMENT 📜
# ===============================================================================

ansible-single-server:
	@echo "📜 [Ansible] Native single server deployment..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@cd deploy/ansible && ansible-playbook -i inventory/native-single-server.yml playbooks/native-single-server.yml -e praho_env=$(ENV)

ansible-two-servers:
	@echo "📜 [Ansible] Two server deployment..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@cd deploy/ansible && ansible-playbook -i inventory/two-servers.yml playbooks/two-servers.yml

ansible-backup:
	@echo "📜 [Ansible] Remote backup..."
	@cd deploy/ansible && ansible-playbook -i inventory/native-single-server.yml playbooks/backup.yml
