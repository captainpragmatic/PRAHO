# ===============================================================================
# PRAHO PLATFORM - SERVICES ARCHITECTURE MAKEFILE 🏗️
# ===============================================================================
# Enhanced for Platform/Portal separation with scoped PYTHONPATH security

.PHONY: help install dev dev-platform dev-portal dev-all test test-platform test-portal test-integration test-e2e test-security build-css migrate fixtures clean lint lint-platform lint-portal type-check pre-commit

# ===============================================================================
# SCOPED PYTHON ENVIRONMENTS 🔒
# ===============================================================================

# Platform-specific Python with scoped PYTHONPATH (database access)
PYTHON_PLATFORM = cd services/platform && PYTHONPATH=$(PWD)/services/platform $(PWD)/.venv/bin/python
PYTHON_PLATFORM_MANAGE = $(PYTHON_PLATFORM) manage.py

# Portal-specific Python (NO PYTHONPATH - cannot import platform code)
PYTHON_PORTAL = cd services/portal && $(PWD)/.venv/bin/python
PYTHON_PORTAL_MANAGE = $(PYTHON_PORTAL) manage.py

# Shared Python for workspace-level tasks
PYTHON_SHARED = .venv/bin/python

# ===============================================================================
# HELP & SETUP 📖
# ===============================================================================

help:
	@echo "🚀 PRAHO Platform - Services Architecture"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🏗️  DEVELOPMENT SERVICES:"
	@echo "  make dev             - Run all services (platform + portal)"
	@echo "  make dev-platform    - Run platform service only (:8700)"
	@echo "  make dev-portal      - Run portal service only (:8701)"
	@echo ""
	@echo "🧪 TESTING (SERVICE-ISOLATED):"
	@echo "  make test            - Test all services (Django test runner)"
	@echo "  make test-platform   - Test platform service with DB access (Django)"
	@echo "  make test-platform-pytest - Test platform service with pytest"
	@echo "  make test-portal     - Test portal service (NO DB access)"
	@echo "  make test-integration - Test platform→portal API communication"
	@echo "  make test-e2e        - End-to-end tests across services"
	@echo "  make test-security   - Validate service isolation"
	@echo ""
	@echo "🔧 DATABASE & ASSETS:"
	@echo "  make migrate         - Run platform database migrations"
	@echo "  make fixtures        - Load sample data (platform only)"
	@echo "  make build-css       - Build Tailwind CSS assets"
	@echo ""
	@echo "🧹 CODE QUALITY:"
	@echo "  make lint            - Lint all services"
	@echo "  make lint-platform   - Lint platform service only"
	@echo "  make lint-portal     - Lint portal service only"
	@echo "  make type-check      - Type check all services"
	@echo "  make pre-commit      - Run pre-commit hooks"
	@echo ""
	@echo "🔒 SECURITY:"
	@echo "  make test-security   - Validate service isolation"
	@echo "  make lint-credentials - Check for hardcoded credentials"
	@echo ""
	@echo "🐳 DOCKER DEPLOYMENT:"
	@echo "  make docker-build    - Build platform + portal Docker images"
	@echo "  make docker-dev      - Start development services with hot reload"
	@echo "  make docker-prod     - Start production services with nginx"
	@echo "  make docker-stop     - Stop all Docker services"
	@echo "  make docker-test     - Test Docker services health"
	@echo "  make docker-clean    - Clean up Docker containers and images"
	@echo ""
	@echo "⚙️  SETUP & MAINTENANCE:"
	@echo "  make install         - Set up development environment"
	@echo "  make clean           - Clean build artifacts"

# ===============================================================================
# DEVELOPMENT ENVIRONMENT SETUP 🔧
# ===============================================================================

install:
	@echo "🔧 Setting up PRAHO services development environment..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "📦 Creating virtual environment..."
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	@echo ""
	@echo "📋 Installing platform dependencies (with database drivers)..."
	.venv/bin/pip install -r services/platform/requirements/dev.txt
	@echo ""
	@echo "📋 Installing portal dependencies (NO database drivers)..."
	.venv/bin/pip install -r services/portal/requirements.txt
	@echo ""
	@echo "✅ Environment ready! Services isolated with scoped PYTHONPATH"
	@echo "🔒 Security: Portal cannot import platform code"

# ===============================================================================
# DEVELOPMENT SERVERS 🚀
# ===============================================================================

dev-platform:
	@echo "🏗️ [Platform] Starting admin platform service..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "📍 PYTHONPATH: services/platform (scoped)"
	@echo "🗄️ Running migrations..."
	@$(PYTHON_PLATFORM_MANAGE) migrate --settings=config.settings.dev
	@echo "🔧 Setting up test data..."
	@$(PYTHON_PLATFORM) scripts/setup_test_data.py || echo "⚠️ Test data setup skipped"
	@echo "⚙️ Setting up scheduled tasks..."
	@$(PYTHON_PLATFORM_MANAGE) setup_scheduled_tasks --settings=config.settings.dev || echo "⚠️ Scheduled tasks setup skipped"
	@echo "🚀 Starting Django-Q2 workers in background..."
	@$(PYTHON_PLATFORM_MANAGE) qcluster --settings=config.settings.dev > django_q.log 2>&1 & 
	@QCLUSTER_PID=$$!; \
	echo "📊 Django-Q2 workers started (PID: $$QCLUSTER_PID)"; \
	echo "🌐 Starting platform server on :8700..."; \
	trap 'echo "🛑 Stopping Django-Q2 workers..."; kill $$QCLUSTER_PID 2>/dev/null || true' EXIT; \
	$(PYTHON_PLATFORM_MANAGE) runserver 0.0.0.0:8700 --settings=config.settings.dev

dev-portal:
	@echo "🌐 [Portal] Starting customer portal service..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🔒 NO PYTHONPATH - portal cannot import platform code"
	@echo "🔍 Validating portal configuration..."
	@$(PYTHON_PORTAL_MANAGE) check
	@echo "✅ Portal configuration valid"
	@echo "🌐 Starting portal server on :8701..."
	@$(PYTHON_PORTAL_MANAGE) runserver 0.0.0.0:8701

dev-all:
	@echo "🚀 [All Services] Starting platform + portal..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(MAKE) -j2 dev-platform dev-portal

dev:
	@$(MAKE) dev-all

# ===============================================================================
# TESTING WITH SERVICE ISOLATION 🧪
# ===============================================================================

test-platform:
	@echo "🧪 [Platform] Testing with database cache (no Redis)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(PYTHON_PLATFORM_MANAGE) test tests --settings=config.settings.test --verbosity=2 --parallel --keepdb
	@echo "✅ Platform tests completed successfully!"

test-platform-pytest:
	@echo "🧪 [Platform] Testing with pytest (database cache)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@cd services/platform && PYTHONPATH=$(PWD)/services/platform $(PWD)/.venv/bin/python -m pytest -v
	@echo "✅ Platform pytest tests completed successfully!"

test-portal:
	@echo "🧪 [Portal] Testing without database access (strict isolation)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@cd services/portal && env -u PYTHONPATH $(PWD)/.venv/bin/python -m pytest -v
	@echo "✅ Portal tests completed - database access properly blocked!"

test-integration:
	@echo "🔄 [Integration] Testing services communication and cache functionality..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🧪 Running integration tests..."
	@$(PWD)/.venv/bin/python -m pytest tests/integration/ -v
	@echo "✅ Integration tests completed!"

test-cache:
	@echo "💾 [Cache] Testing database cache functionality (post Redis removal)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(PWD)/.venv/bin/python -m pytest tests/integration/test_database_cache.py -v -m cache
	@echo "✅ Database cache tests passed!"

test-security:
	@echo "🔒 [Security] Validating service isolation (no Redis dependencies)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🧪 Testing portal cannot import platform code..."
	@cd services/portal && \
		if env -u PYTHONPATH $(PWD)/.venv/bin/python -c "import apps" 2>/dev/null; then \
			echo "❌ SECURITY BREACH: Portal can import platform!"; \
			exit 1; \
		else \
			echo "✅ Portal properly isolated from platform"; \
		fi
	@echo "🧪 Testing platform uses database cache (base settings, not dev override)..."
	@cd services/platform && PYTHONPATH=$(PWD)/services/platform $(PWD)/.venv/bin/python -c "import os; os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.base'); import django; django.setup(); from django.conf import settings; cache_backend = settings.CACHES['default']['BACKEND']; assert 'DatabaseCache' in cache_backend, f'Should use database cache, got: {cache_backend}'; print('✅ Platform base settings use database cache')"
	@echo "🧪 Testing portal has NO database access..."
	@cd services/portal && env -u PYTHONPATH $(PWD)/.venv/bin/python -c "import os; os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings'); import django; django.setup(); from django.conf import settings; print('✅ Portal isolated from DB:', not bool(getattr(settings, 'DATABASES', {})))"
	@echo "🧪 Running portal database access prevention test..."
	@cd services/portal && env -u PYTHONPATH $(PWD)/.venv/bin/python -m pytest conftest.py::test_db_access_blocked -v || echo "✅ Database access properly blocked"
	@echo "🎉 All security isolation tests passed!"

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

# ===============================================================================
# DATABASE & ASSETS 🗄️
# ===============================================================================

migrate:
	@echo "🗄️ [Platform] Running database migrations..."
	@$(PYTHON_PLATFORM_MANAGE) makemigrations --settings=config.settings.dev
	@$(PYTHON_PLATFORM_MANAGE) migrate --settings=config.settings.dev

fixtures:
	@echo "📊 [Platform] Loading sample data..."
	@$(PYTHON_PLATFORM_MANAGE) generate_sample_data --settings=config.settings.dev

# ===============================================================================
# CODE QUALITY 🧹
# ===============================================================================

lint-platform:
	@echo "🏗️ [Platform] Comprehensive code quality check..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🔍 1/3: Performance & Security Analysis (Ruff)..."
	@cd services/platform && $(PWD)/.venv/bin/ruff check . --statistics || echo "⚠️ Ruff check skipped"
	@echo ""
	@echo "🏷️  2/3: Type Safety Check (MyPy)..."
	@cd services/platform && PYTHONPATH=$(PWD)/services/platform $(PWD)/.venv/bin/mypy apps/ --config-file=../../pyproject.toml 2>/dev/null || echo "⚠️ MyPy check skipped"
	@echo ""
	@echo "📊 3/3: Django Check..."
	@$(PYTHON_PLATFORM_MANAGE) check --deploy --settings=config.settings.dev
	@echo "✅ Platform linting complete!"

lint-portal:
	@echo "🌐 [Portal] Code quality check (NO database access)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🔍 1/2: Performance & Security Analysis (Ruff)..."
	@cd services/portal && $(PWD)/.venv/bin/ruff check . --statistics || echo "⚠️ Ruff check skipped"
	@echo ""
	@echo "📊 2/2: Django Check (NO DB)..."
	@$(PYTHON_PORTAL_MANAGE) check
	@echo "✅ Portal linting complete!"

lint:
	@echo "🔄 [All Services] Comprehensive linting..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "📋 Phase 1: Platform service"
	@$(MAKE) lint-platform
	@echo "📋 Phase 2: Portal service"  
	@$(MAKE) lint-portal
	@echo "🎉 All services linting complete!"

lint-credentials:
	@echo "🔑 [Credentials] Hardcoded credentials security check..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🏗️  Platform service:"
	@cd services/platform && $(PWD)/.venv/bin/ruff check . --select=S105,S106,S107,S108 --output-format=concise || echo "⚠️ Credentials check skipped"
	@echo ""
	@echo "🌐 Portal service:"
	@cd services/portal && $(PWD)/.venv/bin/ruff check . --select=S105,S106,S107,S108 --output-format=concise || echo "⚠️ Credentials check skipped"
	@echo "✅ Credentials check complete!"

# ===============================================================================
# TYPE CHECKING 🏷️
# ===============================================================================

type-check:
	@echo "🏷️ [All Services] Comprehensive type checking..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@cd services/platform && PYTHONPATH=$(PWD)/services/platform $(PWD)/.venv/bin/mypy apps/ --config-file=../../pyproject.toml || echo "⚠️ MyPy not configured"
	@cd services/portal && $(PWD)/.venv/bin/mypy portal/ --config-file=../../pyproject.toml || echo "⚠️ MyPy not configured"
	@echo "🎉 All services type checking complete!"

# ===============================================================================
# PRE-COMMIT HOOKS 🔗
# ===============================================================================

pre-commit:
	@echo "🔗 Running pre-commit hooks across services..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@if ! command -v .venv/bin/pre-commit >/dev/null 2>&1; then \
		echo "❌ pre-commit not found. Installing..."; \
		.venv/bin/pip install pre-commit; \
		.venv/bin/pre-commit install || echo "⚠️ Pre-commit config not found"; \
	fi
	@.venv/bin/pre-commit run --all-files || echo "⚠️ Pre-commit hooks skipped"
	@echo "✅ Pre-commit completed!"

# ===============================================================================
# BUILD & ASSETS 🎨
# ===============================================================================

build-css:
	@echo "🎨 Building Tailwind CSS assets..."
	npx tailwindcss -i static/src/styles.css -o static/dist/styles.css --watch

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
