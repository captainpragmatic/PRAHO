# ===============================================================================
# PRAHO PLATFORM - DEVELOPMENT MAKEFILE (Updated for Django Test Runner)
# ===============================================================================

.PHONY: help install dev test test-e2e test-with-e2e test-coverage test-fast test-file build-css migrate fixtures clean lint type-check type-coverage type-check-modified

# Default target
help:
	@echo "🚀 PRAHO Platform - Romanian Hosting Provider"
	@echo "Available commands:"
	@echo "  make install         - Set up development environment"
	@echo "  make dev             - Run development server"
	@echo "  make test            - Run all tests (Django runner) - DEFAULT"
	@echo "  make test-e2e        - Run E2E tests with pytest-playwright"
	@echo "  make test-with-e2e   - Run all tests including E2E"
	@echo "  make test-coverage   - Run tests with coverage report"
	@echo "  make test-fast       - Run tests with minimal output"
	@echo "  make test-prod       - Run production tests with PostgreSQL"
	@echo "  make test-all        - Run both Django and pytest suites"
	@echo "  make test-file FILE=<module> - Run specific test file"
	@echo "  make build-css       - Build Tailwind CSS"
	@echo "  make migrate         - Run database migrations"
	@echo "  make fixtures        - Load sample data"
	@echo "  make clean           - Clean build artifacts"
	@echo "  make lint            - Run code quality checks"
	@echo "  make fix-templates   - Fix Django template syntax issues"
	@echo "  make check-templates - Check for template syntax issues"
	@echo "  make check-ide-settings - Verify IDE auto-formatting prevention"

# Development environment setup
install:
	@echo "🔧 Setting up development environment..."
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements/dev.txt
	@echo "✅ Environment ready! Activate with: source .venv/bin/activate"

# Run development server
dev:
	@echo "🚀 Starting development server..."
	@echo "�️ Running migrations..."
	.venv/bin/python manage.py migrate
	@echo "�🔧 Setting up test data if needed..."
	.venv/bin/python scripts/setup_test_data.py
	.venv/bin/python manage.py runserver 0.0.0.0:8001

# Run tests with Django test runner (reliable and fast) - DEFAULT
test:
	@echo "🧪 Running unified test suite with Django runner..."
	.venv/bin/python manage.py test tests --settings=config.settings.test --verbosity=2
	@echo "✅ All tests completed successfully!"

# Run E2E tests with Django and Playwright
test-e2e:
	@echo "🎭 Running E2E tests with pytest-playwright..."
	@echo "🚀 Starting development server in background..."
	@# Kill any existing development servers
	@pkill -f "manage.py runserver" || true
	@# Start the development server in background
	@.venv/bin/python manage.py migrate --settings=config.settings.test > /dev/null 2>&1
	@.venv/bin/python scripts/setup_test_data.py > /dev/null 2>&1 || true
	@.venv/bin/python manage.py runserver 0.0.0.0:8001 > /dev/null 2>&1 & 
	@echo "⏳ Waiting for server to start..."
	@sleep 3
	@# Check if server is responding
	@curl -s -I http://localhost:8001/ | head -1 | grep -q "200\|302" || (echo "❌ Server failed to start" && exit 1)
	@echo "✅ Development server is ready"
	@# Run the E2E tests
	.venv/bin/pytest tests/e2e/ -v --tb=short; \
	TEST_EXIT_CODE=$$?; \
	echo "🛑 Stopping development server..."; \
	pkill -f "manage.py runserver" || true; \
	if [ $$TEST_EXIT_CODE -eq 0 ]; then \
		echo "✅ E2E tests completed successfully!"; \
	else \
		echo "❌ E2E tests failed"; \
		exit $$TEST_EXIT_CODE; \
	fi

# Run all tests including E2E
test-with-e2e:
	@echo "🔄 Running all tests including E2E..."
	@echo "📋 Phase 1: Unit and integration tests"
	@$(MAKE) test
	@echo "📋 Phase 2: End-to-end tests"
	@$(MAKE) test-e2e
	@echo "✅ All tests (including E2E) completed successfully!"

# Run tests with coverage report
test-coverage:
	@echo "📊 Running test suite with coverage..."
	.venv/bin/coverage run --source='apps' manage.py test tests --settings=config.settings.test
	.venv/bin/coverage report --show-missing
	.venv/bin/coverage html
	@echo "📈 Coverage report: htmlcov/index.html"

# Fast test run with minimal output
test-fast:
	@echo "⚡ Running fast test suite..."
	.venv/bin/python manage.py test tests --settings=config.settings.test --verbosity=1

# Production testing with PostgreSQL (for CI/advanced testing)
test-prod:
	@echo "🏭 Running production-style tests with PostgreSQL..."
	@if ! command -v pytest >/dev/null 2>&1; then \
		echo "📦 Installing pytest for production testing..."; \
		.venv/bin/pip install pytest pytest-django pytest-cov; \
	fi
	.venv/bin/pytest tests/ --ds=config.settings.prod -v --tb=short
	@echo "✅ Production tests completed!"

# Full test suite (both Django and pytest)
test-all:
	@echo "🔄 Running comprehensive test suite..."
	@echo "📋 Phase 1: Django test runner (development)"
	@$(MAKE) test
	@echo "📋 Phase 2: pytest with PostgreSQL (production)"
	@$(MAKE) test-prod
	@echo "🎉 All test phases completed!"

# Run specific test file
test-file:
	@echo "🎯 Running specific test file..."
	@if [ -z "$(FILE)" ]; then echo "❌ Please specify FILE=<test_module> (e.g., make test-file FILE=tests.test_customer_user_comprehensive)"; exit 1; fi
	.venv/bin/python manage.py test $(FILE) --settings=config.settings.test --verbosity=2

# Build CSS assets
build-css:
	@echo "🎨 Building Tailwind CSS..."
	npx tailwindcss -i static/src/styles.css -o static/dist/styles.css --watch

# Database migrations
migrate:
	@echo "🗄️ Running database migrations..."
	.venv/bin/python manage.py makemigrations
	.venv/bin/python manage.py migrate

# Load sample data
fixtures:
	@echo "📊 Loading sample data..."
	.venv/bin/python manage.py generate_sample_data

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/

# ===============================================================================
# LINTING & CODE QUALITY - Strategic Business Focus 🧹
# ===============================================================================

.PHONY: lint lint-fix lint-check lint-security lint-credentials lint-performance lint-watch

## lint: Run comprehensive strategic linting (Ruff + MyPy) 🔍
lint:
	@echo "🎯 PRAHO Platform - Strategic Code Quality Check"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🔍 1/3: Performance & Security Analysis..."
	@.venv/bin/ruff check . --statistics
	@echo ""
	@echo "🏷️ 2/3: Type Safety Analysis..."  
	@.venv/bin/mypy apps/ config/ --ignore-missing-imports --show-error-codes
	@echo ""
	@echo "📊 3/3: Django Check..."
	@.venv/bin/python manage.py check --deploy
	@echo "✅ Strategic linting complete! Focus on performance & security issues."

## lint-fix: Auto-fix strategic issues (safe fixes only) 🔧
lint-fix:
	@echo "� Auto-fixing strategic linting issues..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@.venv/bin/ruff check . --fix
	@.venv/bin/ruff format .
	@echo "✅ Auto-fix complete! Review changes before committing."

## lint-check: Check only, no fixes (CI/CD friendly) 🤖
lint-check:
	@echo "🤖 CI/CD Strategic Lint Check..."
	@.venv/bin/ruff check . --no-fix --quiet
	@.venv/bin/mypy apps/ config/ --ignore-missing-imports

## lint-security: Focus on security issues only 🔒
lint-security:
	@echo "🔒 Security-focused linting (including hardcoded credentials)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "⚠️  WARNING: Review all hardcoded credentials below:"
	@echo ""
	@.venv/bin/ruff check . --select=S --statistics
	@echo ""
	@echo "🔍 Focus areas:"
	@echo "  • S105/S106: Hardcoded passwords/secrets (REVIEW REQUIRED)"
	@echo "  • S602/S603: Subprocess security issues"
	@echo "  • S301-S324: Security anti-patterns"

## lint-credentials: Check for hardcoded credentials everywhere 🔑
lint-credentials:
	@echo "🔑 Hardcoded Credentials Security Check"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "⚠️  REVIEWING ALL HARDCODED PASSWORDS & SECRETS:"
	@echo ""
	@.venv/bin/ruff check . --select=S105,S106,S107,S108 --output-format=concise || true
	@echo ""
	@echo "📋 Review Guidelines:"
	@echo "  ✅ Development/Test files: Usually acceptable"
	@echo "  ⚠️  Configuration files: Should use environment variables"
	@echo "  🚨 Production code: Never acceptable"
	@echo "  💡 Use os.environ.get() or Django settings for real secrets"

## lint-performance: Focus on performance issues only ⚡
lint-performance:
	@echo "⚡ Performance-focused linting..."
	@.venv/bin/ruff check . --select=PERF,C90,PIE,SIM --statistics

## lint-watch: Watch for changes and lint automatically 👀
lint-watch:
	@echo "👀 Watching for changes... (Ctrl+C to stop)"
	@command -v watchfiles >/dev/null 2>&1 || (.venv/bin/pip install watchfiles)
	@.venv/bin/watchfiles ".venv/bin/ruff check . --quiet" apps/ config/

# Production deployment helpers
deploy-check:
	@echo "🔒 Running deployment checks..."
	.venv/bin/python manage.py check --deploy
	.venv/bin/python manage.py collectstatic --noinput --dry-run

# Database backup (Romanian compliance)
backup-db:
	@echo "💾 Creating database backup..."
	.venv/bin/python manage.py dumpdata --natural-foreign --natural-primary > backup/data_$(shell date +%Y%m%d_%H%M%S).json

# Template validation and fixing
fix-templates:
	@echo "🔧 Fixing Django template syntax issues..."
	.venv/bin/python scripts/fix_template_comparisons.py

check-templates:
	@echo "🔍 Checking Django template syntax..."
	.venv/bin/python scripts/fix_template_comparisons.py --check

check-ide-settings:
	@echo "🔍 Checking IDE auto-formatting prevention settings..."
	@if [ -f .vscode/settings.json ]; then \
		echo "✅ VS Code settings found"; \
		grep -q "formatOnSave.*false" .vscode/settings.json && echo "✅ Format on save disabled" || echo "❌ Format on save not disabled"; \
	else \
		echo "❌ VS Code settings missing"; \
	fi
	@if [ -f .editorconfig ]; then \
		echo "✅ EditorConfig found"; \
	else \
		echo "❌ EditorConfig missing"; \
	fi
	@if [ -f .prettierignore ]; then \
		echo "✅ Prettier ignore found"; \
		grep -q "templates/" .prettierignore && echo "✅ Templates excluded from Prettier" || echo "❌ Templates not excluded"; \
	else \
		echo "❌ Prettier ignore missing"; \
	fi
	@if [ -f .git/hooks/pre-commit ]; then \
		echo "✅ Pre-commit hook installed"; \
	else \
		echo "❌ Pre-commit hook missing"; \
	fi
	@echo "📖 For detailed guide: docs/IDE_AUTO_FORMATTING_PREVENTION.md"
