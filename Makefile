# ===============================================================================
# PRAHO PLATFORM - DEVELOPMENT MAKEFILE (Updated for Django Test Runner)
# ===============================================================================

.PHONY: help install dev test test-coverage test-fast test-file build-css migrate fixtures clean lint

# Default target
help:
	@echo "🚀 PRAHO Platform - Romanian Hosting Provider"
	@echo "Available commands:"
	@echo "  make install         - Set up development environment"
	@echo "  make dev             - Run development server"
	@echo "  make test            - Run all tests (Django runner) - DEFAULT"
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
	python -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements/dev.txt
	@echo "✅ Environment ready! Activate with: source .venv/bin/activate"

# Run development server
dev:
	@echo "🚀 Starting development server..."
	.venv/bin/python manage.py runserver 0.0.0.0:8001

# Run tests with Django test runner (reliable and fast) - DEFAULT
test:
	@echo "🧪 Running unified test suite with Django runner..."
	.venv/bin/python manage.py test tests --settings=config.settings.test --verbosity=2
	@echo "✅ All tests completed successfully!"

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

# Code quality checks (keeping existing reliable setup)
lint:
	@echo "🔍 Running code quality checks..."
	.venv/bin/python -m ruff check .
	.venv/bin/python -m mypy .
	@echo "✅ Code quality checks complete"

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
