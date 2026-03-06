# ===============================================================================
# PRAHO PLATFORM SERVICE - PRODUCTION DOCKERFILE 🏗️
# ===============================================================================
# Full Django platform with database access, all business logic

FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# ===============================================================================
# METADATA & LABELS 📋
# ===============================================================================
LABEL maintainer="PRAHO Platform Team"
LABEL service="platform"
LABEL description="PRAHO Platform Service - Admin and business logic"

# ===============================================================================
# ENVIRONMENT CONFIGURATION 🌍
# ===============================================================================
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=config.settings.prod \
    PYTHONPATH=/app \
    SERVICE_NAME=platform

# ===============================================================================
# SYSTEM DEPENDENCIES 📦
# ===============================================================================
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-client \
        build-essential \
        curl \
        git \
        netcat-traditional \
        gettext \
        libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ===============================================================================
# APPLICATION SETUP 🏗️
# ===============================================================================
WORKDIR /app

# Copy workspace lockfile and pyproject files for dependency resolution
COPY pyproject.toml uv.lock ./
COPY services/platform/pyproject.toml ./services/platform/pyproject.toml

# Sync platform production dependencies
RUN uv sync --group platform --group prod --frozen --no-dev

# Activate venv — bare `python` resolves to .venv/bin/python
ENV PATH="/app/.venv/bin:$PATH"

# Copy platform service code (includes assets/ and static/)
COPY services/platform/ ./

# Copy entrypoint script
COPY deploy/platform/entrypoint.sh /app/entrypoint.sh

# ===============================================================================
# STATIC FILES & ASSETS 📁
# ===============================================================================
# Platform already includes assets/ and static/ directories
# Just create directories for runtime files

# Create required runtime directories
RUN mkdir -p /app/staticfiles \
    && mkdir -p /app/media \
    && mkdir -p /app/logs

# ===============================================================================
# SECURITY & PERMISSIONS 🔒
# ===============================================================================
# Create non-root user
RUN addgroup --system django \
    && adduser --system --group django

# Set proper permissions
RUN chmod +x /app/entrypoint.sh \
    && chown -R django:django /app
USER django

# ===============================================================================
# HEALTH CHECK 🏥
# ===============================================================================
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8700/health/', timeout=10).raise_for_status()" \
    || exit 1

# ===============================================================================
# RUNTIME CONFIGURATION ⚙️
# ===============================================================================
EXPOSE 8700

# Entrypoint runs migrations, collectstatic, and setup_initial_data before Gunicorn
ENTRYPOINT ["/app/entrypoint.sh"]
