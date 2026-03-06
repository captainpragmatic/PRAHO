# ===============================================================================
# PRAHO PORTAL SERVICE - PRODUCTION DOCKERFILE 🌐
# ===============================================================================
# Lightweight customer portal - NO database access, API-only

FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# ===============================================================================
# METADATA & LABELS 📋
# ===============================================================================
LABEL maintainer="PRAHO Platform Team"
LABEL service="portal"
LABEL description="PRAHO Portal Service - Customer-facing API gateway"

# ===============================================================================
# ENVIRONMENT CONFIGURATION 🌍
# ===============================================================================
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=config.settings.prod \
    SERVICE_NAME=portal

# Portal uses config.settings.prod (not config.settings) because portal has a
# settings package (config/settings/{base,dev,prod}.py), same as platform.

# ===============================================================================
# MINIMAL SYSTEM DEPENDENCIES 📦
# ===============================================================================
# Note: NO postgresql-client, NO libpq-dev - portal has no DB access
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        netcat-traditional \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ===============================================================================
# APPLICATION SETUP 🏗️
# ===============================================================================
WORKDIR /app

# Copy workspace lockfile and pyproject files for dependency resolution
COPY pyproject.toml uv.lock ./
COPY services/portal/pyproject.toml ./services/portal/pyproject.toml

# Sync portal production dependencies
RUN uv sync --group portal --group prod --frozen --no-dev

# Make venv available on PATH so python/gunicorn just work
ENV PATH="/app/.venv/bin:$PATH"

# Copy portal service code
COPY services/portal/ ./

# ===============================================================================
# STATIC FILES & ASSETS 📁
# ===============================================================================
# Create required directories (minimal)
RUN mkdir -p /app/staticfiles \
    && mkdir -p /app/logs

# ===============================================================================
# SECURITY & PERMISSIONS 🔒
# ===============================================================================
# Create non-root user
RUN addgroup --system django \
    && adduser --system --group django

# Set proper permissions
RUN chown -R django:django /app
USER django

# ===============================================================================
# HEALTH CHECK 🏥
# ===============================================================================
HEALTHCHECK --interval=30s --timeout=30s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8701/status/ || exit 1

# ===============================================================================
# RUNTIME CONFIGURATION ⚙️
# ===============================================================================
EXPOSE 8701

# Default command - lightweight gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8701", "--workers", "2", "--timeout", "60", "config.wsgi:application"]
