# ===============================================================================
# PRAHO PLATFORM SERVICE - PRODUCTION DOCKERFILE
# ===============================================================================
# Multi-stage build: builder stage compiles dependencies, final stage is minimal.
# Full Django platform with database access, all business logic.

# ---------------------------------------------------------------------------
# Stage 1: Builder — install build tools + compile Python dependencies
# ---------------------------------------------------------------------------
FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace lockfile and pyproject files for dependency resolution
COPY pyproject.toml uv.lock ./
COPY services/platform/pyproject.toml ./services/platform/pyproject.toml

# Sync platform production dependencies into /build/.venv
RUN uv sync --group platform --group prod --frozen --no-dev

# ---------------------------------------------------------------------------
# Stage 2: Runtime — minimal image with only runtime dependencies
# ---------------------------------------------------------------------------
FROM python:3.13-slim

LABEL maintainer="PRAHO Platform Team"
LABEL service="platform"
LABEL description="PRAHO Platform Service - Admin and business logic"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=config.settings.prod \
    PYTHONPATH=/app \
    SERVICE_NAME=platform

# Runtime-only system packages (no build-essential, no git, no uv)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-client \
        libpq5 \
        curl \
        netcat-traditional \
        gettext \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy pre-built venv from builder stage
COPY --from=builder /build/.venv /app/.venv

# Activate venv — bare `python` resolves to .venv/bin/python
ENV PATH="/app/.venv/bin:$PATH"

# Copy platform service code (includes assets/ and static/)
COPY services/platform/ ./

# Copy entrypoint script
COPY deploy/platform/entrypoint.sh /app/entrypoint.sh

# Create required runtime directories
RUN mkdir -p /app/staticfiles \
    && mkdir -p /app/media \
    && mkdir -p /app/logs \
    && mkdir -p /var/log/praho

# Create non-root user
RUN addgroup --system django \
    && adduser --system --group django

# Set proper permissions
RUN chmod +x /app/entrypoint.sh \
    && chown -R django:django /app \
    && chown -R django:django /var/log/praho
USER django

HEALTHCHECK --interval=30s --timeout=30s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8700/api/users/health/ || exit 1

EXPOSE 8700

# Entrypoint runs migrations, collectstatic, and setup_initial_data before Gunicorn
ENTRYPOINT ["/app/entrypoint.sh"]
