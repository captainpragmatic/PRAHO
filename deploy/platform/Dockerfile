# ===============================================================================
# PRAHO PLATFORM SERVICE - PRODUCTION DOCKERFILE
# ===============================================================================
# Multi-stage build: builder stage compiles dependencies, final stage is minimal.
# Full Django platform with database access, all business logic.

# ---------------------------------------------------------------------------
# Stage 1: Builder — install build tools + compile Python dependencies
# ---------------------------------------------------------------------------
FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.8.13 /uv /usr/local/bin/uv

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

# Build the venv at the path it runs from. Console scripts such as gunicorn carry an absolute
# shebang to their venv's python, so a venv built elsewhere and copied cannot start them.
ENV UV_PROJECT_ENVIRONMENT=/app/.venv
RUN uv sync --group platform --group prod --frozen --no-dev

# ---------------------------------------------------------------------------
# Development target for `make docker-dev` (--target dev). A build without a target ends at the
# runtime stage below, so production images contain none of this.
# ---------------------------------------------------------------------------
FROM builder AS dev-builder

# Outside /app: the dev stack mounts the source over /app, which would hide a venv there. The dev
# group adds the debug toolbar and colorlog that config.settings.dev imports; the service code
# comes from that mount, so the workspace package itself is not installed.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv
RUN uv sync --group platform --group prod --frozen --no-install-workspace

FROM python:3.13-slim AS dev

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/opt/venv/bin:$PATH" \
    DJANGO_SETTINGS_MODULE=config.settings.dev \
    SERVICE_NAME=platform \
    PRAHO_SKIP_DOTENV=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-client \
        libpq5 \
        curl \
        gettext \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=dev-builder /opt/venv /opt/venv
WORKDIR /app
EXPOSE 8700
# No entrypoint: the dev stack runs migrations, then the autoreloading development server.
CMD ["python", "manage.py", "runserver", "0.0.0.0:8700"]

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
COPY --from=builder /app/.venv /app/.venv

# Activate venv — bare `python` resolves to .venv/bin/python
ENV PATH="/app/.venv/bin:$PATH"

# Copy platform service code (includes assets/ and static/)
COPY services/platform/ ./

# Shared design-system templates and static files (ADR-0035). Settings load them from
# REPO_ROOT/shared/ui, and REPO_ROOT is / here (BASE_DIR is /app).
COPY shared/ui /shared/ui

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

# start-period covers a first boot, which runs every migration before Gunicorn listens.
HEALTHCHECK --interval=30s --timeout=30s --start-period=600s --retries=3 \
    CMD curl -f http://localhost:8700/api/users/health/ || exit 1

EXPOSE 8700

# Entrypoint runs migrations, collectstatic, and setup_initial_data before Gunicorn
ENTRYPOINT ["/app/entrypoint.sh"]
