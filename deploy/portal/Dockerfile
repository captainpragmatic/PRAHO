# ===============================================================================
# PRAHO PORTAL SERVICE - PRODUCTION DOCKERFILE 🌐
# ===============================================================================
# Lightweight customer portal - NO database access, API-only

FROM python:3.11-slim

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
    DJANGO_SETTINGS_MODULE=config.settings \
    SERVICE_NAME=portal

# ⚠️ CRITICAL: NO PYTHONPATH set - portal cannot import platform code

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

# Copy portal service requirements (minimal, no DB drivers)
COPY services/portal/requirements.docker.txt ./requirements.txt

# Install minimal Python dependencies (without constraints to avoid extras issues)
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip cache purge

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
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8701/health/', timeout=10)" \
    || exit 1

# ===============================================================================
# RUNTIME CONFIGURATION ⚙️
# ===============================================================================
EXPOSE 8701

# Default command - lightweight gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8701", "--workers", "2", "--timeout", "60", "config.wsgi:application"]
