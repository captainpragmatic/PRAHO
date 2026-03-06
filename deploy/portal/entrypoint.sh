#!/bin/bash
# =============================================================================
# PRAHO Portal — Docker Entrypoint
# =============================================================================
# Runs on every container start. Portal is stateless (no DB migrations needed).
set -e

echo "📦 Collecting static files..."
python manage.py collectstatic --noinput

echo "✅ Starting Gunicorn..."
exec gunicorn \
    --bind "0.0.0.0:${PORT:-8701}" \
    --workers "${GUNICORN_WORKERS:-2}" \
    --timeout 60 \
    config.wsgi:application
