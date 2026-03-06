#!/bin/bash
# =============================================================================
# PRAHO Portal — Docker Entrypoint
# =============================================================================
# Runs on every container start. Portal is stateless (no DB migrations needed).
# Supports command override: if arguments are passed (e.g., from docker-compose
# `command:`), they run instead of the default gunicorn.
set -e

echo "📦 Collecting static files..."
python manage.py collectstatic --noinput

if [ $# -gt 0 ]; then
    # Command override (used by docker-compose.dev.yml to run runserver)
    exec "$@"
fi

echo "✅ Starting Gunicorn..."
exec gunicorn \
    --bind "0.0.0.0:${PORT:-8701}" \
    --workers "${GUNICORN_WORKERS:-2}" \
    --timeout 60 \
    config.wsgi:application
