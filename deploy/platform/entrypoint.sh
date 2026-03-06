#!/bin/bash
# =============================================================================
# PRAHO Platform — Docker Entrypoint
# =============================================================================
# Runs on every container start. All setup commands are idempotent.
# Supports command override: if arguments are passed (e.g., from docker-compose
# `command:`), they run instead of the default gunicorn.
set -e

echo "🚀 Running database migrations..."
python manage.py migrate --noinput

echo "📦 Collecting static files..."
python manage.py collectstatic --noinput

echo "🏗️ Creating cache table..."
python manage.py createcachetable 2>/dev/null || true

echo "🎯 Setting up initial data..."
python manage.py setup_initial_data

if [ $# -gt 0 ]; then
    # Command override (used by docker-compose.dev.yml to run runserver)
    exec "$@"
fi

echo "✅ Starting Gunicorn..."
exec gunicorn \
    --bind "0.0.0.0:${PORT:-8700}" \
    --workers "${GUNICORN_WORKERS:-4}" \
    --timeout 120 \
    config.wsgi:application
