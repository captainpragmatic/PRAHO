#!/bin/bash
# =============================================================================
# PRAHO Platform — Docker Entrypoint
# =============================================================================
# Runs on every container start. All setup commands are idempotent.
set -e

echo "🚀 Running database migrations..."
python manage.py migrate --noinput

echo "📦 Collecting static files..."
python manage.py collectstatic --noinput

echo "🏗️ Creating cache table..."
python manage.py createcachetable 2>/dev/null || true

echo "🎯 Setting up initial data..."
python manage.py setup_initial_data

echo "✅ Starting Gunicorn..."
exec gunicorn \
    --bind "0.0.0.0:${PORT:-8700}" \
    --workers "${GUNICORN_WORKERS:-4}" \
    --timeout 120 \
    config.wsgi:application
