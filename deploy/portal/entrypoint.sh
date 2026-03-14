#!/bin/bash
# =============================================================================
# PRAHO Portal — Docker Entrypoint
# =============================================================================
# Runs on every container start. Portal uses a local SQLite file for session
# storage only (no business data). The session table migration is idempotent.
# Supports command override: if arguments are passed (e.g., from docker-compose
# `command:`), they run instead of the default gunicorn.
set -e

SESSION_DB="${SESSION_DB_PATH:-portal.sqlite3}"

# Pre-flight: if session DB exists but is corrupted, delete and recreate.
# Session data is disposable — losing it just forces re-login.
if [ -f "$SESSION_DB" ]; then
    if ! python -c "import sqlite3; sqlite3.connect('$SESSION_DB').execute('PRAGMA integrity_check')" 2>/dev/null; then
        echo "⚠️ Corrupt session DB detected, recreating..."
        rm -f "$SESSION_DB" "${SESSION_DB}-wal" "${SESSION_DB}-shm"
    fi
fi

echo "🗄️ Ensuring session table exists..."
python manage.py migrate sessions --noinput

echo "🧹 Clearing expired sessions..."
python manage.py clearsessions

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
