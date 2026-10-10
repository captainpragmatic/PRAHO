#!/bin/bash
# =============================================================================
# PRAHO Portal — Docker Entrypoint
# =============================================================================
# Runs on every container start. SQLite stores sessions and infrastructure guards.
# Supports command overrides after migrations and deployment checks succeed.
set -euo pipefail

SESSION_DB="${SESSION_DB_PATH:-portal.sqlite3}"
export SESSION_DB_PATH="$SESSION_DB"
SESSION_DIR=$(dirname "$SESSION_DB")
mkdir -p "$SESSION_DIR"

# Delete only after integrity_check proves corruption. Lock, permission and I/O
# failures abort startup and preserve the database for recovery.
if [ -f "$SESSION_DB" ]; then
    if python - "$SESSION_DB" <<'PY'
import sqlite3
import sys
from pathlib import Path

try:
    with sqlite3.connect(Path(sys.argv[1]).resolve().as_uri() + "?mode=rw", uri=True) as connection:
        results = connection.execute("PRAGMA integrity_check").fetchall()
except sqlite3.DatabaseError as error:
    code = getattr(error, "sqlite_errorcode", 0) & 0xFF
    if code not in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB):
        raise
    print(f"integrity_check failed: {error}", file=sys.stderr)
    sys.exit(20)
if results != [("ok",)]:
    print(f"integrity_check failed: {results}", file=sys.stderr)
    sys.exit(20)
PY
    then
        :
    else
        integrity_status=$?
        if [ "$integrity_status" -ne 20 ]; then
            exit "$integrity_status"
        fi
        echo "🚨 [Portal] Corrupt database removed; sessions, replay and idempotency guards were reset." >&2
        rm -f "$SESSION_DB" "${SESSION_DB}-wal" "${SESSION_DB}-shm"
    fi
fi

echo "✅ [Portal] Migrating sessions and infrastructure tables..."
python manage.py migrate sessions --noinput
python manage.py migrate common --noinput
python manage.py check --deploy --fail-level ERROR

echo "🧹 Clearing expired sessions and counters..."
python manage.py clearsessions
python manage.py cull_counters

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
    --no-control-socket \
    config.wsgi:application
