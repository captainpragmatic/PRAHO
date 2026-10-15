#!/usr/bin/env bash
# Run the Virtualmin browser smoke tests against the lab (make test-virtualmin-e2e).
#
#   run_e2e.sh                          run every tests/e2e/platform/test_virtualmin_lab_*.py
#   run_e2e.sh -k backup                extra arguments go to pytest
#
# What it starts, and what stops it again (an EXIT trap, so Ctrl-C, a failed test and a crash all clean up):
#   1. a COPY of the lab database (services/platform/db-virtualmin-lab-e2e.sqlite3). The server and the test
#      process share the copy; the lab database and the suites that use it are never touched.
#   2. `manage.py virtualmin_lab_runserver` on 127.0.0.1:${VIRTUALMIN_E2E_PORT} (default 8710, so a developer's
#      `make dev` on 8700 keeps running). It runs Platform under config.settings.lab inside the lab transport,
#      with a worker thread for the queue, and with the opt-in hosting features switched on.
#   It never starts the e2e stack of `make dev-e2e` (config.settings.e2e, portal, seeded e2e database): the two
#   stacks share nothing, and the default `make test-e2e` never collects these tests.
#
# Environment:
#   VENV_DIR              the repository's virtualenv directory (the Makefile passes it; default .venv-<os>)
#   VIRTUALMIN_E2E_PORT   the port of the lab server (default 8710)
#
# The suite needs the lab: `make virtualmin-lab-up`. It fails, never skips, when a node is not healthy.
# The source tree must stay frozen while it runs: a changed tree makes the result diagnostic only (exit 1),
# the same rule as scripts/e2e_stack.py.
# Works with macOS bash 3.2.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV_DIR="${VENV_DIR:-.venv-$(uname -s | tr '[:upper:]' '[:lower:]')}"
PYTHON="${REPO_ROOT}/${VENV_DIR}/bin/python"
PLATFORM="${REPO_ROOT}/services/platform"
SUITE="${REPO_ROOT}/tests/virtualmin_lab"
PORT="${VIRTUALMIN_E2E_PORT:-8710}"
LAB_DB="${PLATFORM}/db-virtualmin-lab.sqlite3"
E2E_DB="${PLATFORM}/db-virtualmin-lab-e2e.sqlite3"
SERVER_LOG="${REPO_ROOT}/logs/virtualmin_e2e_server.log"
ARTIFACTS="${REPO_ROOT}/output/playwright/virtualmin-lab/$(date +%Y%m%d-%H%M%S)"
NODES="vmlab-a vmlab-b"
SERVER_PID=""

die() { echo "🔥 [Virtualmin e2e] $*" >&2; exit 1; }
info() { echo "✅ [Virtualmin e2e] $*"; }

node_state() {
  docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$1" 2>/dev/null || echo missing
}

port_in_use() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# The commit plus every staged, unstaged and untracked source file: what scripts/e2e_stack.py compares.
tree_fingerprint() {
  (cd "${REPO_ROOT}" && PYTHONPATH="${REPO_ROOT}" "${PYTHON}" -c \
    'import json; from scripts.e2e_stack import source_version; print(json.dumps(source_version(), sort_keys=True))')
}

lab_manage() {
  (cd "${PLATFORM}" && DJANGO_SETTINGS_MODULE=config.settings.lab PYTHONPATH="${PLATFORM}" "${PYTHON}" manage.py "$@")
}

stop_server() {
  local waited=0
  [ -n "${SERVER_PID}" ] || return 0
  if kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    while kill -0 "${SERVER_PID}" 2>/dev/null && [ "${waited}" -lt 20 ]; do
      sleep 1
      waited=$(( waited + 1 ))
    done
    # Only the PID this script started: never a pattern.
    if kill -0 "${SERVER_PID}" 2>/dev/null; then
      kill -9 "${SERVER_PID}" 2>/dev/null || true
    fi
  fi
  wait "${SERVER_PID}" 2>/dev/null || true
  SERVER_PID=""
}

cleanup() {
  local rc=$?
  trap - EXIT
  stop_server
  rm -f "${E2E_DB}" "${E2E_DB}-journal" "${E2E_DB}-wal" "${E2E_DB}-shm"
  exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[ -x "${PYTHON}" ] || die "no Python at ${PYTHON}; run: make install"
[ -f "${LAB_DB}" ] || die "no lab database at ${LAB_DB}; run: make virtualmin-lab-up"

for node in ${NODES}; do
  state="$(node_state "${node}")"
  [ "${state}" = "healthy" ] || die "${node} is ${state}; run: make virtualmin-lab-up"
done
lab_manage virtualmin_lab_pins >/dev/null 2>&1 \
  || die "a node no longer presents the certificate PRAHO pinned; run: make virtualmin-lab-up"

if port_in_use "${PORT}"; then
  die "port ${PORT} is in use. Stop its owner or set VIRTUALMIN_E2E_PORT; no process was killed."
fi

mkdir -p "${REPO_ROOT}/logs" "${ARTIFACTS}"
before="$(tree_fingerprint)"

# A consistent copy (the SQLite backup API), so a stale or half-written file never reaches the server.
rm -f "${E2E_DB}"
"${PYTHON}" - "${LAB_DB}" "${E2E_DB}" <<'PY'
import sqlite3
import sys

source = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
target = sqlite3.connect(sys.argv[2])
source.backup(target)
target.close()
source.close()
PY
export VIRTUALMIN_LAB_DATABASE="${E2E_DB}"
lab_manage migrate --noinput >/dev/null

(
  cd "${PLATFORM}"
  export DJANGO_SETTINGS_MODULE=config.settings.lab PYTHONPATH="${PLATFORM}" PYTHONUNBUFFERED=1
  # exec: the background PID is the server itself, so the trap stops exactly what was started.
  exec "${PYTHON}" manage.py virtualmin_lab_runserver "127.0.0.1:${PORT}" --noreload --features
) > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

ready=0
for _ in $(seq 1 90); do
  kill -0 "${SERVER_PID}" 2>/dev/null || { tail -n 30 "${SERVER_LOG}" >&2; die "the lab server exited during start-up (log: ${SERVER_LOG})"; }
  if curl -fsS -o /dev/null "http://localhost:${PORT}/auth/login/" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
[ "${ready}" -eq 1 ] || { tail -n 30 "${SERVER_LOG}" >&2; die "the lab server did not answer on port ${PORT} (log: ${SERVER_LOG})"; }
info "lab server up on port ${PORT} (database copy ${E2E_DB##*/})"

pytest_rc=0
(
  cd "${REPO_ROOT}"
  export DJANGO_SETTINGS_MODULE=config.settings.lab
  export PYTHONPATH="${PLATFORM}:${REPO_ROOT}"
  export PLATFORM_BASE_URL="http://localhost:${PORT}"
  export VIRTUALMIN_E2E=1 E2E_STRICT=1 PYTHONDONTWRITEBYTECODE=1
  # Playwright's sync API keeps an event loop running in the test thread, which Django's async guard refuses
  # for ORM calls. The tests read and write the lab database from that thread; nothing else does.
  export DJANGO_ALLOW_ASYNC_UNSAFE=true
  "${PYTHON}" -m pytest -c "${SUITE}/pytest.ini" --rootdir="${REPO_ROOT}" -m virtualmin_lab \
    --tracing=retain-on-failure --screenshot=only-on-failure --output="${ARTIFACTS}/browser" \
    --junitxml="${ARTIFACTS}/junit.xml" "$@" \
    "${REPO_ROOT}"/tests/e2e/platform/test_virtualmin_lab_*.py
) || pytest_rc=$?

cp "${SERVER_LOG}" "${ARTIFACTS}/" 2>/dev/null || true
for node in ${NODES}; do
  state="$(node_state "${node}")"
  [ "${state}" = "healthy" ] || die "${node} is ${state} after the browser tests"
done

after="$(tree_fingerprint)"
if [ "${before}" != "${after}" ]; then
  die "the source tree changed during the run; the result is diagnostic only. Repeat it on a frozen tree."
fi
if [ "${pytest_rc}" -ne 0 ]; then
  die "the browser tests failed (exit ${pytest_rc}); evidence: ${ARTIFACTS}"
fi
info "the browser tests passed; evidence: ${ARTIFACTS}"
