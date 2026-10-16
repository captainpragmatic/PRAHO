#!/usr/bin/env bash
# Run the Virtualmin workflow suite against the lab nodes (make test-virtualmin-workflows).
#
#   run_workflows.sh              run every workflow
#   run_workflows.sh -k backup    extra arguments go to pytest
#
# Environment:
#   VENV_DIR   the repository's virtualenv directory (the Makefile passes it; default .venv-<os>)
#
# The suite needs the lab: `make virtualmin-lab-up`. It fails, never skips, when a node is not healthy.
# Every workflow cleans up after itself; the runner checks the nodes are still healthy at the end.
# Works with macOS bash 3.2.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV_DIR="${VENV_DIR:-.venv-$(uname -s | tr '[:upper:]' '[:lower:]')}"
PYTHON="${REPO_ROOT}/${VENV_DIR}/bin/python"
PLATFORM="${REPO_ROOT}/services/platform"
SUITE="${REPO_ROOT}/tests/virtualmin_lab"
NODES="vmlab-a vmlab-b"

die() { echo "🔥 [Virtualmin workflows] $*" >&2; exit 1; }
info() { echo "✅ [Virtualmin workflows] $*"; }

node_state() {
  docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$1" 2>/dev/null || echo missing
}

[ -x "${PYTHON}" ] || die "no Python at ${PYTHON}; run: make install"

for node in ${NODES}; do
  state="$(node_state "${node}")"
  [ "${state}" = "healthy" ] || die "${node} is ${state}; run: make virtualmin-lab-up"
done

pytest_rc=0
(
  cd "${PLATFORM}"
  export DJANGO_SETTINGS_MODULE=config.settings.lab
  export PYTHONPATH="${PLATFORM}:${REPO_ROOT}"
  "${PYTHON}" -m pytest -c "${SUITE}/pytest.ini" --rootdir="${REPO_ROOT}" "$@" "${SUITE}/workflows"
) || pytest_rc=$?

for node in ${NODES}; do
  state="$(node_state "${node}")"
  [ "${state}" = "healthy" ] || die "${node} is ${state} after the workflows"
done

if [ "${pytest_rc}" -ne 0 ]; then
  die "the workflow suite failed (exit ${pytest_rc})"
fi
info "the workflow suite passed"
