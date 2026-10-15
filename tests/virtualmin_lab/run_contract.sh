#!/usr/bin/env bash
# Run the Virtualmin contract suite against the lab nodes (make test-virtualmin-contract).
#
#   run_contract.sh            run the suite
#
# Environment:
#   VENV_DIR   the repository's virtualenv directory (the Makefile passes it; default .venv-<os>)
#
# The suite needs the lab: `make virtualmin-lab-up`. It fails, never skips, when a node is not healthy.
# Works with macOS bash 3.2.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV_DIR="${VENV_DIR:-.venv-$(uname -s | tr '[:upper:]' '[:lower:]')}"
PYTHON="${REPO_ROOT}/${VENV_DIR}/bin/python"
PLATFORM="${REPO_ROOT}/services/platform"
SUITE="${REPO_ROOT}/tests/virtualmin_lab"
NODES="vmlab-a vmlab-b"

die() { echo "🔥 [Virtualmin contract] $*" >&2; exit 1; }
info() { echo "✅ [Virtualmin contract] $*"; }

[ -x "${PYTHON}" ] || die "no Python at ${PYTHON}; run: make install"

for node in ${NODES}; do
  state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${node}" 2>/dev/null || echo missing)"
  [ "${state}" = "healthy" ] || die "${node} is ${state}; run: make virtualmin-lab-up"
done

pytest_rc=0
(
  cd "${PLATFORM}"
  export DJANGO_SETTINGS_MODULE=config.settings.lab
  export PYTHONPATH="${PLATFORM}:${REPO_ROOT}"
  "${PYTHON}" -m pytest -c "${SUITE}/pytest.ini" --rootdir="${REPO_ROOT}" "${SUITE}/contract"
) || pytest_rc=$?

if [ "${pytest_rc}" -ne 0 ]; then
  die "the contract suite failed (exit ${pytest_rc})"
fi
info "the contract suite passed"
