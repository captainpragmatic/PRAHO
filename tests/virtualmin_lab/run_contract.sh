#!/usr/bin/env bash
# Run the Virtualmin contract suite against the lab nodes (make test-virtualmin-contract).
#
#   run_contract.sh                 run the suite, then compare the fresh recording with the committed fixtures
#   RECORD=update run_contract.sh   run the suite and write the recording over the committed fixtures
#   RECORD=none run_contract.sh     run the suite, write no recording and compare nothing (the nightly drift check
#                                   against the latest Virtualmin: the assertions are the drift report)
#
# Environment:
#   VENV_DIR   the repository's virtualenv directory (the Makefile passes it; default .venv-<os>)
#   RECORD     "update" rewrites services/platform/tests/fixtures/virtualmin/<version>/; "none" records nothing;
#              anything else checks drift
#
# The suite needs the lab: `make virtualmin-lab-up`. It fails, never skips, when a node is not healthy.
# Works with macOS bash 3.2.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV_DIR="${VENV_DIR:-.venv-$(uname -s | tr '[:upper:]' '[:lower:]')}"
PYTHON="${REPO_ROOT}/${VENV_DIR}/bin/python"
PLATFORM="${REPO_ROOT}/services/platform"
SUITE="${REPO_ROOT}/tests/virtualmin_lab"
FIXTURES="${PLATFORM}/tests/fixtures/virtualmin"
RECORD="${RECORD:-check}"
NODES="vmlab-a vmlab-b"

die() { echo "🔥 [Virtualmin contract] $*" >&2; exit 1; }
info() { echo "✅ [Virtualmin contract] $*"; }

[ -x "${PYTHON}" ] || die "no Python at ${PYTHON}; run: make install"

for node in ${NODES}; do
  state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${node}" 2>/dev/null || echo missing)"
  [ "${state}" = "healthy" ] || die "${node} is ${state}; run: make virtualmin-lab-up"
done

if [ "${RECORD}" = "update" ]; then
  record_dir="${FIXTURES}"
elif [ "${RECORD}" = "none" ]; then
  record_dir=""
else
  record_dir="$(mktemp -d "${TMPDIR:-/tmp}/virtualmin-contract.XXXXXX")"
  trap 'rm -rf "${record_dir}"' EXIT
fi

pytest_rc=0
(
  cd "${PLATFORM}"
  export DJANGO_SETTINGS_MODULE=config.settings.lab
  export PYTHONPATH="${PLATFORM}:${REPO_ROOT}"
  export VIRTUALMIN_CONTRACT_RECORD_DIR="${record_dir}"
  "${PYTHON}" -m pytest -c "${SUITE}/pytest.ini" --rootdir="${REPO_ROOT}" "${SUITE}/contract"
) || pytest_rc=$?

if [ "${pytest_rc}" -ne 0 ]; then
  die "the contract suite failed (exit ${pytest_rc})"
fi
info "the contract suite passed"

if [ "${RECORD}" = "update" ]; then
  info "recordings written to ${FIXTURES}"
  exit 0
fi
if [ "${RECORD}" = "none" ]; then
  info "no recording written and none compared"
  exit 0
fi

drift_rc=0
"${PYTHON}" "${SUITE}/drift.py" --fresh "${record_dir}" --committed "${FIXTURES}" || drift_rc=$?
if [ "${drift_rc}" -ne 0 ]; then
  die "the node answers differently from the committed recordings; if the change is intended: make test-virtualmin-contract RECORD=update"
fi
info "no drift from the committed recordings"
