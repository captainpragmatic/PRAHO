#!/usr/bin/env bash
# Inject faults into the lab while PRAHO works (make test-virtualmin-faults).
#
#   run_faults.sh             run every fault test
#   run_faults.sh -k webmin   extra arguments go to pytest
#
# The faults: Webmin stopped and the network disconnected in the middle of a backup and of a restore, and a node
# paused so that a call times out. The tests assert how PRAHO reads each one (jobs, replay, exclusion, nothing
# falsely done) and put the node back after each test.
#
# Whatever happens, the lab is restored when this script ends (a trap): every lab container unpaused and
# reconnected to the compose network, Webmin running, the nodes healthy, and the certificate pins checked. A node
# restart regenerates a node's TLS identity and invalidates the pin, so a mismatch re-runs the bootstrap and
# `lab.sh apply-credentials`.
#
# Environment:
#   VENV_DIR   the repository's virtualenv directory (the Makefile passes it; default .venv-<os>)
#
# The lab must be up: `make virtualmin-lab-up`. Works with macOS bash 3.2.
# The subshells are deliberate: each step gets its own environment.
# shellcheck disable=SC2030,SC2031
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV_DIR="${VENV_DIR:-.venv-$(uname -s | tr '[:upper:]' '[:lower:]')}"
PYTHON="${REPO_ROOT}/${VENV_DIR}/bin/python"
PLATFORM="${REPO_ROOT}/services/platform"
SUITE="${REPO_ROOT}/tests/virtualmin_lab"
LAB="${REPO_ROOT}/deploy/virtualmin-lab/lab.sh"
NODES="vmlab-a vmlab-b"
NETWORK="virtualmin-lab_default"
WAIT_SECONDS=180

die() { echo "🔥 [Virtualmin faults] $*" >&2; exit 1; }
info() { echo "✅ [Virtualmin faults] $*"; }

node_state() {
  docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$1" 2>/dev/null || echo missing
}

manage() {
  (
    cd "${PLATFORM}"
    export DJANGO_SETTINGS_MODULE=config.settings.lab
    export PYTHONPATH="${PLATFORM}"
    "${PYTHON}" manage.py "$@"
  )
}

wait_healthy() {
  local deadline node
  deadline=$(( $(date +%s) + WAIT_SECONDS ))
  for node in ${NODES}; do
    until [ "$(node_state "${node}")" = "healthy" ]; do
      [ "$(date +%s)" -lt "${deadline}" ] || return 1
      sleep 3
    done
  done
}

# Undo every fault, whether or not a test already did. Each step tolerates "already done".
restore_lab() {
  local node
  for node in ${NODES}; do
    docker unpause "${node}" >/dev/null 2>&1 || true
    docker network connect "${NETWORK}" "${node}" >/dev/null 2>&1 || true
    docker exec "${node}" systemctl start webmin >/dev/null 2>&1 || true
  done
  wait_healthy || { echo "⚠️ [Virtualmin faults] a node is not healthy after the restore" >&2; return 1; }
  if ! manage virtualmin_lab_pins >/dev/null 2>&1; then
    echo "⚠️ [Virtualmin faults] a node's certificate changed; re-running the bootstrap" >&2
    manage virtualmin_lab_bootstrap >/dev/null
    "${LAB}" apply-credentials >/dev/null
    manage virtualmin_lab_pins >/dev/null || return 1
  fi
}

finish() {
  local status=$?
  trap - EXIT
  if restore_lab; then
    info "the lab is restored: nodes healthy, network connected, Webmin running, pins valid"
  else
    echo "🔥 [Virtualmin faults] the lab could not be restored; run: make virtualmin-lab-up" >&2
    status=1
  fi
  exit "${status}"
}

[ -x "${PYTHON}" ] || die "no Python at ${PYTHON}; run: make install"
for node in ${NODES}; do
  state="$(node_state "${node}")"
  [ "${state}" = "healthy" ] || die "${node} is ${state}; run: make virtualmin-lab-up"
done

trap finish EXIT

(
  cd "${PLATFORM}"
  export DJANGO_SETTINGS_MODULE=config.settings.lab
  export PYTHONPATH="${PLATFORM}:${REPO_ROOT}"
  "${PYTHON}" -m pytest -c "${SUITE}/pytest.ini" --rootdir="${REPO_ROOT}" "$@" "${SUITE}/faults"
) || die "the fault suite failed"
info "the fault suite passed"
