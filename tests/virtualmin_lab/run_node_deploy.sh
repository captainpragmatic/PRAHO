#!/usr/bin/env bash
# Deploy a Virtualmin node from scratch and run the contract smoke checks on it (make test-virtualmin-node-deploy).
#
#   run_node_deploy.sh
#
# Steps, on a freshly created container of the bare image praho-debian-node:
#   1. build the image (cached unless the Dockerfile changed) and recreate node-c;
#   2. register its deployment and SSH key, pin its host keys, set the node admin allowlist (ADR-0060);
#   3. run virtualmin.yml and virtualmin_harden.yml through PRAHO's AnsibleService, register and activate the
#      node, and check the API user, its IP lock and the firewall on it;
#   4. run the contract suite's smoke subset against it.
#
# The installer is not pinned to Virtualmin 8.3.0, so the contract recordings are neither compared nor written.
# This is the nightly run: the installer alone takes several minutes. node-c is removed at the end, whatever the
# outcome (vm-a, vm-b and MinIO are never touched).
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
NODE="vmlab-debian-node"

die() { echo "🔥 [Virtualmin node deploy] $*" >&2; exit 1; }
info() { echo "✅ [Virtualmin node deploy] $*"; }

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

cleanup() {
  "${LAB}" node-down >/dev/null 2>&1 || echo "⚠️ [Virtualmin node deploy] could not remove ${NODE}" >&2
}

[ -x "${PYTHON}" ] || die "no Python at ${PYTHON}; run: make install"
for node in vmlab-a vmlab-b; do
  state="$(node_state "${node}")"
  [ "${state}" = "healthy" ] || die "${node} is ${state}; run: make virtualmin-lab-up"
done

trap cleanup EXIT
"${LAB}" build-node
"${LAB}" node-down
"${LAB}" node-up

manage virtualmin_lab_node_deploy prepare
docker exec "${NODE}" /usr/local/sbin/lab-node-credentials
manage virtualmin_lab_node_deploy deploy
info "node-c deployed from the bare image"

(
  cd "${PLATFORM}"
  export DJANGO_SETTINGS_MODULE=config.settings.lab
  export PYTHONPATH="${PLATFORM}:${REPO_ROOT}"
  export VIRTUALMIN_CONTRACT_NODE=node-c
  "${PYTHON}" -m pytest -c "${SUITE}/pytest.ini" --rootdir="${REPO_ROOT}" -m smoke "${SUITE}/contract"
) || die "the contract smoke checks failed on the deployed node"
info "the contract smoke checks passed on the deployed node"
