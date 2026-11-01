#!/usr/bin/env bash
# Canonical Make entry point; the Python driver owns both exact child PIDs and private databases.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV_DIR="${VENV_DIR:-.venv-$(uname -s | tr '[:upper:]' '[:lower:]')}"
exec "${REPO_ROOT}/${VENV_DIR}/bin/python" "${REPO_ROOT}/tests/virtualmin_lab/maintenance_portal_runner.py" "$@"
