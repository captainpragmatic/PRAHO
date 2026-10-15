#!/usr/bin/env bash
# Virtualmin lab driver: two Virtualmin nodes + MinIO (SSE-S3) under Docker.
#
#   lab.sh build              build praho-virtualmin-lab:<version> and praho-debian-node:12
#   lab.sh up                 start the lab and wait until every node is healthy
#   lab.sh down               stop the lab and remove its containers and data
#   lab.sh apply-credentials  re-apply .state/<node>/inject on running nodes
#   lab.sh status             show container health
#   lab.sh healthy            exit 0 only when both nodes and MinIO are up and healthy (no output on success path beyond one line)
#   lab.sh node-up            start the bare Debian node and wait for sshd
#   lab.sh node-down          remove the bare Debian node and its data (a rebuild starts from the image)
#   lab.sh build-node         build praho-debian-node:12 only
#
# VIRTUALMIN_LAB_UNPINNED=1 builds the Virtualmin image from the repository's latest packages instead of the
# pinned versions (the nightly drift check, make test-virtualmin-drift). Use it with VIRTUALMIN_LAB_TAG=latest so
# the pinned image keeps its own tag.
#
# Works with macOS bash 3.2. Image pulls that hang on a credential helper can
# use an anonymous config: LAB_DOCKER_CONFIG=/path/with/empty/config.json.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${LAB_DIR}/.state"
ENV_FILE="${STATE_DIR}/lab.env"
VIRTUALMIN_TAG="${VIRTUALMIN_LAB_TAG:-8.3.0}"
WAIT_SECONDS="${LAB_WAIT_SECONDS:-900}"
NODES="vmlab-a vmlab-b"

if [ -n "${LAB_DOCKER_CONFIG:-}" ]; then
  export DOCKER_CONFIG="${LAB_DOCKER_CONFIG}"
fi

die() { echo "🔥 [Lab] $*" >&2; exit 1; }
info() { echo "✅ [Lab] $*"; }

compose() {
  docker compose --project-directory "${LAB_DIR}" -f "${LAB_DIR}/compose.yml" \
    --env-file "${ENV_FILE}" "$@"
}

ensure_state() {
  mkdir -p "${STATE_DIR}/vm-a/inject" "${STATE_DIR}/vm-b/inject" "${STATE_DIR}/node-c/inject"
  chmod 700 "${STATE_DIR}"
  if [ ! -s "${ENV_FILE}" ]; then
    local tmp
    tmp="$(mktemp "${STATE_DIR}/lab.env.XXXXXX")"
    {
      echo "VIRTUALMIN_LAB_TAG=${VIRTUALMIN_TAG}"
      echo "MINIO_ROOT_USER=lab$(openssl rand -hex 6)"
      echo "MINIO_ROOT_PASSWORD=$(openssl rand -hex 24)"
      echo "MINIO_KMS_SECRET_KEY=lab-key:$(openssl rand -base64 32)"
      echo "LAB_BUCKET=praho-backups"
    } > "${tmp}"
    chmod 600 "${tmp}"
    mv -f "${tmp}" "${ENV_FILE}"
    info "generated ${ENV_FILE}"
  fi
  # Keys for config.settings.lab (the platform side of the lab).
  if [ ! -s "${STATE_DIR}/django.env" ]; then
    local tmp
    tmp="$(mktemp "${STATE_DIR}/django.env.XXXXXX")"
    {
      echo "DJANGO_SECRET_KEY=lab-$(openssl rand -hex 32)"
      echo "DJANGO_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr '+/' '-_')"
      echo "CREDENTIAL_VAULT_MASTER_KEY=$(openssl rand -base64 32 | tr '+/' '-_')"
    } > "${tmp}"
    chmod 600 "${tmp}"
    mv -f "${tmp}" "${STATE_DIR}/django.env"
    info "generated ${STATE_DIR}/django.env"
  fi
}

wait_healthy() {
  local deadline name state
  deadline=$(( $(date +%s) + WAIT_SECONDS ))
  for name in "$@"; do
    while :; do
      state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${name}" 2>/dev/null || echo missing)"
      case "${state}" in
        healthy) info "${name} healthy"; break ;;
        missing|exited|dead|unhealthy) die "${name} is ${state}; see: docker logs ${name}" ;;
      esac
      [ "$(date +%s)" -lt "${deadline}" ] || die "${name} not healthy after ${WAIT_SECONDS}s (state: ${state})"
      sleep 5
    done
  done
}

cmd_build() {
  local revision
  local -a unpinned=()
  revision="$(git -C "${LAB_DIR}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  if [ "${VIRTUALMIN_LAB_UNPINNED:-0}" = "1" ]; then
    [ "${VIRTUALMIN_TAG}" != "8.3.0" ] || die "an unpinned build needs its own tag: set VIRTUALMIN_LAB_TAG=latest"
    # The repository carries a GPL and a Pro build of webmin-virtual-server under one name, and the Pro one is the
    # highest version but answers 401 without a licence: apt's version glob picks the GPL build.
    unpinned=(--build-arg WEBMIN_VERSION= --build-arg 'VIRTUAL_SERVER_VERSION=*-gpl' --build-arg VIRTUALMIN_CORE_VERSION=
      --build-arg VIRTUALMIN_CONFIG_VERSION= --build-arg VIRTUALMIN_STACK_VERSION=)
  fi
  # bash 3.2 treats an empty array as unset under set -u, hence the ${arr[@]+...} form.
  docker build --build-arg "VCS_REF=${revision}" ${unpinned[@]+"${unpinned[@]}"} \
    -f "${LAB_DIR}/virtualmin/Dockerfile" -t "praho-virtualmin-lab:${VIRTUALMIN_TAG}" "${LAB_DIR}"
  docker build --build-arg "VCS_REF=${revision}" -f "${LAB_DIR}/debian-node/Dockerfile" \
    -t praho-debian-node:12 "${LAB_DIR}"
  info "built praho-virtualmin-lab:${VIRTUALMIN_TAG} and praho-debian-node:12"
}

cmd_up() {
  ensure_state
  if ! docker image inspect "praho-virtualmin-lab:${VIRTUALMIN_TAG}" >/dev/null 2>&1; then
    cmd_build
  fi
  compose up -d vm-a vm-b minio
  local attempt=0
  until compose --profile setup run --rm --no-deps minio-bucket >/dev/null 2>&1; do
    attempt=$(( attempt + 1 ))
    [ "${attempt}" -lt 30 ] || die "bucket creation failed; see: docker logs vmlab-minio"
    sleep 2
  done
  info "bucket ready"
  # Word splitting is intended: NODES is a space-separated list.
  # shellcheck disable=SC2086
  wait_healthy ${NODES}
  info "lab up: vm-a https://127.0.0.1:${LAB_A_WEBMIN_PORT:-10101} ssh :${LAB_A_SSH_PORT:-2522}," \
    "vm-b https://127.0.0.1:${LAB_B_WEBMIN_PORT:-10102} ssh :${LAB_B_SSH_PORT:-2622}," \
    "MinIO http://127.0.0.1:${LAB_MINIO_PORT:-19000}"
}

cmd_down() {
  [ -s "${ENV_FILE}" ] || { info "no lab state; nothing to stop"; return 0; }
  compose --profile debian-node down --volumes --remove-orphans
  info "lab down"
}

cmd_apply_credentials() {
  local name
  for name in ${NODES}; do
    docker exec "${name}" /usr/local/sbin/lab-node-credentials
  done
}

cmd_healthy() {
  local name state
  for name in ${NODES} vmlab-minio; do
    state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${name}" 2>/dev/null || echo missing)"
    case "${state}" in
      healthy|running) ;;
      *) echo "${name} is ${state}"; return 1 ;;
    esac
  done
  info "lab is up"
}

cmd_status() {
  ensure_state
  compose --profile debian-node ps
}

cmd_node_up() {
  ensure_state
  compose --profile debian-node up -d debian-node
  wait_healthy vmlab-debian-node
}

cmd_build_node() {
  local revision
  revision="$(git -C "${LAB_DIR}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  docker build --build-arg "VCS_REF=${revision}" -f "${LAB_DIR}/debian-node/Dockerfile" \
    -t praho-debian-node:12 "${LAB_DIR}"
  info "built praho-debian-node:12"
}

cmd_node_down() {
  ensure_state
  compose --profile debian-node rm -sfv debian-node
  info "node-c removed"
}

case "${1:-}" in
  build-node) cmd_build_node ;;
  node-down) cmd_node_down ;;
  build) cmd_build ;;
  up) cmd_up ;;
  down) cmd_down ;;
  apply-credentials) cmd_apply_credentials ;;
  status) cmd_status ;;
  healthy) cmd_healthy ;;
  node-up) cmd_node_up ;;
  *) sed -n '2,13p' "${BASH_SOURCE[0]}" >&2; exit 2 ;;
esac
