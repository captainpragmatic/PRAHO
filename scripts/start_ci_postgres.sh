#!/bin/bash
# CI uses real PostgreSQL 16; retry the official image via Docker Hub if its public mirror fails.
set -euo pipefail
CID_FILE="${RUNNER_TEMP:?CI runner temporary directory required}/praho-ci-postgres.cid"
stop_database() {
    local cid
    [ -s "$CID_FILE" ] || return 0
    cid=$(cat "$CID_FILE")
    [[ "$cid" =~ ^[0-9a-f]{12,64}$ ]] || { echo 'Invalid CI PostgreSQL container ID' >&2; return 1; }
    docker rm --force --volumes "$cid"
    rm -f "$CID_FILE"
}
if [ "${1:-}" = --stop ]; then stop_database; exit 0; fi
TAG="${1:-16}"
case "$TAG" in 16|16-alpine) ;; *) echo 'CI PostgreSQL tag must be 16 or 16-alpine' >&2; exit 1 ;; esac
[ ! -e "$CID_FILE" ] || { echo 'CI PostgreSQL container already recorded' >&2; exit 1; }
: "${POSTGRES_PASSWORD:?CI database fixture password required}"
export POSTGRES_PASSWORD
IMAGE=""
for source in "public.ecr.aws/docker/library/postgres:$TAG" "docker.io/library/postgres:$TAG"; do
    if docker pull "$source"; then IMAGE="$source"; break; fi
done
[ -n "$IMAGE" ] || { echo 'Official PostgreSQL image unavailable from both registries' >&2; exit 1; }
export POSTGRES_DB=test_db
export POSTGRES_USER="${CI_POSTGRES_USER:-postgres}"
OPTIONS=()
if [ "$TAG" = 16-alpine ]; then
    export POSTGRES_INITDB_ARGS=--nosync
    OPTIONS+=(--env POSTGRES_INITDB_ARGS --shm-size=256mb --tmpfs /var/lib/postgresql/data)
fi
# shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap.
failed_start() {
    local result="$1"
    if [ "$result" -ne 0 ]; then stop_database || true; fi
    return "$result"
}
trap 'failed_start "$?"' EXIT
docker run --detach --cidfile "$CID_FILE" --publish 127.0.0.1:5432:5432 \
    --env POSTGRES_DB --env POSTGRES_USER --env POSTGRES_PASSWORD \
    --health-cmd "pg_isready -U $POSTGRES_USER -d $POSTGRES_DB" \
    --health-interval 2s --health-timeout 3s --health-retries 30 \
    ${OPTIONS[@]+"${OPTIONS[@]}"} "$IMAGE"
CID=$(cat "$CID_FILE")
for ((attempt=1; attempt<=30; attempt++)); do
    STATUS=$(docker inspect --format '{{.State.Health.Status}}' "$CID")
    case "$STATUS" in
        healthy)
            VERSION=$(docker exec "$CID" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc 'SHOW server_version_num')
            [[ "$VERSION" =~ ^16[0-9]{4}$ ]] || { echo 'Expected PostgreSQL major 16' >&2; exit 1; }
            exit 0 ;;
        starting) sleep 2 ;;
        *) docker logs "$CID"; echo "CI PostgreSQL health failed: $STATUS" >&2; exit 1 ;;
    esac
done
echo 'CI PostgreSQL readiness timed out' >&2
exit 1
