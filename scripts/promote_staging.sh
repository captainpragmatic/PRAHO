#!/usr/bin/env bash
# Promote a release candidate to staging.
#
#   scripts/promote_staging.sh [--dry-run] [--rollback] <sha>      (or: make promote-staging SHA=<sha>)
#
# 1. The commit must be on origin/master and have a successful run of release-candidate.yml titled
#    "Release candidate <sha>", whose own commit is on master. The run is the proof, not the commit
#    status of the same name: anyone who can push could post that status.
# 2. It is deployed from a clean detached checkout of exactly that commit, so the playbooks, roles and
#    templates are the reviewed ones and not whatever this checkout holds. Only a git deploy installs the
#    approved commit (an rsync deploy copies a working tree), so any other DEPLOY_METHOD is refused, read
#    with the deploy's own parser.
# 3. Only after the deploy succeeds does origin/staging move to it, so the branch names what staging
#    runs. A forward move must be a fast-forward; --rollback allows an OLDER approved commit. Every move
#    carries a lease on the value this run validated, so a branch moved meanwhile is never overwritten.
#
# One promotion runs at a time per clone; promote from one machine. Runs anywhere with git, gh
# (authenticated for this repository), this repository's venv and the staging deploy inputs.
# Works with macOS bash 3.2.
set -euo pipefail

die() { echo "❌ $*" >&2; exit 1; }
info() { echo "🔎 $*"; }

dry_run=0
rollback=0
candidate=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) dry_run=1 ;;
        --rollback) rollback=1 ;;
        -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
        -*) die "Unknown option: $1" ;;
        *) [ -z "$candidate" ] || die "Give exactly one commit"; candidate="$1" ;;
    esac
    shift
done
[ -n "$candidate" ] || die "Usage: $0 [--dry-run] [--rollback] <sha>"
[[ "$candidate" =~ ^[0-9a-fA-F]{7,40}$ ]] || die "Not a commit SHA: $candidate"

root="$(git rev-parse --show-toplevel)"
cd "$root"
command -v gh >/dev/null 2>&1 || die "gh is not installed"
python="$root/.venv-$(uname -s | tr '[:upper:]' '[:lower:]')/bin/python"
[ -x "$python" ] || die "No project venv at $python (run make install)"
env_file="$root/.env.staging"
[ -f "$env_file" ] || die "Missing .env.staging (see .env.example.staging)"

lock="$(git rev-parse --git-common-dir)/promote-staging.lock"
mkdir "$lock" 2>/dev/null || die "Another promotion is running from this clone ($lock); remove it if that run died"
release=""
cleanup() {
    if [ -n "$release" ]; then
        git worktree remove --force "$release" >/dev/null 2>&1 || true
    fi
    rmdir "$lock" 2>/dev/null || true
}
trap cleanup EXIT

info "Fetching master and staging from origin..."
git fetch --quiet origin master staging

sha="$(git rev-parse --verify --quiet "${candidate}^{commit}")" || die "Unknown commit: $candidate"
staging="$(git rev-parse origin/staging)"

git merge-base --is-ancestor "$sha" origin/master || die "$sha is not on master"
info "On master: $sha"

# --paginate: a rollback may name a release approved hundreds of runs ago.
runs="$(gh api --paginate "repos/{owner}/{repo}/actions/workflows/release-candidate.yml/runs?event=workflow_dispatch&status=success&per_page=100" \
    --jq ".workflow_runs[] | select(.display_title == \"Release candidate $sha\" and .path == \".github/workflows/release-candidate.yml\" and .conclusion == \"success\") | \"\(.id) \(.head_sha)\"")" \
    || die "Could not read the release-candidate runs from GitHub (is gh authenticated?)"
approved=""
while read -r run_id run_sha; do
    [ -n "$run_id" ] || continue
    # An edited copy of the workflow on a branch could also succeed; only a run of master's copy counts.
    if git cat-file -e "${run_sha}^{commit}" 2>/dev/null && git merge-base --is-ancestor "$run_sha" origin/master; then
        approved="$run_id"
        break
    fi
done <<< "$runs"
[ -n "$approved" ] || die "No successful release-candidate run from master for $sha: run the Release candidate workflow for it first"
info "Release candidate run $approved passed for $sha"

if [ "$sha" = "$staging" ]; then
    info "Staging already points at $sha; redeploying the same release"
    move="none"
elif git merge-base --is-ancestor "$staging" "$sha"; then
    move="fast-forward"
elif [ "$rollback" -eq 1 ] && git merge-base --is-ancestor "$sha" "$staging"; then
    move="rollback"
else
    die "origin/staging ($staging) is not an ancestor of $sha; pass --rollback to deploy an older approved release"
fi
info "Branch move after the deploy: $move ($staging -> $sha)"

release="$(mktemp -d "${TMPDIR:-/tmp}/praho-release.XXXXXXXXXX")"
rmdir "$release"
git worktree add --quiet --detach "$release" "$sha"
method="$(PYTHONPATH="$release/deploy/scripts" "$python" -c \
    'import sys; from native_env import read_env; print(read_env(__import__("pathlib").Path(sys.argv[1])).get("DEPLOY_METHOD", "git"))' \
    "$env_file")" || die "Could not read $env_file with the deploy's parser"
[ "$method" = "git" ] || die "DEPLOY_METHOD is '$method' in .env.staging: only a git deploy installs exactly the approved commit"

if [ "$dry_run" -eq 1 ]; then
    echo "✅ Dry run: every check passed. A real run deploys $sha from a clean checkout of it, then moves staging."
    exit 0
fi

echo "🚀 Deploying $sha to staging from a clean checkout of it..."
"$python" "$release/deploy/scripts/native_env.py" run --env staging --env-file "$env_file" --version "$sha" \
    || die "The deploy of $sha failed partway or at its checks: staging's state is unknown until a deploy succeeds. origin/staging still names $staging."

if [ "$move" != "none" ]; then
    # A non-fast-forward (the rollback) needs the admin bypass on the staging ruleset; the lease holds either way.
    git push --force-with-lease="staging:$staging" origin "$sha:refs/heads/staging" \
        || die "Staging now RUNS $sha, but moving origin/staging failed (it moved since $staging, or the push was refused). Check the branch, then re-run promote-staging for the release staging should run."
fi
echo "✅ Staging runs $sha, and origin/staging names it."
