#!/usr/bin/env bash
# Promote a release candidate to staging.
#
#   scripts/promote_staging.sh [--dry-run] [--rollback] <sha>      (or: make promote-staging SHA=<sha>)
#
# 1. The commit must be on origin/master and carry the commit status `release-candidate` = success,
#    which only release-candidate.yml posts, after every release check passed on that exact commit.
# 2. It is deployed with `make deploy-staging VERSION=<sha>` (the playbook's pre- and post-checks).
# 3. Only after the deploy succeeds does origin/staging move to it, so the branch always names what
#    staging runs. A forward move must be a fast-forward. --rollback allows an OLDER approved commit
#    and moves the branch back with a lease on its current value.
#
# Runs anywhere with git, gh (authenticated for this repository) and the staging deploy inputs; it
# assumes nothing about the machine beyond that. Works with macOS bash 3.2.
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
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        -*) die "Unknown option: $1" ;;
        *) [ -z "$candidate" ] || die "Give exactly one commit"; candidate="$1" ;;
    esac
    shift
done
[ -n "$candidate" ] || die "Usage: $0 [--dry-run] [--rollback] <sha>"
[[ "$candidate" =~ ^[0-9a-fA-F]{7,40}$ ]] || die "Not a commit SHA: $candidate"

cd "$(git rev-parse --show-toplevel)"
command -v gh >/dev/null 2>&1 || die "gh is not installed"

info "Fetching master and staging from origin..."
git fetch --quiet origin master staging

sha="$(git rev-parse --verify --quiet "${candidate}^{commit}")" || die "Unknown commit: $candidate"
staging="$(git rev-parse origin/staging)"

git merge-base --is-ancestor "$sha" origin/master || die "$sha is not on master"
info "On master: $sha"

state="$(gh api "repos/{owner}/{repo}/commits/$sha/status" \
    --jq '[.statuses[] | select(.context == "release-candidate")][0].state // "missing"')" \
    || die "Could not read the commit status from GitHub (is gh authenticated?)"
[ "$state" = "success" ] \
    || die "release-candidate is '$state' on $sha: run the Release candidate workflow for it first"
info "release-candidate status: success"

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

if [ "$dry_run" -eq 1 ]; then
    echo "✅ Dry run: every check passed. A real run deploys with 'make deploy-staging VERSION=$sha', then moves staging."
    exit 0
fi

echo "🚀 Deploying $sha to staging..."
make deploy-staging VERSION="$sha" || die "The deploy failed; origin/staging still points at $staging"

case "$move" in
    fast-forward) git push origin "$sha:refs/heads/staging" ;;
    rollback) git push --force-with-lease="staging:$staging" origin "$sha:refs/heads/staging" ;;
    none) ;;
esac
echo "✅ Staging runs $sha, and origin/staging names it."
