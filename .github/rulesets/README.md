# Repository rulesets

GitHub keeps rulesets in the repository settings, not in git. These files are the reviewed source of
truth; apply a change to them with `gh api` after it merges, so the live rules never drift from what
was reviewed. See ADR-0036 for why each rule exists.

| File | Target | What it enforces |
|---|---|---|
| `master.json` | `master` | Changes arrive by pull request through the merge queue, squash merge only; every required check passes on the pull request and again on the queue's commit; no force push or deletion. The organization admin may bypass on a pull request, never by a direct push |
| `staging.json` | `staging` | Only the organization admin moves it (`make promote-staging` pushes as the owner); no deletion; a non-fast-forward only by that bypass (`--rollback`) |
| `release-tags.json` | `v*` tags | Only the organization admin creates, moves or deletes a release tag |

`tests/integration/test_ci_required_checks.py` checks `master.json` against the workflows: every
required check must be a job that every pull request to `master` and every merge group starts, the
queue must outwait the slowest required job, and only the GitHub Actions app (integration id 15368) may
satisfy a check.

The queue takes a squash's message from the repository's merge settings, which the rulesets do not
hold. Set them with the rulesets: the pull request's title and description.

```bash
gh api --method PATCH "repos/$repo" -f squash_merge_commit_title=PR_TITLE -f squash_merge_commit_message=PR_BODY
```

## Applying

```bash
unset GH_TOKEN  # use the keyring login, which carries admin rights on the repository
repo=captainpragmatic/PRAHO

# First time: create each ruleset.
for file in master staging release-tags; do
  gh api --method POST "repos/$repo/rulesets" --input ".github/rulesets/$file.json"
done

# Later changes: update the existing ruleset by id, matched on its name.
id=$(gh api "repos/$repo/rulesets" --jq ".[] | select(.name == \"$(jq -r .name .github/rulesets/master.json)\") | .id")
gh api --method PUT "repos/$repo/rulesets/$id" --input .github/rulesets/master.json
```

Apply `master.json` only after the workflows that run on `merge_group` are on `master`: a queue whose
checks never start waits until it times out.

After applying, prove the rules with a throwaway pull request: a failing check blocks the merge, a
direct push to `master` is rejected, a docs-only change still reports every required check, and a pull
request behind `master` enters the queue, skips the lab on the pull request and runs it in the queue.
Check that `master` then sits on the commit the queue tested: the release candidate relies on it.

Applied on 2026-10-28 (ids 26026153, 26026156, 26026158).
