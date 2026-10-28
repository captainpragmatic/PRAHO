# Repository rulesets

GitHub keeps rulesets in the repository settings, not in git. These files are the reviewed source of
truth; apply a change to them with `gh api` after it merges, so the live rules never drift from what
was reviewed. See ADR-0036 for why each rule exists.

| File | Target | What it enforces |
|---|---|---|
| `master.json` | `master` | Changes arrive by pull request, squash merge only; every required check passes on an up-to-date branch; no force push or deletion. The organization admin may bypass on a pull request, never by a direct push |
| `staging.json` | `staging` | Only the organization admin moves it (`make promote-staging` pushes as the owner); no deletion; a non-fast-forward only by that bypass (`--rollback`) |
| `release-tags.json` | `v*` tags | Only the organization admin creates, moves or deletes a release tag |

`tests/integration/test_ci_required_checks.py` checks `master.json` against the workflows: every
required check must be a job that every pull request to `master` starts, and only the GitHub Actions
app (integration id 15368) may satisfy it.

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

After applying, prove the rules with a throwaway pull request: a failing check blocks the merge, a
direct push to `master` is rejected, and a docs-only change still reports every required check.

Applied on 2026-10-28 (ids 26026153, 26026156, 26026158).
