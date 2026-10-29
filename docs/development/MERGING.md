# Merging a pull request

How a pull request reaches `master`. Opening one is in [CONTRIBUTING.md](../../CONTRIBUTING.md);
releasing what merged is in [DEPLOYMENT.md](../deployment/DEPLOYMENT.md#promoting-a-release-to-staging).
Why the rules are what they are: [ADR-0036](../ADRs/ADR-0036-tiered-ci-testing-strategy.md) and
[`.github/rulesets/README.md`](../../.github/rulesets/README.md).

## How `master` merges

Every change reaches `master` through the **merge queue**, as a squash. A branch does not need to be up
to date with `master`: the queue tests it on the current `master` itself.

For each pull request it accepts, the queue:

1. builds a commit: `master`, plus every pull request queued ahead of it, plus this one, squashed;
2. runs every required check on that commit, including the Virtualmin lab when the change can reach it;
3. when that commit's own checks pass, moves `master` to exactly that commit.

So the commit on `master` is the commit that was tested. The release candidate relies on it.

## Before you queue

- **Every required check is green on the pull request.** The lab reports *skipped* there; it runs in the
  queue.
- **The title and description are the commit message.** The squash takes the pull request's title as
  its subject and its description as its body. Write them as a commit message:
  - a [Conventional Commits](https://www.conventionalcommits.org/) title;
  - what changed and why, not a log of the branch;
  - `Closes #N` in the description for each issue it closes (a `#N` in the title closes nothing);
  - the last line is your sign-off: `Signed-off-by: Your Name <you@example.com>`.

  The DCO check refuses a description without a sign-off line, and checks the queue's squash too. It runs
  again when you edit the description.

## Queueing

Use **Merge when ready** on the pull request, or:

```bash
gh pr merge <number>
```

Queue a pull request once its checks are green: the repository does not allow auto-merge, so
`gh pr merge` refuses one whose checks are still running.

A queued pull request needs nothing more from you. Up to five are built at once; each lands only when its
own commit is green, and `master` moves in queue order. A queued branch accepts no pushes: to change it,
remove it from the queue first, then push and queue it again.

## When the queue removes a pull request

The queue drops a pull request, and rebuilds the ones behind it, when:

- a required check fails or does not report within 150 minutes;
- it conflicts with `master` or with a pull request ahead of it;
- a new commit is pushed to it.

Fix the cause on the branch and queue it again. A check that fails for reasons outside the change is a
flaky test: fix it, never retry it away ([ADR-0014](../ADRs/ADR-0014-no-test-suppression-policy.md)).

## The Virtualmin lab before queueing

The lab takes about an hour and runs only in the queue. To learn its result first, run the full lab on
your branch:

```bash
gh workflow run virtualmin-lab.yml --ref <branch> -f suite=full
```

## Pull requests that build on each other

Open each one against `master`, not against the other's branch. Queue the second only after the first has
landed. The queue builds squashes: where the second changes code the first adds, its change meets the
first's squash as a conflict, and the queue removes it. Once the first is on `master`, merge `master` into
the second branch with a sign-off (`git merge --signoff origin/master`). Where both sides changed the same
lines, keep the second's version, which already contains the first's; take `master`'s version everywhere
else. Then push and queue it.

## Merging around the queue

An organization admin can bypass the queue in an emergency. The release candidate refuses a commit that
the queue never tested, so land a follow-up through the queue before the next release.
