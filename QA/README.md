# QA

| Path | What it is |
|---|---|
| [`plan.md`](plan.md) | **Living spec.** The portal checklist, annotated with the automated test that now enforces each phase |
| [`cycle-02-v0.30.0/findings.md`](cycle-02-v0.30.0/findings.md) | **Current cycle.** Findings, evidence, and what is still open |
| [`cycle-02-v0.30.0/phase-4-survey.md`](cycle-02-v0.30.0/phase-4-survey.md) | Cycle 2's route, assertion-quality and suppressed-gate survey |
| Cycle 1 (v0.21.0) | Closed; read it from history: `git show 57e9c124:QA/cycle-01-v0.21.0/qa_report.md` (also `action_log.md`, `mobile_pass_plan.md`, `README.md`) |

## How this is meant to work

A cycle folder is dated evidence. While a cycle is open, it is corrected only by dated additions, never
by rewriting what it said, because cycle 3 has to be able to compare against what cycle 2 actually
said. Once a cycle closes and every open item has been carried into the next one, the folder leaves
the tree and is read from git history at a pinned commit. That is where the comparison still works,
and it keeps the tree to what is current. `plan.md` is the opposite: it is carried forward and corrected.

Every finding belongs in one of four states — PASS, FAIL, BLOCKED, NOT-RUN — and PASS requires
naming the test that fails if the fix is reverted. "Tests pass" is not evidence of anything except
the absence of regression.

The reason cycle 1 went stale for six months is recorded in
[`cycle-02-v0.30.0/findings.md`](cycle-02-v0.30.0/findings.md#root-cause-of-the-staleness-by-5-whys),
and it was not laziness: end-to-end QA work moved no number anyone watched. The browser suite ran
in no CI workflow and reported `--no-cov`. The nightly job that was meant to fix that (#543,
2026-09-28) is the load-bearing change — and it failed at its "Set up Node" step on each of its
first seven nights, 2026-09-29 to 10-05, before a browser was ever installed, because the
`package-lock.json` it installs from was gitignored and existed on no runner. Nobody noticed: a red
scheduled job notifies no one, so the same root cause recurred one level up. The lockfile is tracked
since 2026-10-06 and a guard test (`services/platform/tests/common/test_ci_node_lockfile.py`) keeps it that way. The
job's first green run is the evidence that the suite runs nightly; until then no document here may
claim it.

## The gates a cycle runs

Read the nightly's real results first. Every number below is only as good as the job that produces
it, and this programme has now twice believed a gate that was not running:

```bash
gh run list --workflow nightly.yml -L 7   # both jobs green, on the branch you are about to claim
```

Then:

```bash
make lint                # 11 phases (0-10), including the settings guardrail's 6 checks
make test-platform       # Django suite
make test-portal         # plus the portal DB-isolation guard
make test-integration    # cross-service HMAC
make test-e2e-coverage   # browser suite, both services live, server-side coverage
make coverage-portal-union
make coverage-platform-packages
```
