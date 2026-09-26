# QA

| Path | What it is |
|---|---|
| [`plan.md`](plan.md) | **Living spec.** The portal checklist, annotated with the automated test that now enforces each phase |
| [`cycle-02-v0.30.0/findings.md`](cycle-02-v0.30.0/findings.md) | **Current cycle.** Findings, evidence, and what is still open |
| [`cycle-01-v0.21.0/`](cycle-01-v0.21.0/) | Cycle 1 evidence, preserved unedited |

## How this is meant to work

A cycle folder is dated evidence and is never edited afterwards — cycle 3 has to be able to compare
against what cycle 2 actually said. `plan.md` is the opposite: it is carried forward and corrected.

Every finding belongs in one of four states — PASS, FAIL, BLOCKED, NOT-RUN — and PASS requires
naming the test that fails if the fix is reverted. "Tests pass" is not evidence of anything except
the absence of regression.

The reason cycle 1 went stale for six months is recorded in
[`cycle-02-v0.30.0/findings.md`](cycle-02-v0.30.0/findings.md#root-cause-of-the-staleness-by-5-whys),
and it was not laziness: end-to-end QA work moved no number anyone watched. The browser suite ran
in no CI workflow and reported `--no-cov`. That is fixed, and it is the load-bearing change — the
documents were the symptom.

## The gates a cycle runs

```bash
make lint                # 8 phases, including the settings guardrail's 6 checks
make test-platform       # Django suite
make test-portal         # plus the portal DB-isolation guard
make test-integration    # cross-service HMAC
make test-e2e-coverage   # browser suite, both services live, server-side coverage
make coverage-portal-union
make coverage-platform-packages
```
