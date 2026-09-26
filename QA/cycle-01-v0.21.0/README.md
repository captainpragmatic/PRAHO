# QA cycle 1 — v0.21.0 (executed 2026-03-05)

Point-in-time evidence from the first portal walkthrough, preserved unedited. Do not update these
files: cycle 2 needs to be able to compare against what cycle 1 actually said, and an edited
report cannot answer the only question that matters about a QA programme — is it working?

| File | What it is |
|---|---|
| `qa_report.md` | The findings: 2 CRITICAL, 3 HIGH, 9 MEDIUM, 6 LOW |
| `action_log.md` | The step-by-step record of the walkthrough |
| `mobile_pass_plan.md` | The planned mobile pass |

## What cycle 1 got right, and the one thing it got wrong

The methodology worked. Its findings became regression tests — the `terms_accepted` CRITICAL is
enforced today by `services/portal/tests/users/test_registration_terms.py`, and that test still
fails if the fix is reverted. That is the bar.

What it got wrong was accounting, and it is worth stating plainly because it is the failure mode a
QA document invites. The report recorded "11/11 checks PASS" in a summary table while the body of
the same document described known breakage, because PASS was being used for "I looked at it" rather
than "it did what it should". Cycle 2 separates PASS / FAIL / BLOCKED / NOT-RUN and never collapses
them into a ratio.

The deeper reason it was never re-run is in `../cycle-02-v0.30.0/findings.md`: end-to-end QA work
moved no number anyone watched. That is now fixed — the browser suite runs nightly and reports
coverage.
