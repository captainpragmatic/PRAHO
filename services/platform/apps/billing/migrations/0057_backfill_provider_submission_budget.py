"""Rows that pre-date `submissions` keep the retry budget they already spent.

`0055` added `ProviderIssuance.submissions` with `default=0`. That satisfied the column and
contradicted all three of its consumers - `sweep_pending_issuances`' `submissions__lt` filter,
`_claim`'s cap check, and the exhausted gauge's `submissions__gte` count - so every row written
before it read as though it had never submitted anything, and would have been handed a full
budget of POSTs against a rate-limited third party on deploy day.

`attempts` is the only durable count of work already done, and it is not the same count: it
increments in `claim()`, before the rate gate, so a row that `release_unsent` only ever
deferred has burned attempts while sending nothing. No field separates the two after the fact.
`mark_failed` is called without a `response` and writes `{}`, so three refused POSTs and three
pacing deferrals leave an identical row - same state, same empty response, `last_error` holding
only whichever happened last.

So this over-counts, deliberately. The cap exists to stop a permanent validation error being
resubmitted forever against a rate-limited provider, not to prevent duplicate documents: a
refusal earns REJECTED only from a recognised refusal envelope, and a reply that could not be
classified goes to `outcome_unknown`, which no sweep touches and `claim()` has no path out of.
So over-counting costs one invoice not issued until an operator looks at it, and under-counting
costs futile POSTs - the exact thing the cap is for. Over-counting is the cheaper error.

A row over-counted this way lands in a state `_finalize` can never produce: `pending` at the
cap. Both readers of the column had narrowed to `state=FAILED` because that was the only way to
reach it, so this ships alongside those predicates widened to the sweep's own state set. Without
that, an over-counted row would be listed nowhere at all - not by the gauge, not by the
reconciliation queue, and `adopt_provider_document` accepts only `outcome_unknown`.

Numbered invoices are skipped. The document exists, so the budget is spent by definition, and
recording it could only park the row behind an operator screen it does not belong on.
"""

from __future__ import annotations

from django.db import migrations
from django.db.models import F

# Snapshotted rather than imported from `issuers.models`: a migration must keep describing what
# it did on the day it ran, even if the cap is raised later.
_MAX_SUBMISSIONS = 3


def carry_forward_spent_budget(apps, schema_editor):
    issuance = apps.get_model("billing", "ProviderIssuance")
    # `submissions=0` is the guard that makes this re-runnable and keeps it from ever lowering
    # a count that real work produced.
    unrecorded = issuance.objects.filter(submissions=0, invoice__number__isnull=True)

    capped = unrecorded.filter(attempts__gte=_MAX_SUBMISSIONS).update(submissions=_MAX_SUBMISSIONS)
    carried = unrecorded.filter(attempts__gt=0, attempts__lt=_MAX_SUBMISSIONS).update(submissions=F("attempts"))

    if capped or carried:
        print(
            f"\n  Provider submission budget: {capped} row(s) capped at {_MAX_SUBMISSIONS}, "
            f"{carried} carried forward from attempts"
        )


def keep_the_repair(apps, schema_editor):
    # No-op, and not for want of an inverse: there is no earlier value to return to. Every row
    # this touched held 0 only because the column had just been added with that default, so
    # restoring it would re-create the defect this migration exists to remove.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0056_repair_credit_note_document_types"),
    ]

    operations = [
        migrations.RunPython(carry_forward_spent_budget, keep_the_repair),
    ]
