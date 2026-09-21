"""Widen ``Refund.reason`` to the vocabulary the refund forms actually offer, and canonicalize
the ``reason`` and ``refund_type`` values written before anything canonicalized them.

The four staff refund selects and the portal's customer-facing one offered eleven reasons.
Only three were valid ``REASON_CHOICES`` values. Django does not run ``full_clean()`` on
``objects.create()``, so the other eight were accepted and stored as-is — a refund reading
"Quality Not As Expected" carried a value no filter or report could match, and nothing failed.

Six of those terms are genuinely new concepts and are added to the field. Three were merely
different spellings of choices that already existed, so the templates were corrected to the
canonical spelling (labels untouched) and the rows already written under the old spellings are
migrated here. ``"API refund request"`` was the API endpoint's default and was never valid.

``refund_type`` is migrated for a different and sharper reason. The service now canonicalizes
it on both sides of the idempotency probe, folding an absent or empty value to ``"full"``.
Before that, an empty POST field was probed *and* written as ``""``. A pending row left holding
``""`` across this deployment would therefore be invisible to the new probe, and the retry that
found nothing would reserve a **second refund against the same payment**. Canonicalizing the
stored values closes that window rather than teaching the probe to match both spellings.
"""

from django.db import migrations, models
from django.db.models import Case, Value, When

# Old spelling -> the canonical choice it always meant.
#
# `""` maps to "other", not "customer_request": empty means "not supplied", and the forms
# offer blank and customer_request as distinct selections. Converting it to an affirmative
# customer request would invent an audit claim. "other" is a new choice that says exactly
# what is known about these rows.
REASON_ALIASES = {
    "dispute_resolution": "dispute",
    "duplicate_invoice": "duplicate_payment",
    "duplicate_order": "duplicate_payment",
    "cancellation_request": "cancellation",
    "API refund request": "customer_request",
    "": "other",
}

# Non-canonical `refund_type` values reachable before canonicalization: an empty POST field,
# an explicit None stringified by the ORM, and the enum members the legacy wrappers default to.
REFUND_TYPE_ALIASES = {
    "": "full",
    "None": "full",
    "RefundType.FULL": "full",
    "RefundType.PARTIAL": "partial",
}


def _canonicalize(model, field, aliases):
    """One conditional UPDATE per column rather than one per alias.

    Neither column is indexed, so a filter-per-alias would scan the table once per entry.
    The `__in` filter keeps this to a single pass touching only rows that need changing.
    """
    model.objects.filter(**{f"{field}__in": list(aliases)}).update(
        **{field: Case(*[When(**{field: old}, then=Value(new)) for old, new in aliases.items()])}
    )


def canonicalize_values(apps, schema_editor):
    Refund = apps.get_model("billing", "Refund")
    _canonicalize(Refund, "reason", REASON_ALIASES)
    _canonicalize(Refund, "refund_type", REFUND_TYPE_ALIASES)


def noop_reverse(apps, schema_editor):
    """Deliberately not reversible.

    Several historic spellings collapse onto one canonical value, so no faithful inverse
    exists — rolling back cannot tell a row migrated from ``dispute_resolution`` apart from
    one that was always ``dispute``. The widened field is harmless on the old code path.
    """


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0047_seed_supported_currencies"),
    ]

    operations = [
        migrations.AlterField(
            model_name="refund",
            name="reason",
            field=models.CharField(
                choices=[
                    ("customer_request", "Customer Request"),
                    ("error_correction", "Error Correction"),
                    ("dispute", "Dispute"),
                    ("service_failure", "Service Failure"),
                    ("duplicate_payment", "Duplicate Payment"),
                    ("fraud", "Fraud"),
                    ("cancellation", "Cancellation"),
                    ("downgrade", "Downgrade"),
                    ("administrative", "Administrative"),
                    ("quality_issue", "Quality Issue"),
                    ("technical_issue", "Technical Issue"),
                    ("billing_error", "Billing Error"),
                    ("policy_violation", "Policy Violation"),
                    ("unsatisfied_service", "Unsatisfied Service"),
                    ("other", "Other"),
                ],
                default="customer_request",
                max_length=50,
            ),
        ),
        migrations.RunPython(canonicalize_values, noop_reverse),
    ]
