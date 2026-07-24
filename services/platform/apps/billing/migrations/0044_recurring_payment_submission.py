import django.db.models.deletion
import django_fsm
from django.db import migrations, models

_BACKFILL_BATCH_SIZE = 500


def backfill_unfinished_recurring_submissions(apps, schema_editor) -> None:
    Payment = apps.get_model("billing", "Payment")
    RecurringPaymentSubmission = apps.get_model("billing", "RecurringPaymentSubmission")
    database_alias = schema_editor.connection.alias

    submissions = []
    payments = (
        Payment.objects.using(database_alias)
        .filter(
            payment_method="stripe",
            idempotency_key__isnull=False,
            meta__source="recurring_billing",
        )
        .filter(
            models.Q(status="pending")
            | (
                models.Q(status="succeeded", proforma__isnull=False)
                & ~models.Q(proforma__status="converted")
            )
        )
        .exclude(idempotency_key="")
        .iterator(chunk_size=_BACKFILL_BATCH_SIZE)
    )
    for payment in payments:
        is_bound = bool(payment.gateway_txn_id)
        submissions.append(
            RecurringPaymentSubmission(
                payment_id=payment.id,
                state="submitted" if is_bound else "manual_review",
                claimed_at=(payment.updated_at or payment.created_at) if is_bound else None,
                submitted_at=(payment.updated_at or payment.created_at) if is_bound else None,
                attempt_count=1 if is_bound else 0,
            )
        )
        if len(submissions) == _BACKFILL_BATCH_SIZE:
            RecurringPaymentSubmission.objects.using(database_alias).bulk_create(submissions)
            submissions.clear()
    if submissions:
        RecurringPaymentSubmission.objects.using(database_alias).bulk_create(submissions)


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0043_billing_operator_controls"),
    ]

    operations = [
        migrations.CreateModel(
            name="RecurringPaymentSubmission",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "state",
                    django_fsm.FSMField(
                        choices=[
                            ("reserved", "Reserved"),
                            ("in_flight", "In flight"),
                            ("submitted", "Submitted"),
                            ("abandoned", "Abandoned"),
                            ("manual_review", "Manual review"),
                        ],
                        default="reserved",
                        max_length=24,
                        protected=True,
                    ),
                ),
                ("claimed_at", models.DateTimeField(blank=True, null=True)),
                ("submitted_at", models.DateTimeField(blank=True, null=True)),
                ("attempt_count", models.PositiveIntegerField(default=0)),
                ("reconcile_claim_token", models.UUIDField(blank=True, editable=False, null=True)),
                ("reconcile_claim_expires_at", models.DateTimeField(blank=True, editable=False, null=True)),
                ("last_error", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "payment",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="recurring_submission",
                        to="billing.payment",
                    ),
                ),
            ],
            options={
                "db_table": "billing_recurring_payment_submissions",
                "ordering": ("created_at", "id"),
            },
        ),
        migrations.AddIndex(
            model_name="recurringpaymentsubmission",
            index=models.Index(fields=["state", "claimed_at"], name="recurring_submit_state_idx"),
        ),
        migrations.AddIndex(
            model_name="recurringpaymentsubmission",
            index=models.Index(fields=["state", "submitted_at"], name="recurring_submitted_at_idx"),
        ),
        migrations.AddIndex(
            model_name="recurringpaymentsubmission",
            index=models.Index(fields=["reconcile_claim_expires_at"], name="recurring_reconcile_lease_idx"),
        ),
        migrations.AddConstraint(
            model_name="recurringpaymentsubmission",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    state__in=["reserved", "in_flight", "submitted", "abandoned", "manual_review"]
                ),
                name="recurring_submission_state_valid",
            ),
        ),
        migrations.AddConstraint(
            model_name="recurringpaymentsubmission",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(
                        state__in=["reserved", "abandoned", "manual_review"],
                        claimed_at__isnull=True,
                        submitted_at__isnull=True,
                        attempt_count=0,
                    )
                    | models.Q(
                        state="in_flight",
                        claimed_at__isnull=False,
                        submitted_at__isnull=True,
                        attempt_count__gte=1,
                    )
                    | models.Q(
                        state="submitted",
                        claimed_at__isnull=False,
                        submitted_at__isnull=False,
                        attempt_count__gte=1,
                    )
                ),
                name="recurring_submission_claim_consistent",
            ),
        ),
        migrations.AddConstraint(
            model_name="recurringpaymentsubmission",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(reconcile_claim_token__isnull=True, reconcile_claim_expires_at__isnull=True)
                    | models.Q(reconcile_claim_token__isnull=False, reconcile_claim_expires_at__isnull=False)
                ),
                name="recurring_reconcile_claim_consistent",
            ),
        ),
        migrations.RunPython(backfill_unfinished_recurring_submissions, migrations.RunPython.noop),
    ]
