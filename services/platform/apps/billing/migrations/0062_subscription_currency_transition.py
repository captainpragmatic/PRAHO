"""Add a notice ledger; existing subscriptions and financial records are untouched."""

import uuid

import django.db.models.deletion
import django_fsm
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("billing", "0061_frozen_cycle_terms"), ("notifications", "0002_initial")]

    operations = [migrations.CreateModel(
        name="SubscriptionCurrencyTransition",
        fields=[
            ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
            ("policy_revision", models.PositiveIntegerField()),
            ("old_terms", models.JSONField()), ("target_terms", models.JSONField()),
            ("target_fingerprint", models.CharField(max_length=64)),
            ("status", django_fsm.FSMField(max_length=20, default="pending", protected=True, choices=[
                ("pending", "Pending notice"), ("notified", "Notice accepted"),
                ("committed", "Renewal document prepared"), ("superseded", "Superseded"),
            ])),
            ("notice_recipient", models.EmailField(blank=True, max_length=254)),
            ("notice_subject", models.CharField(max_length=255)), ("notice_body", models.TextField()),
            ("notice_attempted_at", models.DateTimeField(blank=True, null=True)),
            ("notice_accepted_at", models.DateTimeField(blank=True, null=True)),
            ("preparation_not_before", models.DateTimeField(blank=True, null=True)),
            ("effective_period_start", models.DateTimeField(blank=True, null=True)),
            ("hold_reason", models.CharField(blank=True, max_length=255)),
            ("last_error", models.CharField(blank=True, max_length=255)),
            ("created_at", models.DateTimeField(auto_now_add=True)), ("updated_at", models.DateTimeField(auto_now=True)),
            ("subscription", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT,
                                              related_name="currency_transitions", to="billing.subscription")),
            ("notice_email", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT,
                                              to="notifications.emaillog")),
            ("committed_cycle", models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT,
                                                    to="billing.billingcycle")),
        ],
        options={
            "db_table": "billing_subscription_currency_transitions", "ordering": ("created_at",),
            "constraints": [
                models.UniqueConstraint(fields=("subscription",), condition=models.Q(status__in=["pending", "notified"]),
                                        name="one_open_subscription_currency_offer"),
                models.CheckConstraint(condition=models.Q(status__in=["pending", "notified", "committed", "superseded"]),
                                       name="subscription_currency_transition_status"),
            ],
        },
    )]
