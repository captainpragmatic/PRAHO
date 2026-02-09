"""
Add Subscription, SubscriptionChange, SubscriptionItem, and PriceGrandfathering models.
Also adds idempotency_key to Payment model.

This migration adds comprehensive recurring billing support with:
- Subscription model for recurring billing lifecycle
- Price grandfathering for existing customers during price changes
- Subscription changes with proration tracking
- Multi-product subscription items
- Payment idempotency for safe retries
"""

import uuid

import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0009_alter_refundstatushistory_previous_status"),
        ("customers", "0003_rename_payment_method_field"),
        ("products", "0002_alter_product_options_alter_productbundle_options_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # Add idempotency_key to Payment model
        migrations.AddField(
            model_name="payment",
            name="idempotency_key",
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text="Unique key to prevent duplicate payment processing",
                max_length=64,
                null=True,
                unique=True,
            ),
        ),
        # Create Subscription model
        migrations.CreateModel(
            name="Subscription",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "subscription_number",
                    models.CharField(
                        help_text="Unique subscription identifier (e.g., SUB-000001)",
                        max_length=50,
                        unique=True,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("trialing", "Trialing"),
                            ("active", "Active"),
                            ("past_due", "Past Due"),
                            ("paused", "Paused"),
                            ("cancelled", "Cancelled"),
                            ("expired", "Expired"),
                            ("pending", "Pending Activation"),
                        ],
                        db_index=True,
                        default="pending",
                        max_length=20,
                    ),
                ),
                (
                    "billing_cycle",
                    models.CharField(
                        choices=[
                            ("monthly", "Monthly"),
                            ("quarterly", "Quarterly"),
                            ("semi_annual", "Semi-Annual"),
                            ("yearly", "Yearly"),
                            ("custom", "Custom"),
                        ],
                        default="monthly",
                        max_length=20,
                    ),
                ),
                (
                    "custom_cycle_days",
                    models.PositiveIntegerField(
                        blank=True,
                        help_text="Custom billing cycle in days (only if billing_cycle='custom')",
                        null=True,
                        validators=[
                            django.core.validators.MinValueValidator(1),
                            django.core.validators.MaxValueValidator(730),
                        ],
                    ),
                ),
                (
                    "unit_price_cents",
                    models.BigIntegerField(
                        help_text="Current billing amount per cycle in cents",
                        validators=[django.core.validators.MinValueValidator(0)],
                    ),
                ),
                (
                    "locked_price_cents",
                    models.BigIntegerField(
                        blank=True,
                        help_text="Grandfathered price if customer is on legacy pricing",
                        null=True,
                        validators=[django.core.validators.MinValueValidator(0)],
                    ),
                ),
                (
                    "locked_price_reason",
                    models.CharField(
                        blank=True,
                        help_text="Reason for locked pricing (e.g., 'Early adopter discount')",
                        max_length=200,
                    ),
                ),
                (
                    "locked_price_expires_at",
                    models.DateTimeField(
                        blank=True,
                        help_text="When grandfathered pricing expires (null = never)",
                        null=True,
                    ),
                ),
                (
                    "quantity",
                    models.PositiveIntegerField(
                        default=1,
                        help_text="Number of units (e.g., seats, domains, GB)",
                        validators=[django.core.validators.MinValueValidator(1)],
                    ),
                ),
                (
                    "current_period_start",
                    models.DateTimeField(help_text="Start of current billing period"),
                ),
                (
                    "current_period_end",
                    models.DateTimeField(help_text="End of current billing period"),
                ),
                (
                    "next_billing_date",
                    models.DateTimeField(
                        db_index=True,
                        help_text="Date when next invoice will be generated",
                    ),
                ),
                (
                    "trial_start",
                    models.DateTimeField(blank=True, help_text="When trial period started", null=True),
                ),
                (
                    "trial_end",
                    models.DateTimeField(blank=True, help_text="When trial period ends", null=True),
                ),
                ("trial_converted", models.BooleanField(default=False, help_text="Whether trial has converted to paid subscription")),
                (
                    "started_at",
                    models.DateTimeField(blank=True, help_text="When subscription became active", null=True),
                ),
                (
                    "cancelled_at",
                    models.DateTimeField(blank=True, help_text="When subscription was cancelled", null=True),
                ),
                (
                    "cancel_at_period_end",
                    models.BooleanField(
                        default=False,
                        help_text="If true, cancel at end of current period instead of immediately",
                    ),
                ),
                (
                    "cancellation_reason",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("customer_request", "Customer Request"),
                            ("non_payment", "Non-Payment"),
                            ("fraud", "Fraud"),
                            ("service_issue", "Service Issue"),
                            ("upgrade", "Upgrade to Different Plan"),
                            ("downgrade", "Downgrade to Different Plan"),
                            ("business_closed", "Business Closed"),
                            ("competitor", "Switched to Competitor"),
                            ("other", "Other"),
                        ],
                        max_length=50,
                    ),
                ),
                ("cancellation_feedback", models.TextField(blank=True, help_text="Customer feedback on cancellation")),
                ("paused_at", models.DateTimeField(blank=True, null=True)),
                (
                    "resume_at",
                    models.DateTimeField(blank=True, help_text="Scheduled date to resume paused subscription", null=True),
                ),
                (
                    "ended_at",
                    models.DateTimeField(blank=True, help_text="When subscription actually ended", null=True),
                ),
                (
                    "payment_method_id",
                    models.CharField(
                        blank=True,
                        help_text="Stripe PaymentMethod ID or other gateway reference",
                        max_length=255,
                    ),
                ),
                ("last_payment_date", models.DateTimeField(blank=True, null=True)),
                ("last_payment_amount_cents", models.BigIntegerField(blank=True, null=True)),
                (
                    "failed_payment_count",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Consecutive failed payment attempts",
                    ),
                ),
                (
                    "grace_period_days",
                    models.PositiveIntegerField(
                        default=7,
                        help_text="Days of grace after payment failure before suspension",
                    ),
                ),
                (
                    "grace_period_ends_at",
                    models.DateTimeField(
                        blank=True,
                        help_text="When grace period expires (set on payment failure)",
                        null=True,
                    ),
                ),
                (
                    "stripe_subscription_id",
                    models.CharField(
                        blank=True,
                        db_index=True,
                        help_text="Stripe Subscription ID for syncing",
                        max_length=100,
                    ),
                ),
                (
                    "external_reference",
                    models.CharField(blank=True, help_text="External system reference if applicable", max_length=255),
                ),
                ("meta", models.JSONField(blank=True, default=dict, help_text="Additional subscription metadata")),
                ("notes", models.TextField(blank=True, help_text="Internal notes about this subscription")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="created_subscriptions",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "currency",
                    models.ForeignKey(
                        help_text="Currency for this subscription",
                        on_delete=django.db.models.deletion.PROTECT,
                        to="billing.currency",
                    ),
                ),
                (
                    "customer",
                    models.ForeignKey(
                        help_text="Customer who owns this subscription",
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="subscriptions",
                        to="customers.customer",
                    ),
                ),
                (
                    "product",
                    models.ForeignKey(
                        help_text="Product/plan being subscribed to",
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="subscriptions",
                        to="products.product",
                    ),
                ),
            ],
            options={
                "verbose_name": "Subscription",
                "verbose_name_plural": "Subscriptions",
                "db_table": "subscriptions",
                "ordering": ("-created_at",),
            },
        ),
        # Add indexes to Subscription
        migrations.AddIndex(
            model_name="subscription",
            index=models.Index(fields=["customer", "status"], name="billing_sub_cust_status_idx"),
        ),
        migrations.AddIndex(
            model_name="subscription",
            index=models.Index(fields=["status", "next_billing_date"], name="billing_sub_status_billing_idx"),
        ),
        migrations.AddIndex(
            model_name="subscription",
            index=models.Index(fields=["product", "status"], name="billing_sub_prod_status_idx"),
        ),
        # Add constraints to Subscription
        migrations.AddConstraint(
            model_name="subscription",
            constraint=models.CheckConstraint(
                check=models.Q(unit_price_cents__gte=0),
                name="subscription_price_non_negative",
            ),
        ),
        migrations.AddConstraint(
            model_name="subscription",
            constraint=models.CheckConstraint(
                check=models.Q(quantity__gte=1),
                name="subscription_quantity_positive",
            ),
        ),
        # Create PriceGrandfathering model
        migrations.CreateModel(
            name="PriceGrandfathering",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "locked_price_cents",
                    models.BigIntegerField(
                        help_text="The grandfathered price in cents",
                        validators=[django.core.validators.MinValueValidator(0)],
                    ),
                ),
                (
                    "original_price_cents",
                    models.BigIntegerField(help_text="Price at time of grandfathering (for reference)"),
                ),
                (
                    "current_product_price_cents",
                    models.BigIntegerField(help_text="Current product price at time of grandfathering"),
                ),
                (
                    "locked_at",
                    models.DateTimeField(auto_now_add=True, help_text="When price was locked"),
                ),
                (
                    "expires_at",
                    models.DateTimeField(
                        blank=True,
                        help_text="When grandfathering expires (null = never)",
                        null=True,
                    ),
                ),
                (
                    "is_active",
                    models.BooleanField(default=True, help_text="Whether grandfathering is currently active"),
                ),
                (
                    "reason",
                    models.CharField(
                        help_text="Reason for grandfathering (e.g., 'Early adopter', 'Loyalty reward')",
                        max_length=200,
                    ),
                ),
                (
                    "price_increase_id",
                    models.CharField(
                        blank=True,
                        help_text="Reference to the price increase that triggered grandfathering",
                        max_length=100,
                    ),
                ),
                (
                    "campaign",
                    models.CharField(
                        blank=True,
                        help_text="Campaign or promotion that granted grandfathering",
                        max_length=100,
                    ),
                ),
                (
                    "expiry_notified",
                    models.BooleanField(default=False, help_text="Whether expiry notification has been sent"),
                ),
                ("expiry_notified_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="created_grandfathering",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "customer",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="grandfathered_prices",
                        to="customers.customer",
                    ),
                ),
                (
                    "product",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="grandfathered_customers",
                        to="products.product",
                    ),
                ),
            ],
            options={
                "verbose_name": "Price Grandfathering",
                "verbose_name_plural": "Price Grandfatherings",
                "db_table": "price_grandfathering",
                "unique_together": {("customer", "product")},
            },
        ),
        # Add indexes to PriceGrandfathering
        migrations.AddIndex(
            model_name="pricegrandfathering",
            index=models.Index(fields=["customer", "is_active"], name="billing_gf_cust_active_idx"),
        ),
        migrations.AddIndex(
            model_name="pricegrandfathering",
            index=models.Index(fields=["product", "is_active"], name="billing_gf_prod_active_idx"),
        ),
        migrations.AddIndex(
            model_name="pricegrandfathering",
            index=models.Index(fields=["expires_at", "is_active"], name="billing_gf_expires_active_idx"),
        ),
        # Create SubscriptionChange model
        migrations.CreateModel(
            name="SubscriptionChange",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "change_type",
                    models.CharField(
                        choices=[
                            ("upgrade", "Upgrade"),
                            ("downgrade", "Downgrade"),
                            ("quantity_increase", "Quantity Increase"),
                            ("quantity_decrease", "Quantity Decrease"),
                            ("billing_cycle_change", "Billing Cycle Change"),
                            ("price_change", "Price Change"),
                        ],
                        max_length=30,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("applied", "Applied"),
                            ("cancelled", "Cancelled"),
                            ("failed", "Failed"),
                        ],
                        default="pending",
                        max_length=20,
                    ),
                ),
                ("old_price_cents", models.BigIntegerField()),
                ("old_quantity", models.PositiveIntegerField()),
                ("old_billing_cycle", models.CharField(max_length=20)),
                ("new_price_cents", models.BigIntegerField()),
                ("new_quantity", models.PositiveIntegerField()),
                ("new_billing_cycle", models.CharField(max_length=20)),
                ("prorate", models.BooleanField(default=True, help_text="Whether to prorate the change")),
                (
                    "proration_amount_cents",
                    models.BigIntegerField(
                        default=0,
                        help_text="Proration amount (positive = charge, negative = credit)",
                    ),
                ),
                (
                    "unused_credit_cents",
                    models.BigIntegerField(default=0, help_text="Credit for unused portion of old plan"),
                ),
                (
                    "new_charge_cents",
                    models.BigIntegerField(default=0, help_text="Charge for remaining portion of new plan"),
                ),
                ("effective_date", models.DateTimeField(help_text="When change takes effect")),
                (
                    "apply_immediately",
                    models.BooleanField(default=True, help_text="Apply immediately vs at next billing cycle"),
                ),
                ("reason", models.TextField(blank=True)),
                ("meta", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("applied_at", models.DateTimeField(blank=True, null=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="subscription_changes_created",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "invoice",
                    models.ForeignKey(
                        blank=True,
                        help_text="Invoice generated for proration charge",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="subscription_changes",
                        to="billing.invoice",
                    ),
                ),
                (
                    "new_product",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="subscription_changes_to",
                        to="products.product",
                    ),
                ),
                (
                    "old_product",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="subscription_changes_from",
                        to="products.product",
                    ),
                ),
                (
                    "subscription",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="changes",
                        to="billing.subscription",
                    ),
                ),
            ],
            options={
                "verbose_name": "Subscription Change",
                "verbose_name_plural": "Subscription Changes",
                "db_table": "subscription_changes",
                "ordering": ("-created_at",),
            },
        ),
        # Add indexes to SubscriptionChange
        migrations.AddIndex(
            model_name="subscriptionchange",
            index=models.Index(fields=["subscription", "-created_at"], name="billing_change_sub_created_idx"),
        ),
        migrations.AddIndex(
            model_name="subscriptionchange",
            index=models.Index(fields=["status", "effective_date"], name="billing_change_status_eff_idx"),
        ),
        # Create SubscriptionItem model
        migrations.CreateModel(
            name="SubscriptionItem",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "unit_price_cents",
                    models.BigIntegerField(
                        validators=[django.core.validators.MinValueValidator(0)],
                    ),
                ),
                (
                    "locked_price_cents",
                    models.BigIntegerField(
                        blank=True,
                        null=True,
                        validators=[django.core.validators.MinValueValidator(0)],
                    ),
                ),
                ("quantity", models.PositiveIntegerField(default=1)),
                ("meta", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "product",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="subscription_items",
                        to="products.product",
                    ),
                ),
                (
                    "subscription",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="items",
                        to="billing.subscription",
                    ),
                ),
            ],
            options={
                "verbose_name": "Subscription Item",
                "verbose_name_plural": "Subscription Items",
                "db_table": "subscription_items",
                "unique_together": {("subscription", "product")},
            },
        ),
    ]
