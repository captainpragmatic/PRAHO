# Phase A: Rename order FSM states for Order-Proforma-Invoice lifecycle.
# Per adversarial finding F1: CHECK constraint blocks migration — DROP before RENAME.
#
# Renames: pending→awaiting_payment, confirmed→paid, processing→provisioning
# Removes: refunded, partially_refunded (migrated to completed — they WERE completed)
# Adds: in_review (new state for review gate)
#
# OrderStatusHistory records are left with old values as historical record (M1).

import django_fsm
from django.db import migrations, models


def rename_order_statuses(apps, schema_editor):
    """Rename existing order statuses to new values.

    Uses raw SQL UPDATE for each rename — QuerySet.update() bypasses FSM guards
    intentionally because this is a data migration, not a business transition.
    """
    Order = apps.get_model("orders", "Order")

    # Rename active statuses
    Order.objects.filter(status="pending").update(status="awaiting_payment")  # fsm-bypass: data migration
    Order.objects.filter(status="confirmed").update(status="paid")  # fsm-bypass: data migration
    Order.objects.filter(status="processing").update(status="provisioning")  # fsm-bypass: data migration

    # Refunded/partially_refunded orders → completed (they WERE completed, refund is on Invoice)
    Order.objects.filter(status="refunded").update(status="completed")  # fsm-bypass: data migration
    Order.objects.filter(status="partially_refunded").update(status="completed")  # fsm-bypass: data migration


def reverse_order_statuses(apps, schema_editor):
    """Reverse the status renames for rollback."""
    Order = apps.get_model("orders", "Order")

    # H4 fix: Map in_review to confirmed (old equivalent of "paid"), NOT pending.
    # in_review orders have already been paid — mapping to pending (pre-payment) is wrong semantics.
    Order.objects.filter(status="in_review").update(status="confirmed")  # fsm-bypass: data migration
    Order.objects.filter(status="awaiting_payment").update(status="pending")  # fsm-bypass: data migration
    Order.objects.filter(status="paid").update(status="confirmed")  # fsm-bypass: data migration
    Order.objects.filter(status="provisioning").update(status="processing")  # fsm-bypass: data migration
    # Note: cannot distinguish formerly refunded from originally completed on rollback


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0020_add_format_check_validation_source"),
        ("customers", "0014_add_vies_status_index"),
        ("orders", "0004_initial"),
    ]

    operations = [
        # Step 1: Remove old CHECK constraint (F1: must drop BEFORE renaming rows)
        migrations.RemoveConstraint(
            model_name="order",
            name="order_status_valid_values",
        ),
        # Step 2: Rename existing rows while no constraint is active
        migrations.RunPython(
            rename_order_statuses,
            reverse_order_statuses,
        ),
        # Step 3: Alter field choices on the FSM field
        migrations.AlterField(
            model_name="order",
            name="status",
            field=django_fsm.FSMField(
                choices=[
                    ("draft", "Draft"),
                    ("awaiting_payment", "Awaiting Payment"),
                    ("paid", "Paid"),
                    ("in_review", "In Review"),
                    ("provisioning", "Provisioning"),
                    ("completed", "Completed"),
                    ("cancelled", "Cancelled"),
                    ("failed", "Failed"),
                ],
                default="draft",
                help_text="Current order status",
                max_length=20,
                protected=True,
            ),
        ),
        # Step 4: Add new CHECK constraint with updated valid values
        migrations.AddConstraint(
            model_name="order",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    status__in=[
                        "draft",
                        "awaiting_payment",
                        "paid",
                        "in_review",
                        "provisioning",
                        "completed",
                        "cancelled",
                        "failed",
                    ]
                ),
                name="order_status_valid_values",
            ),
        ),
    ]
