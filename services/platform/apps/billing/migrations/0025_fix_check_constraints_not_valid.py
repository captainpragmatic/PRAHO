"""
Zero-downtime fix: recreate all billing CHECK constraints with NOT VALID + VALIDATE.

The standard ADD CONSTRAINT acquires ACCESS EXCLUSIVE lock for the full table scan.
This pattern splits the operation into two steps:
  1. ADD CONSTRAINT ... NOT VALID  — acquires only ShareUpdateExclusiveLock, no scan
  2. VALIDATE CONSTRAINT           — acquires ShareUpdateExclusiveLock, scans but allows reads/writes
"""
from django.db import migrations

_CONSTRAINTS = [
    ("billing_invoice", "invoice_subtotal_non_negative", "subtotal_cents >= 0"),
    ("billing_invoice", "invoice_tax_non_negative", "tax_cents >= 0"),
    ("billing_invoice", "invoice_total_non_negative", "total_cents >= 0"),
    (
        "billing_invoice",
        "invoice_status_valid_values",
        "status IN ('draft','issued','paid','overdue','void','refunded','partially_refunded')",
    ),
    ("billing_invoiceline", "invoiceline_unit_price_non_negative", "unit_price_cents >= 0"),
    ("billing_invoiceline", "invoiceline_tax_non_negative", "tax_cents >= 0"),
    ("billing_invoiceline", "invoiceline_line_total_non_negative", "line_total_cents >= 0"),
    ("billing_payment", "payment_amount_non_negative", "amount_cents >= 0"),
    (
        "billing_payment",
        "payment_status_valid_values",
        "status IN ('pending','succeeded','failed','refunded','partially_refunded')",
    ),
    ("billing_proformainvoice", "proformainvoice_subtotal_non_negative", "subtotal_cents >= 0"),
    ("billing_proformainvoice", "proformainvoice_tax_non_negative", "tax_cents >= 0"),
    ("billing_proformainvoice", "proformainvoice_total_non_negative", "total_cents >= 0"),
    (
        "billing_proformainvoice",
        "proformainvoice_status_valid_values",
        "status IN ('draft','sent','accepted','expired','converted')",
    ),
    ("billing_proformaline", "proformaline_unit_price_non_negative", "unit_price_cents >= 0"),
    ("billing_proformaline", "proformaline_tax_non_negative", "tax_cents >= 0"),
    ("billing_proformaline", "proformaline_line_total_non_negative", "line_total_cents >= 0"),
    (
        "billing_refund",
        "refund_status_valid_values",
        "status IN ('pending','processing','approved','completed','rejected','failed','cancelled')",
    ),
    (
        "billing_subscription",
        "subscription_status_valid_values",
        "status IN ('trialing','active','past_due','paused','cancelled','expired','pending')",
    ),
    (
        "billing_efacturadocument",
        "efactura_valid_status",
        "status IN ('draft','queued','submitted','processing','accepted','rejected','error')",
    ),
    (
        "billing_billingcycle",
        "billingcycle_status_valid_values",
        "status IN ('upcoming','active','closing','closed','invoiced','finalized')",
    ),
    (
        "billing_usageaggregation",
        "usageaggregation_status_valid_values",
        "status IN ('accumulating','pending_rating','rated','invoiced','finalized')",
    ),
]


def add_constraints_not_valid(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for table, name, expr in _CONSTRAINTS:
        schema_editor.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name};")
        schema_editor.execute(f"ALTER TABLE {table} ADD CONSTRAINT {name} CHECK ({expr}) NOT VALID;")


def validate_constraints(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for table, name, _expr in _CONSTRAINTS:
        schema_editor.execute(f"ALTER TABLE {table} VALIDATE CONSTRAINT {name};")


def reverse_migration(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for table, name, _expr in _CONSTRAINTS:
        schema_editor.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name};")


class Migration(migrations.Migration):
    atomic = False

    dependencies = [("billing", "0024_alter_payment_amount_cents")]

    operations = [
        migrations.RunPython(add_constraints_not_valid, reverse_code=reverse_migration),
        migrations.RunPython(validate_constraints, reverse_code=migrations.RunPython.noop),
    ]
