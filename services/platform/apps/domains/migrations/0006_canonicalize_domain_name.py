"""Canonicalize existing Domain.name values to lowercase (#442).

Domain.save() now lowercases on write, but rows created before that change may hold
mixed-case names. An exact-match lookup (e.g. the renew-item link in
create_domain_order_item) misses those rows silently, so they must be fixed in place
rather than left to be rewritten opportunistically.

``name`` is ``unique=True``: if both ``Example.RO`` and ``example.ro`` somehow exist,
lowercasing the former would collide. That is a genuine data conflict a migration must
not paper over by dropping a row, so it fails loudly with the offending names instead.
"""

from __future__ import annotations

from django.db import migrations
from django.db.models.functions import Lower


def canonicalize_names(apps, schema_editor):
    domain = apps.get_model("domains", "Domain")

    mixed_case = domain.objects.exclude(name=Lower("name"))
    if not mixed_case.exists():
        return

    # Detect collisions before writing: a lowercase twin already occupying the target.
    existing_lower = set(
        domain.objects.filter(name__in=[d.name.lower() for d in mixed_case]).values_list("name", flat=True)
    )
    collisions = [d.name for d in mixed_case if d.name.lower() in existing_lower]
    if collisions:
        raise RuntimeError(
            "Cannot canonicalize Domain.name — these rows would collide with an existing "
            f"lowercase row: {sorted(collisions)}. Resolve the duplicates manually, then re-run."
        )

    for row in mixed_case:
        row.name = row.name.strip().lower()
        row.save(update_fields=["name"])


class Migration(migrations.Migration):
    dependencies = [
        ("domains", "0005_tld_tld_min_registration_period_lte_max"),
    ]

    operations = [
        # Reverse is a no-op: the original casing is not recoverable, and lowercase names
        # are valid input for the pre-#442 code, so rolling back needs no data change.
        migrations.RunPython(canonicalize_names, migrations.RunPython.noop),
    ]
