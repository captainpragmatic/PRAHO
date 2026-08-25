"""Canonicalize existing Domain.name values to stripped lowercase (#442).

Domain.save() now canonicalizes on write, but rows created before that change may hold
mixed-case or whitespace-padded names. An exact-match lookup (e.g. the renew-item link
in create_domain_order_item) misses those rows silently, so they must be fixed in place
rather than left to be rewritten opportunistically.

``name`` is ``unique=True``: if two rows canonicalize to the same target — a mixed-case
row next to an existing lowercase twin, or two mixed-case variants of one name — the
rewrite would collide. That is a genuine data conflict a migration must not paper over
by dropping a row, so every collision shape is detected UP FRONT (before any row is
rewritten) and the migration fails loudly with the offending names.

The whole table is scanned in Python: domain tables are small, a one-time full scan is
cheap, and it sidesteps per-backend SQL semantics of LOWER()/TRIM() entirely — the
Python canonical (``strip().lower()``) is by construction the same one save() applies.
"""

from __future__ import annotations

from django.db import migrations


def canonicalize_names(apps, schema_editor):
    domain = apps.get_model("domains", "Domain")

    to_fix = []  # (row, canonical) pairs needing a rewrite
    targets: dict[str, list[str]] = {}  # canonical name -> every stored name mapping to it
    for row in domain.objects.all().iterator():
        canonical = row.name.strip().lower()
        targets.setdefault(canonical, []).append(row.name)
        if row.name != canonical:
            to_fix.append((row, canonical))

    if not to_fix:
        return

    # Every collision shape at once: an existing-lowercase occupant plus a variant,
    # or several non-canonical variants of the same name — refuse before ANY write,
    # never midway through on a raw IntegrityError.
    collisions = {canonical: names for canonical, names in targets.items() if len(names) > 1}
    if collisions:
        detail = "; ".join(f"{canonical}: {sorted(names)}" for canonical, names in sorted(collisions.items()))
        raise RuntimeError(
            f"Cannot canonicalize Domain.name — multiple rows map to the same canonical name ({detail}). "
            "Resolve the duplicates manually, then re-run."
        )

    for row, canonical in to_fix:
        row.name = canonical
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
