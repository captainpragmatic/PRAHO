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

Concurrency note: the scan and the rewrite are not table-locked, so an OLD app instance
still serving during the migration could insert a non-canonical row after the scan.
That row either stays non-canonical (harmless — the migration is idempotent and the
function can be re-run) or occupies a rewrite target, failing the migration atomically
(default transactional RunPython on both SQLite and PostgreSQL — nothing partial is
committed; re-run after the deploy settles). Once the new code serves, save() and the
DomainQuerySet bulk paths make non-canonical writes impossible, so the window closes
with the deploy itself.
"""

from __future__ import annotations

from django.db import migrations


def canonicalize_names(apps, schema_editor):
    domain = apps.get_model("domains", "Domain")

    to_fix = []  # (pk, canonical) pairs needing a rewrite
    targets: dict[str, list[tuple]] = {}  # canonical -> (stored name, pk, customer_id, status) rows
    for pk, name, customer_id, status in domain.objects.values_list("pk", "name", "customer_id", "status").iterator():
        canonical = name.strip().lower()
        targets.setdefault(canonical, []).append((name, pk, customer_id, status))
        if name != canonical:
            to_fix.append((pk, canonical))

    if not to_fix:
        return

    # Every collision shape at once: an existing-lowercase occupant plus a variant,
    # or several non-canonical variants of the same name — refuse before ANY write,
    # never midway through on a raw IntegrityError. The detail names pk/customer/
    # status so the on-call operator can pick the survivor WITHOUT guessing — a
    # careless delete cascades DomainOperation/ServiceDomain history.
    collisions = {canonical: rows for canonical, rows in targets.items() if len(rows) > 1}
    if collisions:
        detail = "; ".join(
            f"{canonical}: " + ", ".join(f"{n!r} (pk={pk}, customer={cid}, status={st})" for n, pk, cid, st in sorted(rows))
            for canonical, rows in sorted(collisions.items())
        )
        raise RuntimeError(
            f"Cannot canonicalize Domain.name — multiple rows map to the same canonical name ({detail}). "
            "Resolve the duplicates manually (mind FK cascades from DomainOperation/ServiceDomain), then re-run."
        )

    # Rewrite via queryset update, NOT instance save(): the historical model has no
    # custom save()/manager, and staying model-layer-independent keeps this function
    # honest under test — it must do the rewrite itself, not lean on live-model
    # canonicalization.
    for pk, canonical in to_fix:
        domain.objects.filter(pk=pk).update(name=canonical)


class Migration(migrations.Migration):
    dependencies = [
        ("domains", "0005_tld_tld_min_registration_period_lte_max"),
    ]

    operations = [
        # Reverse is a no-op: the original casing is not recoverable, and lowercase names
        # are valid input for the pre-#442 code, so rolling back needs no data change.
        migrations.RunPython(canonicalize_names, migrations.RunPython.noop),
    ]
