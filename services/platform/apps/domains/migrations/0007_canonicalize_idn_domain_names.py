"""Canonicalize existing internationalized Domain.name values to IDNA A-labels (#473).

Domain.save() now folds internationalized names through IDNA UTS-46 on write, but
rows created before that change may hold Unicode U-labels. Exact-match lookups using
the equivalent ASCII A-label miss those rows, so they must be fixed in place rather
than left to be rewritten opportunistically.

``name`` is ``unique=True``: an existing A-label row can collide with a U-label row
that folds onto it, and multiple U-label variants can share one target. That is a
genuine data conflict a migration must not paper over by dropping a row, so every
collision shape is detected UP FRONT (before any row is rewritten) and the migration
fails loudly with the offending names.

The whole table is scanned in Python so ASCII rows participate as potential collision
targets, but only rows whose stored name contains non-ASCII characters are rewritten.
The inline canonicalization deliberately matches the application helper: strip and
lower first, use IDNA UTS-46 for non-ASCII input, and fall back to the folded Unicode
value if IDNA rejects it.

Concurrency note: the scan and rewrite are not table-locked, so an OLD app instance
still serving during the migration could insert a U-label row after the scan. That row
either stays non-canonical (the migration is idempotent and can be re-run) or occupies
a rewrite target, failing the migration atomically. Once the new code serves,
Domain.save() and the DomainQuerySet bulk paths make new U-label writes impossible.
"""

from __future__ import annotations

from uuid import UUID

import idna
from django.apps.registry import Apps
from django.db import migrations
from django.db.backends.base.schema import BaseDatabaseSchemaEditor


def canonicalize_names(apps: Apps, _schema_editor: BaseDatabaseSchemaEditor | None) -> None:
    domain = apps.get_model("domains", "Domain")

    to_fix: list[tuple[UUID, str]] = []
    targets: dict[str, list[tuple[str, UUID, UUID, str]]] = {}
    for pk, name, customer_id, status in domain.objects.values_list("pk", "name", "customer_id", "status").iterator():
        folded = name.strip().lower()
        canonical = folded
        if not folded.isascii():
            try:
                canonical = idna.encode(folded, uts46=True).decode("ascii")
            except UnicodeError:
                canonical = folded

        targets.setdefault(canonical, []).append((name, pk, customer_id, status))
        if not name.isascii() and name != canonical:
            to_fix.append((pk, canonical))

    if not to_fix:
        return

    # Include every row in the target map: an existing ASCII A-label is just as
    # important a collision occupant as another U-label. Refuse before ANY write
    # and include enough detail for an operator to choose the survivor safely.
    collisions = {canonical: rows for canonical, rows in targets.items() if len(rows) > 1}
    if collisions:
        detail = "; ".join(
            f"{canonical}: "
            + ", ".join(
                f"{name!r} (pk={pk}, customer={customer_id}, status={status})" for name, pk, customer_id, status in sorted(rows)
            )
            for canonical, rows in sorted(collisions.items())
        )
        raise RuntimeError(
            f"Cannot canonicalize internationalized Domain.name — multiple rows map to the same "
            f"canonical name ({detail}). Resolve the duplicates manually (mind FK cascades from "
            "DomainOperation/ServiceDomain), then re-run."
        )

    # Rewrite via queryset update, not instance save, so this migration remains
    # independent of the live model and its current canonicalization behavior.
    for pk, canonical in to_fix:
        domain.objects.filter(pk=pk).update(name=canonical)


class Migration(migrations.Migration):
    dependencies = [
        ("domains", "0006_canonicalize_domain_name"),
    ]

    operations = [
        # Reverse is a no-op: the original U-label spelling is not recoverable, and
        # A-labels remain valid input for the pre-#473 application.
        migrations.RunPython(canonicalize_names, migrations.RunPython.noop),
    ]
