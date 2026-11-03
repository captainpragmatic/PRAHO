"""Inventory old entitlements without issuing native changes or inventing historical defaults."""

import uuid

from django.db import migrations

BATCH_SIZE = 1000


def pin_legacy_allowances(apps, schema_editor):
    Service = apps.get_model("provisioning", "Service")
    Limits = apps.get_model("provisioning", "ServiceHostingLimits")
    alias = schema_editor.connection.alias
    pending = []
    services = (
        Service.objects.using(alias)
        .exclude(pk__in=Limits.objects.using(alias).values("service_id"))
        .values("pk", "service_plan_id", "service_plan__disk_space_gb", "service_plan__bandwidth_gb")
    )
    for service in services.iterator(chunk_size=BATCH_SIZE):
        disk = service["service_plan__disk_space_gb"]
        bandwidth = service["service_plan__bandwidth_gb"]
        pending.append(
            Limits(
                id=uuid.uuid4(),
                service_id=service["pk"],
                assigned_plan_id=service["service_plan_id"],
                disk_allowance_mib=disk * 1024 if disk is not None else None,
                bandwidth_allowance_mib=bandwidth * 1024 if bandwidth is not None else None,
                disk_source="legacy_catalog" if disk is not None else "legacy_unknown",
                bandwidth_source="legacy_catalog" if bandwidth is not None else "legacy_unknown",
            )
        )
        if len(pending) == BATCH_SIZE:
            Limits.objects.using(alias).bulk_create(pending)
            pending = []
    if pending:
        Limits.objects.using(alias).bulk_create(pending)


class Migration(migrations.Migration):
    dependencies = [("provisioning", "0029_virtualminaccount_effective_disk_quota_mb_and_more")]
    operations = [
        # Reversing schema later drops the table. A data-only rollback must not erase
        # assignments created or reviewed after this inventory was taken.
        migrations.RunPython(pin_legacy_allowances, migrations.RunPython.noop),
    ]
