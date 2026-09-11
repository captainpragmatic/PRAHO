"""Retain registrar acceptance and intent identity beyond cache/worker timeouts."""

from django.db import migrations, models
from django.db.models.functions import Coalesce
from django.utils import timezone


def preserve_uncertain_operations(apps, schema_editor):
    Operation = apps.get_model("domains", "DomainOperation")
    alias = schema_editor.connection.alias
    # An existing handle is evidence of acceptance, regardless of the current state.
    for operation in Operation.objects.using(alias).exclude(registrar_operation_id="").iterator():
        Operation.objects.using(alias).filter(pk=operation.pk).update(
            accepted_at=operation.submitted_at or operation.created_at,
        )
    # Never synthesize intent keys or success for historical records. The old
    # worker's timeout text was persisted in the configured language; handle-bearing
    # failures and known timeout text are conservatively returned to review.
    uncertain = (
        Operation.objects.using(alias)
        .filter(state="failed")
        .filter(
            models.Q(error_message__icontains="unconfirmed after 72h")
            | models.Q(registrar_operation_id__gt="")
            | models.Q(
                error_message__in=(
                    "network_error",
                    "timeout",
                    "invalid_response",
                    "internal_error",
                    "operation_pending",
                )
            )
        )
    )
    uncertain.update(
        state="submitted",
        review_required_at=timezone.now(),
        next_retry_at=None,
        submitted_at=Coalesce("submitted_at", "created_at"),
    )


class Migration(migrations.Migration):
    dependencies = [("domains", "0008_domainoperation_register_renew_types")]

    operations = [
        migrations.AddField("domainoperation", "intent_key", models.CharField(max_length=64, null=True, blank=True)),
        migrations.AddField("domainoperation", "accepted_at", models.DateTimeField(null=True, blank=True)),
        migrations.AddField("domainoperation", "review_required_at", models.DateTimeField(null=True, blank=True)),
        migrations.AlterField(
            "domainoperation", "registrar_operation_id", models.CharField(max_length=2048, blank=True)
        ),
        migrations.AddConstraint(
            "domainoperation",
            models.UniqueConstraint(
                fields=("registrar", "domain", "operation_type", "intent_key"),
                name="domainop_unique_intent",
            ),
        ),
        migrations.RunPython(preserve_uncertain_operations, migrations.RunPython.noop),
    ]
