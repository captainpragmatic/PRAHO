import re

from django.db import migrations, models


def preserve_attempt_history(apps, schema_editor):
    EmailLog = apps.get_model("notifications", "EmailLog")
    for row in (
        EmailLog.objects.using(schema_editor.connection.alias)
        .only("pk", "status", "provider_response")
        .iterator(chunk_size=1000)
    ):
        response = row.provider_response if isinstance(row.provider_response, dict) else {}
        known = [int(match[1]) + 1 for key in response if (match := re.fullmatch(r"retry_(\d+)_error", key))]
        index = response.get("retry_count")
        if isinstance(index, int) and not isinstance(index, bool) and index >= 0:
            known.append(index + (1 if row.status == "failed" and not response.get("permanent_failure") else 0))
        attempts = max(known, default=0)
        if attempts:
            EmailLog.objects.using(schema_editor.connection.alias).filter(pk=row.pk).update(
                delivery_attempts=min(attempts, 2_147_483_647)
            )


class Migration(migrations.Migration):
    dependencies = [("notifications", "0002_initial")]

    operations = [
        migrations.AddField(
            model_name="emaillog", name="delivery_attempts", field=models.PositiveIntegerField(default=0)
        ),
        migrations.RunPython(preserve_attempt_history, migrations.RunPython.noop),
    ]
