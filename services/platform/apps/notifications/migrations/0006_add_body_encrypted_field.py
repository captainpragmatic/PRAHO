"""Add body_encrypted field to EmailLog and backfill existing rows.

Existing rows with non-empty body_text that lacks the 'aes:' prefix are
marked body_encrypted=False (legacy plaintext).  All other rows default
to True (already encrypted or empty).

Uses raw SQL for the data migration because SoftDeleteManager lacks
use_in_migrations=True (see project memory / ADR-0016).
"""

from django.db import migrations, models


def backfill_body_encrypted(apps, schema_editor):
    """Mark legacy plaintext rows as body_encrypted=False."""
    # Raw SQL: SoftDeleteManager workaround (ADR-0016)
    schema_editor.execute(
        """
        UPDATE email_log
        SET body_encrypted = FALSE
        WHERE (
            (body_text IS NOT NULL AND body_text != '' AND body_text NOT LIKE 'aes:%%')
            OR
            (body_html IS NOT NULL AND body_html != '' AND body_html NOT LIKE 'aes:%%')
        )
        """
    )


class Migration(migrations.Migration):
    dependencies = [
        ("notifications", "0005_unsubscribetoken"),
    ]

    operations = [
        migrations.AddField(
            model_name="emaillog",
            name="body_encrypted",
            field=models.BooleanField(
                default=True,
                help_text="Whether body fields are encrypted at rest.",
            ),
        ),
        migrations.RunPython(
            backfill_body_encrypted,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
