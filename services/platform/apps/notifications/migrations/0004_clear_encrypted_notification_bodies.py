"""Clear encrypted notification bodies for AES-256-GCM encryption upgrade.

Notification bodies encrypted with Django Signer (enc:v1: prefix) become unreadable.
Historical notification content is cleared.
"""

from django.db import migrations


def clear_encrypted_bodies(apps, schema_editor):
    """Clear notification bodies that were encrypted with the old enc:v1: format."""
    EmailLog = apps.get_model("notifications", "EmailLog")
    text_cleared = EmailLog.objects.filter(body_text__startswith="enc:").update(body_text="")
    html_cleared = EmailLog.objects.filter(body_html__startswith="enc:").update(body_html="")
    total = text_cleared + html_cleared
    if total:
        print(f"\n  Cleared {total} encrypted notification body field(s).")


class Migration(migrations.Migration):
    dependencies = [
        ("notifications", "0003_alter_emailcampaign_created_by_emailpreference_and_more"),
    ]

    operations = [
        migrations.RunPython(clear_encrypted_bodies, migrations.RunPython.noop),
    ]
