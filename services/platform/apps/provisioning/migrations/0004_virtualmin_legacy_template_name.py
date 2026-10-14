"""Rename the pre-Virtualmin-8 default template on existing accounts.

Migration 0003 changed only the default. Rows written before it still say "Default", a template
Virtualmin 8 does not have, so reprovisioning or recovering them would fail.
"""

from typing import Any

from django.db import migrations

LEGACY_DEFAULT = "Default"
VIRTUALMIN_8_DEFAULT = "Default Settings"


def rename_legacy_default_template(apps: Any, schema_editor: Any) -> None:
    account = apps.get_model("provisioning", "VirtualminAccount")
    account.objects.filter(template_name=LEGACY_DEFAULT).update(template_name=VIRTUALMIN_8_DEFAULT)


class Migration(migrations.Migration):
    dependencies = [
        ("provisioning", "0003_virtualmin_default_template_name"),
    ]

    operations = [
        migrations.RunPython(rename_legacy_default_template, migrations.RunPython.noop),
    ]
