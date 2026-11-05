"""Join CrowdSec qualification and read-only hosting safety observation histories."""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("provisioning", "0037_alter_virtualminprovisioningjob_operation"),
        ("provisioning", "0037_merge_crowdsec_hosting_limits"),
    ]

    operations = []
