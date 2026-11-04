"""Keep independently deployed CrowdSec and hosting-limit histories intact."""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("provisioning", "0029_crowdsec_qualification_profile"),
        ("provisioning", "0036_alter_nodehostingexecution_action"),
    ]

    operations = []
