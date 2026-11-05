"""Join CrowdSec qualification with hosting warning and temporary raise histories."""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("provisioning", "0038_merge_crowdsec_hosting_observation"),
        ("provisioning", "0039_servicehostingraise_and_more"),
    ]

    operations = []
