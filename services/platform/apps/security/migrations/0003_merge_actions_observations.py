"""Join independent host actions and completed-login observation histories."""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("security", "0002_actions"),
        ("security", "0002_customer_ip_observations"),
    ]

    operations = []
