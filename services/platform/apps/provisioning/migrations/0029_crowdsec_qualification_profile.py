from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("provisioning", "0028_component_migration_authority")]

    operations = [
        migrations.AddField(
            model_name="virtualminserver",
            name="security_policy_version",
            field=models.CharField(default="virtualmin-web-only-v2", editable=False, max_length=40),
        ),
        migrations.AddField(
            model_name="virtualminserver",
            name="security_configuration_digest",
            field=models.CharField(blank=True, default="", editable=False, max_length=64),
        ),
    ]
