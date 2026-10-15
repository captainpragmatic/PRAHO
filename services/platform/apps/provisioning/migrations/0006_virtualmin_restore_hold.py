import django.db.models.deletion  # noqa: F401
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('provisioning', '0005_virtualmin_differential_chain'),
    ]

    operations = [
        migrations.AddField(
            model_name='virtualminaccount',
            name='restore_hold',
            field=models.CharField(blank=True, default='', editable=False, help_text='Why reconcile must leave this account disabled; empty when nothing holds it', max_length=30),
        ),
        migrations.AddField(
            model_name='virtualminaccount',
            name='restore_hold_safety_backup_id',
            field=models.CharField(blank=True, default='', editable=False, help_text='The safety backup taken before the restore that left the domain half-restored', max_length=100),
        ),
    ]
