# Generated manually for rollback tracking fields

from django.db import migrations, models


class Migration(migrations.Migration):
    """
    Add rollback tracking fields to VirtualminProvisioningJob.

    These fields enable:
    - Tracking whether rollback was executed after a failure
    - Recording the status of rollback operations
    - Storing detailed rollback operation results
    """

    dependencies = [
        ('provisioning', '0004_service_provisioning_task_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='virtualminprovisioningjob',
            name='rollback_executed',
            field=models.BooleanField(
                default=False,
                verbose_name='Rollback Executed',
                help_text='Whether rollback was attempted after failure'
            ),
        ),
        migrations.AddField(
            model_name='virtualminprovisioningjob',
            name='rollback_status',
            field=models.CharField(
                max_length=20,
                blank=True,
                default='',
                choices=[
                    ('', 'Not Applicable'),
                    ('success', 'Rollback Successful'),
                    ('partial', 'Rollback Partially Successful'),
                    ('failed', 'Rollback Failed'),
                ],
                verbose_name='Rollback Status',
                help_text='Status of rollback operation if executed'
            ),
        ),
        migrations.AddField(
            model_name='virtualminprovisioningjob',
            name='rollback_details',
            field=models.JSONField(
                default=dict,
                blank=True,
                help_text='Details of rollback operations performed'
            ),
        ),
    ]
