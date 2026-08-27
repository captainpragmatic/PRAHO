"""Add registration and renewal DomainOperation types (#257).

Gandi answers chargeable register/renew with 202 acceptance; the accepted-but-
unconfirmed state needs a durable operation row the reconciliation worker can
converge, so both become first-class operation types.
"""

from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("domains", "0007_canonicalize_idn_domain_names"),
    ]

    operations = [
        migrations.AlterField(
            model_name="domainoperation",
            name="operation_type",
            field=models.CharField(
                choices=[
                    ("register", "Registration"),
                    ("renew", "Renewal"),
                    ("transfer_in", "Transfer In"),
                    ("transfer_out", "Transfer Out"),
                    ("nameserver_update", "Nameserver Update"),
                    ("lock_update", "Lock Status Update"),
                    ("whois_update", "WHOIS Privacy Update"),
                    ("domain_info", "Domain Info Sync"),
                ],
                max_length=30,
            ),
        ),
    ]
