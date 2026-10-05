from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0007_smartbill_correction_identity"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="invoice",
            index=models.Index(fields=["tax_point_date"], name="bill_inv_tax_point"),
        ),
        migrations.AddIndex(
            model_name="invoice",
            index=models.Index(
                condition=models.Q(("tax_point_date__isnull", True)), fields=["issued_at"], name="bill_inv_issued_no_tp"
            ),
        ),
        migrations.AddIndex(
            model_name="invoice",
            index=models.Index(
                condition=models.Q(("issued_at__isnull", True), ("tax_point_date__isnull", True)),
                fields=["created_at"],
                name="bill_inv_created_undated",
            ),
        ),
        migrations.AddIndex(
            model_name="fiscalcorrection",
            index=models.Index(fields=["fiscal_date"], name="bill_fiscorr_fiscal_date"),
        ),
    ]
