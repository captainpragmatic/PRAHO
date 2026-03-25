"""Add product_slug snapshot field to OrderItem for EN16931 BT-155 compliance."""

from django.db import migrations, models


def backfill_product_slug(apps, schema_editor):
    """Backfill product_slug from product.slug for existing OrderItems."""
    OrderItem = apps.get_model("orders", "OrderItem")
    updated = 0
    for item in OrderItem.objects.filter(product_slug="").select_related("product"):
        if item.product and item.product.slug:
            item.product_slug = item.product.slug
            item.save(update_fields=["product_slug"])
            updated += 1
    if updated:
        print(f"  Backfilled product_slug on {updated} OrderItems")


class Migration(migrations.Migration):
    dependencies = [
        ("orders", "0006_add_proforma_fk"),
    ]

    operations = [
        migrations.AddField(
            model_name="orderitem",
            name="product_slug",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Product slug/SKU at time of order (EN16931 BT-155)",
                max_length=200,
            ),
        ),
        migrations.RunPython(backfill_product_slug, migrations.RunPython.noop),
    ]
