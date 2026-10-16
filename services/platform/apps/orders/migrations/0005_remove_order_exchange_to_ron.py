"""Drop Order.exchange_to_ron: nothing read or wrote it. An invoice freezes its own rate at issue."""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("orders", "0004_initial")]

    operations = [
        migrations.RemoveField(model_name="order", name="exchange_to_ron"),
    ]
