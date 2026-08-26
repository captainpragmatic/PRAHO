# #246: index the APIToken expiry purge path.
#
# Only (expires_at) is added — it serves the daily purge, the genuinely unbounded
# query. A (user, expires_at) composite for the per-user cap check was considered and
# dropped: PG16 EXPLAIN at 20k rows showed identical plan/cost with or without it,
# while at 200k rows the COUNT can go Index-Only on it — a real but marginal,
# contingent benefit against per-user row counts kept small by the cap plus this very
# purge index. Re-add it CONCURRENTLY if production EXPLAIN ever proves the need.
# Cardinality note: this is a staff-token table (cap x staff users), so the
# non-concurrent CREATE INDEX here builds in milliseconds.

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0004_create_apitoken"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="apitoken",
            index=models.Index(fields=["expires_at"], name="apitoken_expires_at_idx"),
        ),
    ]
