# #246: index the APIToken expiry purge path.
#
# Only (expires_at) is added. The other candidate — a (user, expires_at) composite for
# the per-user live-token cap check — was dropped after EXPLAIN showed the production
# null-OR-future disjunction never uses it (the planner takes the plain user FK index;
# per-user rows are bounded by the token cap anyway). See APIToken.Meta.indexes.

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
