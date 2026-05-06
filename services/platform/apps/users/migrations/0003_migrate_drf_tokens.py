"""
Data migration: copy existing DRF authtoken tokens to the new APIToken model.

Each DRF token is hashed with SHA-256 and stored in APIToken so that existing
consumers can continue authenticating with their current token values once the
HashedTokenAuthentication backend is activated.
"""

import hashlib

from django.db import migrations


def forward(apps, schema_editor):
    """Copy DRF Token rows into APIToken with SHA-256 hashed keys."""
    DRFToken = apps.get_model("authtoken", "Token")
    APIToken = apps.get_model("users", "APIToken")

    tokens_to_create = [
        APIToken(
            user=drf_token.user,
            key_hash=hashlib.sha256(drf_token.key.encode("utf-8")).hexdigest(),
            key_prefix=drf_token.key[:8],
            name="Migrated from DRF authtoken",
            created_at=drf_token.created,
        )
        for drf_token in DRFToken.objects.select_related("user").iterator()
    ]
    if tokens_to_create:
        APIToken.objects.bulk_create(tokens_to_create)


def reverse(apps, schema_editor):
    """Remove migrated APIToken rows (does NOT restore DRF tokens)."""
    APIToken = apps.get_model("users", "APIToken")
    APIToken.objects.filter(name="Migrated from DRF authtoken").delete()


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0002_create_apitoken"),
        ("authtoken", "0004_alter_tokenproxy_options"),
    ]

    operations = [
        migrations.RunPython(forward, reverse),
    ]
