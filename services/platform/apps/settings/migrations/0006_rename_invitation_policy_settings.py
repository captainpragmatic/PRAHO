"""Give invitation-related policies distinct identities without losing overrides.

The former ``security.invitation_rate_limit_per_user`` row actually controlled
join-request owner notifications while the initial membership-invitation gate
was hardcoded. Its value is therefore copied to both accurately named policies:
this preserves deployed notification behaviour and the operator's apparent
intent for membership invitations.

The welcome-invite row is a resend guard scoped to the target user, so it is
renamed rather than merged with either of those policies.
"""

from django.core.cache import cache
from django.db import migrations, transaction

# Embedded migration constants mirror SettingsService without importing mutable
# application service code from a historical migration.
_CACHE_PREFIX = "praho_setting"
_CACHE_VERSION = 1

OLD_MEMBERSHIP_KEY = "security.invitation_rate_limit_per_user"
OLD_WELCOME_KEY = "security.welcome_invite_limit_per_user_per_hour"

MEMBERSHIP_KEY = "security.membership_invitation_limit_per_inviter_per_hour"
JOIN_NOTIFICATION_KEY = "security.join_request_notification_limit_per_customer_per_hour"
WELCOME_KEY = "security.welcome_invite_limit_per_target_per_hour"

RETIRED_KEYS = (OLD_MEMBERSHIP_KEY, OLD_WELCOME_KEY)

POLICY_METADATA = {
    MEMBERSHIP_KEY: {
        "name": "Membership invitation limit",
        "description": "Maximum initial membership invitations per inviter and source IP per hour. Zero blocks invitations.",
        "help_text": "Maximum initial membership invitations per inviter and source IP per hour. Zero blocks invitations.",
        "default_value": 10,
    },
    JOIN_NOTIFICATION_KEY: {
        "name": "Join-request notification limit",
        "description": "Maximum owner-notification batches per customer per hour. Zero blocks these notifications.",
        "help_text": "Maximum owner-notification batches per customer per hour. Zero blocks these notifications.",
        "default_value": 10,
    },
    WELCOME_KEY: {
        "name": "Welcome-invite resend limit",
        "description": "Maximum welcome or password-reset invite emails sent to one target user per hour. Zero blocks resends.",
        "help_text": "Maximum welcome or password-reset invite emails sent to one target user per hour. Zero blocks resends.",
        "default_value": 3,
    },
}


def _metadata_for(key):
    return {
        "category": "advanced",
        "data_type": "integer",
        "is_sensitive": False,
        **POLICY_METADATA[key],
    }


def _copy_policy_row(system_setting, source, destination_key):
    if system_setting.objects.filter(key=destination_key).exists():
        return
    system_setting.objects.create(
        key=destination_key,
        value=source.value,
        is_required=source.is_required,
        is_active=source.is_active,
        requires_restart=source.requires_restart,
        **_metadata_for(destination_key),
    )


def _rename_policy_row(system_setting, source, destination_key):
    if system_setting.objects.filter(key=destination_key).exists():
        source.delete()
        return
    source.key = destination_key
    for field_name, value in _metadata_for(destination_key).items():
        setattr(source, field_name, value)
    source.save(
        update_fields=[
            "key",
            "category",
            "name",
            "description",
            "help_text",
            "data_type",
            "default_value",
            "is_sensitive",
            "updated_at",
        ]
    )


def migrate_policy_rows(apps, schema_editor):
    system_setting = apps.get_model("settings", "SystemSetting")

    membership_source = system_setting.objects.filter(key=OLD_MEMBERSHIP_KEY).first()
    if membership_source is not None:
        _copy_policy_row(system_setting, membership_source, JOIN_NOTIFICATION_KEY)
        _rename_policy_row(system_setting, membership_source, MEMBERSHIP_KEY)

    welcome_source = system_setting.objects.filter(key=OLD_WELCOME_KEY).first()
    if welcome_source is not None:
        _rename_policy_row(system_setting, welcome_source, WELCOME_KEY)

    # Historical models do not emit the current SystemSetting cache-invalidation
    # signal. Clear after commit so a rolling-deploy worker cannot repopulate a
    # destination default before the migrated override becomes visible.
    for destination_key in (MEMBERSHIP_KEY, JOIN_NOTIFICATION_KEY, WELCOME_KEY):
        transaction.on_commit(
            lambda key=destination_key: cache.delete(f"{_CACHE_PREFIX}:{key}", version=_CACHE_VERSION)
        )


class Migration(migrations.Migration):
    dependencies = [
        ("settings", "0005_delete_file_hash_cache_key"),
    ]

    operations = [
        # Reverse is intentionally a no-op: three independently editable
        # policies cannot be losslessly recombined into the two ambiguous keys.
        migrations.RunPython(migrate_policy_rows, migrations.RunPython.noop),
    ]
