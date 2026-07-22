"""
Catalog curation data migration (ADR-0040).

1. Deletes SystemSetting rows for retired keys — settings the wiring census
   proved are consumed by nothing ("decoy settings"), including billing.vat_rate
   (VAT truth lives in TaxRule) and system flags whose real gates read the
   environment. Cache entries for deleted keys expire naturally (≤1h, no readers).
2. Reconciles every surviving row's catalog-owned metadata (name, description,
   help text, data type, sensitivity). Sensitivity transitions re-encrypt or
   decrypt the stored value and clear the settings cache for the key.

Irreversible by design: the deleted rows describe settings that no longer exist.
"""

from django.core.cache import cache
from django.db import migrations

# Settings cache constants (mirrors SettingsService; embedded so this migration
# never depends on service-code history)
_CACHE_PREFIX = "praho_setting"
_CACHE_VERSION = 1

RETIRED_KEYS = [
    'billing.negative_balance_threshold',
    'billing.payment_grace_period_days',
    'billing.payment_retry_attempts',
    'billing.payment_retry_delay_hours',
    'billing.vat_rate',
    'domains.auto_renewal_enabled',
    'domains.max_per_package',
    'domains.max_subdomains_per_domain',
    'domains.registration_enabled',
    'domains.renewal_notice_days',
    'gdpr.audit_log_retention_years',
    'gdpr.data_retention_years',
    'gdpr.export_retention_days',
    'gdpr.log_retention_months',
    'integrations.api_connection_timeout_seconds',
    'integrations.api_request_timeout_seconds',
    'integrations.webhook_batch_size',
    'integrations.webhook_retry_attempts',
    'integrations.webhook_timeout_seconds',
    'monitoring.alert_cooldown_minutes',
    'monitoring.cpu_warning_threshold',
    'monitoring.disk_warning_threshold',
    'monitoring.health_check_interval_minutes',
    'monitoring.memory_warning_threshold',
    'node_deployment.auto_registration',
    'node_deployment.cost_tracking_enabled',
    'node_deployment.default_environment',
    'node_deployment.default_provider',
    'node_deployment.default_region',
    'node_deployment.timeout_ansible_playbook',
    'node_deployment.timeout_terraform_apply',
    'node_deployment.timeout_validation',
    'notifications.digest_frequency_hours',
    'notifications.email_enabled',
    'notifications.max_history',
    'notifications.sms_enabled',
    'provisioning.auto_setup_enabled',
    'provisioning.default_bandwidth_quota_gb',
    'provisioning.default_disk_quota_gb',
    'provisioning.max_email_accounts_per_package',
    'provisioning.setup_timeout_minutes',
    'provisioning.suspend_timeout_minutes',
    'provisioning.terminate_timeout_minutes',
    'security.api_burst_limit',
    'security.rate_limit_per_hour',
    'security.require_2fa_for_admin',
    'security.session_validation_rate_limit',
    'system.backup_retention_days',
    'tickets.auto_escalation_hours',
    'tickets.max_attachments_per_ticket',
    'tickets.max_reassignments',
    'tickets.sla_critical_response_hours',
    'tickets.sla_high_response_hours',
    'tickets.sla_low_response_hours',
    'tickets.sla_standard_response_hours',
    'ui.default_page_size',
    'ui.max_attachment_size_mb',
    'ui.max_page_size',
    'ui.min_page_size',
    'users.account_lockout_duration_minutes',
    'users.backup_code_count',
    'users.login_rate_limit_per_hour',
    'users.max_login_attempts',
    'users.mfa_required_for_staff',
    'users.session_timeout_minutes',
    'virtualmin.api_endpoint_path',
    'virtualmin.ssh_username',
    'virtualmin.use_ssl',]


def _reconcile_row(setting, definition, encrypt_value, decrypt_value, is_encrypted):
    """Apply catalog-owned metadata to one historical row. Returns list of changed fields."""
    changed = []

    has_value = setting.value is not None
    if setting.is_sensitive and not definition.sensitive and has_value and is_encrypted(str(setting.value)):
        # sensitive → plain: decrypt so the value stays readable
        setting.value = decrypt_value(str(setting.value))
        changed.append("value")
    elif definition.sensitive and not setting.is_sensitive and has_value and not is_encrypted(str(setting.value)):
        # plain → sensitive: encrypt at rest (historical models skip the custom save())
        setting.value = encrypt_value(str(setting.value))
        changed.append("value")

    catalog_metadata = {
        "name": definition.label,
        "description": definition.help_text or f"System setting: {definition.key}",
        "help_text": definition.help_text,
        "category": definition.group,
        "data_type": definition.data_type,
        "is_sensitive": definition.sensitive,
        "default_value": definition.default,
    }
    for field_name, target in catalog_metadata.items():
        if getattr(setting, field_name) != target:
            setattr(setting, field_name, target)
            changed.append(field_name)
    return changed


def curate(apps, schema_editor):
    # Deliberate exception to the frozen-data rule: reconciliation must apply the
    # CURRENT catalog, and the catalog is pure data with no model dependencies.
    from apps.common.encryption import decrypt_value, encrypt_value, is_encrypted  # noqa: PLC0415
    from apps.settings.catalog import CATALOG_BY_KEY  # noqa: PLC0415

    system_setting = apps.get_model("settings", "SystemSetting")

    deleted, _ = system_setting.objects.filter(key__in=RETIRED_KEYS).delete()

    reconciled = 0
    for setting in system_setting.objects.all():
        definition = CATALOG_BY_KEY.get(setting.key)
        if definition is None:
            continue  # ad-hoc row outside the catalog — left untouched
        changed = _reconcile_row(setting, definition, encrypt_value, decrypt_value, is_encrypted)
        if changed:
            setting.save(update_fields=[*changed, "updated_at"])
            cache.delete(f"{_CACHE_PREFIX}:{setting.key}", version=_CACHE_VERSION)
            reconciled += 1

    print(f"  settings curation: {deleted} retired rows deleted, {reconciled} rows reconciled")


class Migration(migrations.Migration):
    dependencies = [
        ("settings", "0002_remove_invalid_efactura_controls"),
    ]

    operations = [
        migrations.RunPython(curate, migrations.RunPython.noop),
    ]
