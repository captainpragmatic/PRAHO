"""Display snapshots for optional settings logging have their own savepoint."""

from django.test import override_settings

from apps.settings.models import SystemSetting
from tests.common._deferred_audit_reads import DeferredAuditReadTestCase


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class DeferredSettingPayloadTests(DeferredAuditReadTestCase):
    def test_setting_update_commits_when_deferred_display_type_fetch_fails(self) -> None:
        setting = SystemSetting.objects.create(
            key="billing.proforma_validity_days",
            name="Validity",
            category="billing",
            data_type="integer",
            value=30,
            default_value=30,
        )
        setting = SystemSetting.objects.defer("data_type").get(pk=setting.pk)
        setting.value = 45
        self.run_deferred_read(setting, lambda: setting.save(update_fields=["value"]))
        self.assertEqual(SystemSetting.objects.get(pk=setting.pk).value, 45)
