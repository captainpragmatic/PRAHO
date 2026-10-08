"""Domain configuration saves survive optional audit failures."""

from django.test import override_settings

from apps.billing.models import Currency
from apps.domains.models import TLD
from tests.common._signal_isolation import SignalIsolationTestCase


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class DomainSignalIsolationTests(SignalIsolationTestCase):
    def setUp(self) -> None:
        super().setUp()
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})

    def test_tld_creation_survives_failed_audit_write(self) -> None:
        tld = self.run_effect(
            "apps.domains.signals.DomainsAuditService.log_tld_event",
            lambda: TLD.objects.create(
                extension="isolation",
                registration_price_cents=1000,
                renewal_price_cents=1000,
                transfer_price_cents=1000,
            ),
        )
        self.assertTrue(TLD.objects.filter(pk=tld.pk).exists())
