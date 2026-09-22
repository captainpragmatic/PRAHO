"""Changing who issues invoices, and being honest about what that does.

The switch only ever affects documents that do not exist yet: provenance is stamped
per document and frozen. So this is not about history — it is about work already in
flight, and about not handing e-Factura to a provider while PRAHO is still filing.
"""

from __future__ import annotations

from unittest.mock import patch

from django.test import TestCase

from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus
from apps.billing.invoice_models import ISSUER_BUILTIN, ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.base import ConfigurationReport
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.issuers.policy import can_switch_invoice_issuer, default_issuer_provider
from apps.common.types import Err, Ok
from apps.settings.catalog import CATALOG_BY_KEY
from tests.factories.billing_factories import CustomerFactory

GREEN = Ok(ConfigurationReport(provider=ISSUER_SMARTBILL, ok=True))


def _currency(code: str = "RON") -> Currency:
    obj, _ = Currency.objects.get_or_create(code=code, defaults={"symbol": "L", "decimals": 2})
    return obj


class CatalogTests(TestCase):
    def test_every_smartbill_setting_is_declared(self) -> None:
        """ADR-0042: an undeclared key read at runtime fails the consumer contract."""
        for key in (
            "billing.invoice_issuer",
            "integrations.smartbill_email",
            "integrations.smartbill_token",
            "integrations.smartbill_v3_token",
            "integrations.smartbill_cif",
            "integrations.smartbill_invoice_series",
            "integrations.smartbill_tax_names",
            "integrations.smartbill_measuring_unit",
            "integrations.smartbill_language",
        ):
            with self.subTest(key=key):
                self.assertIn(key, CATALOG_BY_KEY)

    def test_both_api_tokens_are_write_only_secrets(self) -> None:
        """The settings surface must never render a stored credential back."""
        for key in ("integrations.smartbill_token", "integrations.smartbill_v3_token"):
            with self.subTest(key=key):
                self.assertTrue(CATALOG_BY_KEY[key].sensitive)
                self.assertEqual(CATALOG_BY_KEY[key].input_kind, "secret")

    def test_the_issuer_defaults_to_builtin(self) -> None:
        """Nothing reaches a provider until someone deliberately switches."""
        self.assertEqual(CATALOG_BY_KEY["billing.invoice_issuer"].default, ISSUER_BUILTIN)
        self.assertEqual(default_issuer_provider(), ISSUER_BUILTIN)


class PreflightTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()

    def _invoice(self, **kwargs: object) -> Invoice:
        defaults: dict[str, object] = {
            "customer": self.customer,
            "currency": self.currency,
            "number": "INV-SW-0001",
            "status": "issued",
            "subtotal_cents": 10000,
            "tax_cents": 2100,
            "total_cents": 12100,
            "bill_to_name": "Test Company SRL",
        }
        defaults.update(kwargs)
        return Invoice.objects.create(**defaults)

    def test_a_clean_system_may_switch(self) -> None:
        with patch(
            "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.validate_configuration",
            return_value=GREEN,
        ):
            self.assertTrue(can_switch_invoice_issuer(ISSUER_SMARTBILL).is_ok())

    def test_an_unknown_outcome_blocks_the_switch(self) -> None:
        """Switching would leave that attempt owned by a provider nobody is watching."""
        invoice = self._invoice()
        ProviderIssuance.objects.create(
            invoice=invoice,
            provider=ISSUER_SMARTBILL,
            state=IssuanceState.OUTCOME_UNKNOWN.value,
        )

        with patch(
            "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.validate_configuration",
            return_value=GREEN,
        ):
            result = can_switch_invoice_issuer(ISSUER_SMARTBILL)

        self.assertTrue(result.is_err())
        self.assertTrue(any("unresolved" in b.reason for b in result.error))

    def test_an_invoice_awaiting_a_number_blocks_the_switch(self) -> None:
        self._invoice(number=None, status="draft")

        with patch(
            "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.validate_configuration",
            return_value=GREEN,
        ):
            result = can_switch_invoice_issuer(ISSUER_SMARTBILL)

        self.assertTrue(result.is_err())
        self.assertTrue(any("awaiting a number" in b.reason for b in result.error))

    def test_an_in_flight_efactura_submission_blocks_switching_to_a_provider(self) -> None:
        """Handing e-Factura over mid-submission risks the same invoice reaching SPV twice."""
        invoice = self._invoice(number="INV-SW-0002", bill_to_country="RO")
        EFacturaDocument.objects.create(invoice=invoice, status=EFacturaStatus.SUBMITTED.value)

        with patch(
            "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.validate_configuration",
            return_value=GREEN,
        ):
            result = can_switch_invoice_issuer(ISSUER_SMARTBILL)

        self.assertTrue(result.is_err())
        self.assertTrue(any("in flight" in b.reason for b in result.error))

    def test_unusable_credentials_block_the_switch(self) -> None:
        """The check that would have caught a deactivated SmartBill company."""
        with patch(
            "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.validate_configuration",
            return_value=Err("Invoice series 'TEST' not found in the account"),
        ):
            result = can_switch_invoice_issuer(ISSUER_SMARTBILL)

        self.assertTrue(result.is_err())
        self.assertTrue(any("not usable" in b.reason for b in result.error))

    def test_switching_back_to_builtin_does_not_require_provider_credentials(self) -> None:
        """Leaving must not be gated on the thing you are leaving still working."""
        with patch(
            "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.validate_configuration",
            return_value=Err("credentials rejected"),
        ):
            self.assertTrue(can_switch_invoice_issuer(ISSUER_BUILTIN).is_ok())

    def test_every_blocker_is_reported_at_once(self) -> None:
        invoice = self._invoice(number=None, status="draft")
        ProviderIssuance.objects.create(
            invoice=invoice, provider=ISSUER_SMARTBILL, state=IssuanceState.OUTCOME_UNKNOWN.value
        )

        with patch(
            "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.validate_configuration",
            return_value=Err("nope"),
        ):
            result = can_switch_invoice_issuer(ISSUER_SMARTBILL)

        self.assertGreaterEqual(len(result.error), 3)
