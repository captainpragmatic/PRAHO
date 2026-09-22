"""One document, one e-Factura submission owner.

PRAHO's e-Factura stack stays in the repository after an external issuer is
switched on. Nothing but an explicit guard stops it from filing a document the
provider has already filed, and a duplicate upload to SPV cannot be taken back.

These tests drive every entry point that can reach ANAF and assert the HTTP client
is never touched for an externally-issued invoice.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from typing import cast
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus
from apps.billing.efactura.service import EFacturaService
from apps.billing.efactura.validator import CIUSROValidator
from apps.billing.invoice_models import ISSUER_BUILTIN, ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.policy import (
    EFacturaProviderConflictError,
    assert_efactura_submission_allowed,
    efactura_submission_denied_reason,
)
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory

UPLOAD_METHODS = ("upload_invoice", "upload_credit_note", "upload_b2c")


def _currency(code: str = "RON") -> Currency:
    obj, _ = Currency.objects.get_or_create(code=code, defaults={"symbol": "L", "decimals": 2})
    return obj


class ProviderExclusionPolicyTests(TestCase):
    """The policy itself, independent of any caller."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()

    def _invoice(self, issuer: str) -> Invoice:
        return Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"INV-{issuer.upper()}-0001",
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=issuer,
        )

    def test_builtin_documents_are_allowed(self) -> None:
        invoice = self._invoice(ISSUER_BUILTIN)
        self.assertIsNone(efactura_submission_denied_reason(invoice))
        assert_efactura_submission_allowed(invoice)  # must not raise

    def test_external_documents_are_denied_with_a_reason(self) -> None:
        reason = efactura_submission_denied_reason(self._invoice(ISSUER_SMARTBILL))
        self.assertIsNotNone(reason)
        assert reason is not None
        self.assertIn("smartbill", reason)

    def test_only_explicit_builtin_is_permitted(self) -> None:
        """Fail closed: the rule is an allowlist of one, not a denylist of SmartBill.

        An unknown provider, a blank string or None must all be refused. A guard that
        only knew how to say no to "smartbill" would wave through a typo.
        """
        invoice = self._invoice(ISSUER_BUILTIN)
        for value in ("unknown-provider", "", "SMARTBILL", "builtin ", None):
            with self.subTest(issuer_provider=value):
                invoice.issuer_provider = value
                self.assertIsNotNone(
                    efactura_submission_denied_reason(invoice),
                    msg=f"{value!r} must not be treated as an owner PRAHO may file for",
                )

    def test_missing_provenance_raises_rather_than_defaulting(self) -> None:
        """A double or row without provenance must not silently resolve to "allowed"."""

        class NoProvenance:
            pass

        with self.assertRaises(AttributeError):
            efactura_submission_denied_reason(cast("Invoice", NoProvenance()))

    def test_the_backstop_raises_rather_than_returning(self) -> None:
        """The lowest boundary fails closed; it does not return a value a caller can ignore."""
        with self.assertRaises(EFacturaProviderConflictError):
            assert_efactura_submission_allowed(self._invoice(ISSUER_SMARTBILL))


@override_settings(EFACTURA_ENABLED=True)
class NoAnafCallForExternallyIssuedInvoiceTests(TestCase):
    """Drive every reachable entry point and prove the ANAF client is never used."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="SB-0001",
            status="issued",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_tax_id="RO12345678",
            bill_to_address1="Str. Exemplu 1",
            bill_to_city="Sector 1",
            bill_to_region="Bucuresti",
            bill_to_postal="010101",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )
        InvoiceLineFactory(
            invoice=self.invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )

    def _client(self) -> MagicMock:
        client = MagicMock()
        for name in UPLOAD_METHODS:
            getattr(client, name).side_effect = AssertionError(
                f"{name} was called for an externally issued invoice"
            )
        return client

    def _assert_no_upload(self, client: MagicMock) -> None:
        for name in UPLOAD_METHODS:
            getattr(client, name).assert_not_called()

    def test_service_submit_invoice_declines(self) -> None:
        client = self._client()
        result = EFacturaService(client=client).submit_invoice(self.invoice)
        self.assertFalse(result.success)
        self.assertIn("owned by the issuing provider", result.error_message or "")
        self._assert_no_upload(client)
        self.assertFalse(EFacturaDocument.objects.filter(invoice=self.invoice).exists())

    def test_submit_task_declines(self) -> None:
        from apps.billing.efactura.tasks import submit_efactura_task  # noqa: PLC0415

        client = self._client()
        with patch("apps.billing.efactura.service.EFacturaClient", return_value=client):
            submit_efactura_task(str(self.invoice.id))

        self._assert_no_upload(client)
        # The real discriminator: without the guard the claim step creates this row
        # before the flow dies later at validation.
        self.assertFalse(EFacturaDocument.objects.filter(invoice=self.invoice).exists())

    def test_the_retry_poller_skips_a_document_that_should_not_exist(self) -> None:
        """Defense in depth: even a row created out-of-band must not be uploaded.

        A SmartBill invoice never gets an EFacturaDocument, because submit_invoice
        refuses before creating one. This forces the bad state anyway.

        XML generation and validation are patched so the retry path genuinely reaches
        the upload dispatch; otherwise the flow dies early and the test proves nothing.
        """
        from apps.billing.efactura.tasks import process_efactura_retries_task  # noqa: PLC0415

        EFacturaDocument.objects.create(
            invoice=self.invoice,
            status=EFacturaStatus.ERROR.value,
            retry_count=0,
            # get_ready_for_retry() requires a due next_retry_at. Without it the poller
            # never selects the row and the test passes for the wrong reason.
            next_retry_at=timezone.now() - timedelta(minutes=5),
        )

        document = EFacturaDocument.objects.get(invoice=self.invoice)
        before = (document.status, document.retry_count)

        client = self._client()
        # Patch XML generation and validation so preparation SUCCEEDS. Without this the
        # retry dies at XML generation and the test would pass whether or not the guard
        # exists — measured, not assumed.
        with (
            patch("apps.billing.efactura.service.EFacturaClient", return_value=client),
            patch.object(EFacturaService, "_generate_xml", return_value="<Invoice/>"),
            patch.object(CIUSROValidator, "validate") as validate,
        ):
            validate.return_value.is_valid = True
            validate.return_value.errors = []
            process_efactura_retries_task()

        self._assert_no_upload(client)
        document.refresh_from_db()
        self.assertEqual((document.status, document.retry_count), before)

    def test_the_pending_submissions_poller_also_skips_it(self) -> None:
        """The second scheduled poller, proven independently of the retry one."""
        from apps.billing.efactura.tasks import process_pending_submissions_task  # noqa: PLC0415

        document = EFacturaDocument.objects.create(
            invoice=self.invoice,
            status=EFacturaStatus.QUEUED.value,
        )
        before = (document.status, document.retry_count)

        client = self._client()
        with (
            patch("apps.billing.efactura.service.EFacturaClient", return_value=client),
            patch.object(EFacturaService, "_generate_xml", return_value="<Invoice/>"),
            patch.object(CIUSROValidator, "validate") as validate,
        ):
            validate.return_value.is_valid = True
            validate.return_value.errors = []
            process_pending_submissions_task()

        self._assert_no_upload(client)
        document.refresh_from_db()
        self.assertEqual((document.status, document.retry_count), before)

    def test_issuing_the_invoice_does_not_queue_a_submission(self) -> None:
        from apps.billing.signals import _trigger_efactura_submission  # noqa: PLC0415

        with (
            patch("apps.billing.efactura.tasks.queue_efactura_submission") as queue,
            self.captureOnCommitCallbacks(execute=True),
        ):
            _trigger_efactura_submission(self.invoice)
        queue.assert_not_called()

    def test_refunding_does_not_build_a_credit_note(self) -> None:
        # The path is gated on an ACCEPTED document; without one it returns early and
        # the test would pass regardless of the guard.
        from apps.billing.signals import _handle_efactura_refund_reporting  # noqa: PLC0415

        EFacturaDocument.objects.create(
            invoice=self.invoice,
            status=EFacturaStatus.ACCEPTED.value,
        )

        with patch("apps.billing.efactura.xml_builder.UBLCreditNoteBuilder") as builder:
            _handle_efactura_refund_reporting(self.invoice)
        builder.assert_not_called()



@override_settings(EFACTURA_ENABLED=True)
class BuiltinInvoiceStillSubmitsTests(TestCase):
    """The positive control, without which every test above is satisfiable by a
    guard that refuses everything.

    XML generation and CIUS-RO validation are patched narrowly so the flow reaches
    the upload dispatch. Everything between the policy check and the client call —
    the claim, the routing, the finalisation — is the real code.
    """

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()

    def _invoice(self, issuer: str) -> Invoice:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"INV-{issuer.upper()}-9001",
            status="issued",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_tax_id="RO12345678",
            bill_to_address1="Str. Exemplu 1",
            bill_to_city="Sector 1",
            bill_to_region="Bucuresti",
            bill_to_postal="010101",
            bill_to_country="RO",
            issuer_provider=issuer,
        )
        InvoiceLineFactory(
            invoice=invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        return invoice

    def _submit(self, invoice: Invoice) -> tuple[MagicMock, object]:
        from apps.billing.efactura.client import UploadResponse  # noqa: PLC0415

        client = MagicMock()
        client.upload_invoice.return_value = UploadResponse(success=True, upload_index="UI-12345")
        service = EFacturaService(client=client)

        with (
            patch.object(EFacturaService, "_generate_xml", return_value="<Invoice/>"),
            patch.object(service._validator, "validate") as validate,
        ):
            validate.return_value.is_valid = True
            validate.return_value.errors = []
            result = service.submit_invoice(invoice)
        return client, result

    def test_a_builtin_invoice_actually_reaches_the_upload(self) -> None:
        client, result = self._submit(self._invoice(ISSUER_BUILTIN))

        client.upload_invoice.assert_called_once()
        self.assertTrue(result.success, msg=getattr(result, "error_message", ""))

    def test_the_same_flow_is_refused_for_an_external_issuer(self) -> None:
        """Same fixture, same patches, only provenance differs. This is the contrast."""
        client, result = self._submit(self._invoice(ISSUER_SMARTBILL))

        client.upload_invoice.assert_not_called()
        self.assertFalse(result.success)
        self.assertIn("owned by the issuing provider", result.error_message or "")


@override_settings(EFACTURA_ENABLED=True)
class BackstopTests(TestCase):
    """The fail-closed backstop at the upload dispatch, in isolation.

    The top-level check is what normally declines. This proves the second, deeper
    guard is still wired in — so a future caller that constructs a claim by another
    route still cannot reach ANAF.
    """

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="SB-BACKSTOP-0001",
            status="issued",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_tax_id="RO12345678",
            bill_to_address1="Str. Exemplu 1",
            bill_to_city="Sector 1",
            bill_to_region="Bucuresti",
            bill_to_postal="010101",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )
        InvoiceLineFactory(
            invoice=self.invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )

    def test_backstop_raises_before_upload_when_the_entry_check_is_bypassed(self) -> None:
        client = MagicMock()
        service = EFacturaService(client=client)

        with (
            # Disable ONLY the entry check, so the claim is genuinely acquired and the
            # backstop is the thing under test.
            patch("apps.billing.efactura.service.efactura_submission_denied_reason", return_value=None),
            patch.object(EFacturaService, "_generate_xml", return_value="<Invoice/>"),
            patch.object(service._validator, "validate") as validate,
        ):
            validate.return_value.is_valid = True
            validate.return_value.errors = []
            with self.assertRaises(EFacturaProviderConflictError):
                service.submit_invoice(self.invoice)

        client.upload_invoice.assert_not_called()
        client.upload_credit_note.assert_not_called()
        client.upload_b2c.assert_not_called()

    def test_a_conflicting_claim_carries_an_expiry(self) -> None:
        """The claim taken before the backstop is time-bounded, not open-ended.

        Scope, stated precisely: this proves an expiry is persisted. It does NOT
        prove the reclaim sweep later selects this document — that predicate is
        covered by the existing submission-claim tests. What it pins is that a
        future change cannot make an ownership conflict leave a claim with no
        expiry at all, which is what would wedge the document permanently.
        """
        client = MagicMock()
        service = EFacturaService(client=client)

        with (
            patch("apps.billing.efactura.service.efactura_submission_denied_reason", return_value=None),
            patch.object(EFacturaService, "_generate_xml", return_value="<Invoice/>"),
            patch.object(service._validator, "validate") as validate,
        ):
            validate.return_value.is_valid = True
            validate.return_value.errors = []
            with self.assertRaises(EFacturaProviderConflictError):
                service.submit_invoice(self.invoice)

        document = EFacturaDocument.objects.get(invoice=self.invoice)
        self.assertIsNotNone(
            document.submission_claim_expires_at,
            msg="a claim taken before the backstop must carry an expiry, or it wedges forever",
        )
