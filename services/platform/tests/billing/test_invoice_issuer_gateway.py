"""The issuer contract, and the one consumer wired to it so far.

Scope, stated honestly: this phase establishes the gateway and routes the `pre_save`
safety-net through it. The three invoice-creation services still allocate their
number inline before a row exists, so they cannot use this interface until Phase 6
makes issuance deferred. These tests pin the contract and that single integration,
not a completed consolidation.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from uuid import UUID, uuid4

from django.test import TestCase

from apps.billing.invoice_models import ISSUER_BUILTIN, ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.base import (
    Ambiguous,
    ConfigurationReport,
    InvoiceIssuerGateway,
    Issued,
    IssueOutcome,
    Rejected,
    get_invoice_issuer,
    get_registered_issuers,
    register_invoice_issuer,
)
from apps.billing.issuers.builtin import BuiltinIssuer
from apps.billing.issuers.policy import resolve_issuer
from apps.common.types import Ok, Result
from tests.factories.billing_factories import CustomerFactory
from tests.helpers.fsm_helpers import force_status


def _currency(code: str = "RON") -> Currency:
    obj, _ = Currency.objects.get_or_create(code=code, defaults={"symbol": "L", "decimals": 2})
    return obj


class RecordingIssuer(InvoiceIssuerGateway):
    """A stand-in for a future external provider, used to prove the seam is real."""

    provider = "recording-test-issuer"
    seen: list[UUID] = []  # noqa: RUF012

    def validate_configuration(self) -> Result[ConfigurationReport, str]:
        return Ok(ConfigurationReport(provider=self.provider, ok=True))

    def issue_invoice(self, invoice: Invoice, *, attempt_id: UUID) -> IssueOutcome:
        RecordingIssuer.seen.append(attempt_id)
        return Issued(number="EXT-000001", series="EXT", provider_document_id="doc-1")


@contextmanager
def registry_sandbox() -> Iterator[None]:
    """Snapshot and restore the module-level issuer registry.

    Database state rolls back between tests; a module-level dict does not.
    """
    from apps.billing.issuers import base  # noqa: PLC0415

    saved = dict(base._ISSUER_REGISTRY)
    try:
        yield
    finally:
        base._ISSUER_REGISTRY.clear()
        base._ISSUER_REGISTRY.update(saved)


class IssueOutcomeTests(TestCase):
    """Three outcomes, not two. The third is why duplicate invoices are avoidable."""

    def test_the_three_outcomes_are_distinguishable(self) -> None:
        issued: IssueOutcome = Issued(number="INV-000001")
        rejected: IssueOutcome = Rejected(errors=("series not found",))
        ambiguous: IssueOutcome = Ambiguous(reason="read timeout after POST")

        self.assertIsInstance(issued, Issued)
        self.assertNotIsInstance(rejected, Issued)
        self.assertNotIsInstance(ambiguous, Rejected)

    def test_outcomes_are_immutable(self) -> None:
        """An outcome is evidence of what a provider did; it must not be edited after."""
        outcome = Issued(number="INV-000001")
        # Indirect attribute name: keeps this type-clean without a type: ignore, and
        # avoids ruff B010 which only objects to a constant attribute.
        frozen_field = "number"
        with self.assertRaises(FrozenInstanceError):
            setattr(outcome, frozen_field, "INV-000002")


class RegistryTests(TestCase):
    def test_the_builtin_issuer_is_registered(self) -> None:
        """Scope: this proves registration happened, not that `ready()` caused it.

        Registration is a side effect of importing `apps.billing.issuers.builtin`,
        and this module imports `BuiltinIssuer` directly, so the test cannot
        distinguish its own import from `BillingConfig.ready()`. Proving the latter
        needs a fresh process. What this does pin is that resolving the built-in key
        yields the built-in gateway rather than something else.
        """
        self.assertIn(ISSUER_BUILTIN, get_registered_issuers())
        self.assertIsInstance(get_invoice_issuer(ISSUER_BUILTIN), BuiltinIssuer)

    def test_app_startup_imports_the_module_that_registers_issuers(self) -> None:
        """Complements the above: the AppConfig must perform that import itself.

        Without this, removing the import from ready() would still leave the suite
        green (every test module that touches issuers imports them directly) while
        production started with an empty registry.
        """
        import inspect  # noqa: PLC0415

        from apps.billing.apps import BillingConfig  # noqa: PLC0415

        source = inspect.getsource(BillingConfig.ready)
        self.assertIn("issuers", source, msg="BillingConfig.ready() no longer registers issuers")

    def test_an_unknown_provider_raises_rather_than_falling_back(self) -> None:
        """Silently issuing through the wrong provider is worse than failing loudly."""
        with self.assertRaises(ValueError) as ctx:
            get_invoice_issuer("no-such-provider")
        self.assertIn("no-such-provider", str(ctx.exception))

    def test_a_new_issuer_can_be_registered_and_resolved(self) -> None:
        """Proves the seam actually accepts a second implementation."""
        with registry_sandbox():
            register_invoice_issuer(RecordingIssuer.provider, RecordingIssuer)
            self.assertIsInstance(get_invoice_issuer(RecordingIssuer.provider), RecordingIssuer)

        self.assertNotIn(RecordingIssuer.provider, get_registered_issuers())

    def test_a_key_that_disagrees_with_the_class_is_refused(self) -> None:
        with registry_sandbox(), self.assertRaises(ValueError) as ctx:
            register_invoice_issuer("some-other-key", RecordingIssuer)
        self.assertIn("disagrees", str(ctx.exception))

    def test_an_existing_issuer_cannot_be_silently_replaced(self) -> None:
        """Import-order accidents must not change who issues a company's invoices."""

        class Impostor(RecordingIssuer):
            provider = ISSUER_BUILTIN

        with registry_sandbox(), self.assertRaises(ValueError) as ctx:
            register_invoice_issuer(ISSUER_BUILTIN, Impostor)
        self.assertIn("refusing to replace", str(ctx.exception))

    def test_re_registering_the_same_class_is_idempotent(self) -> None:
        with registry_sandbox():
            register_invoice_issuer(BuiltinIssuer.provider, BuiltinIssuer)  # must not raise


class BuiltinIssuerTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
        )

    def test_it_allocates_from_the_local_sequence(self) -> None:
        outcome = BuiltinIssuer().issue_invoice(self.invoice, attempt_id=uuid4())

        self.assertIsInstance(outcome, Issued)
        assert isinstance(outcome, Issued)
        self.assertTrue(outcome.number.startswith("INV-"), msg=outcome.number)

    def test_consecutive_allocations_do_not_collide(self) -> None:
        issuer = BuiltinIssuer()
        first = issuer.issue_invoice(self.invoice, attempt_id=uuid4())
        second = issuer.issue_invoice(self.invoice, attempt_id=uuid4())

        assert isinstance(first, Issued)
        assert isinstance(second, Issued)
        self.assertNotEqual(first.number, second.number)

    def test_it_reports_itself_as_configured(self) -> None:
        result = BuiltinIssuer().validate_configuration()
        self.assertTrue(result.is_ok())
        self.assertTrue(result.unwrap().ok)


class IssuerResolutionTests(TestCase):
    """Resolution reads the document, never a global setting."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()

    def _invoice(self, issuer: str, number: str) -> Invoice:
        return Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=number,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            issuer_provider=issuer,
        )

    def test_a_builtin_document_resolves_to_the_builtin_issuer(self) -> None:
        self.assertIsInstance(resolve_issuer(self._invoice(ISSUER_BUILTIN, "INV-R-1")), BuiltinIssuer)

    def test_two_documents_can_resolve_differently_at_the_same_time(self) -> None:
        """The property that makes a provider switch safe for existing documents.

        A global setting would give both the same answer. Because provenance lives
        on the row, an invoice issued before a switch keeps its own issuer forever.
        """
        builtin_doc = self._invoice(ISSUER_BUILTIN, "INV-R-2")
        external_doc = self._invoice(ISSUER_SMARTBILL, "INV-R-3")
        external_doc.issuer_provider = RecordingIssuer.provider

        with registry_sandbox():
            register_invoice_issuer(RecordingIssuer.provider, RecordingIssuer)
            self.assertIsInstance(resolve_issuer(builtin_doc), BuiltinIssuer)
            self.assertIsInstance(resolve_issuer(external_doc), RecordingIssuer)


class SignalUsesTheGatewayTests(TestCase):
    """The integration the contract tests alone do not prove.

    Without these, reverting the signal back to calling InvoiceNumberingService
    directly would leave every other test in this module green.
    """

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()
        RecordingIssuer.seen = []

    def _unnumbered(self) -> Invoice:
        return Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
        )

    def test_issuance_goes_through_the_registered_gateway(self) -> None:
        """Swap the built-in gateway for a recorder and watch issuance route to it."""
        from apps.billing.issuers import base  # noqa: PLC0415

        invoice = self._unnumbered()

        with registry_sandbox():
            # Direct registry write: the public API deliberately refuses to replace
            # an existing registration, which is the behaviour tested elsewhere.
            base._ISSUER_REGISTRY[ISSUER_BUILTIN] = RecordingIssuer
            force_status(invoice, "issued")

        self.assertEqual(len(RecordingIssuer.seen), 1, msg="the gateway was never consulted")
        self.assertIsInstance(RecordingIssuer.seen[0], UUID)

        invoice.refresh_from_db()
        self.assertEqual(
            invoice.number,
            "EXT-EXT-000001",
            msg="the number the gateway returned was not persisted onto the invoice",
        )

    def test_a_non_issued_outcome_aborts_persistence(self) -> None:
        """A gateway that cannot number the document must not leave it issued."""
        from apps.billing.issuers import base  # noqa: PLC0415

        class RefusingIssuer(RecordingIssuer):
            provider = "refusing-test-issuer"

            def issue_invoice(self, invoice: Invoice, *, attempt_id: UUID) -> IssueOutcome:
                return Rejected(errors=("series not configured",))

        invoice = self._unnumbered()

        with registry_sandbox():
            base._ISSUER_REGISTRY[ISSUER_BUILTIN] = RefusingIssuer
            with self.assertRaises(ValueError) as ctx:
                force_status(invoice, "issued")

        self.assertIn("did not assign a number", str(ctx.exception))

        invoice.refresh_from_db()
        self.assertIsNone(invoice.number)
        self.assertEqual(invoice.status, "draft", msg="issuance must not survive a refusal")
