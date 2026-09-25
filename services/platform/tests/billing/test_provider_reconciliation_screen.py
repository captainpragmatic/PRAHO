"""The only exit from `outcome_unknown` needed an operator, and had no way in.

`reconcile_confirmed_issued` was written with the hard part solved - it locks, refuses
a wrong state, and rejects a number already adopted elsewhere - but nothing called it.
An issuance whose outcome nobody knew stayed that way permanently, and the setting
could not even be switched off while one existed.

It also assigned a legal fiscal number on a human's word without writing an audit
event, which ADR-0016 does not permit for an act of that kind.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.invoice_models import ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.operator_controls import BillingControlActor, adopt_provider_document
from tests.factories.billing_factories import (
    CustomerFactory,
    InvoiceLineFactory,
    PaymentCreationRequest,
    create_payment,
)
from tests.factories.core_factories import create_admin_user, create_staff_user


def _unresolved_issuance(customer: object, currency: Currency, *, number: str) -> ProviderIssuance:
    invoice = Invoice.objects.create(
        customer=customer,
        currency=currency,
        number=None,
        status="draft",
        issued_at=timezone.now(),
        subtotal_cents=10000,
        tax_cents=2100,
        total_cents=12100,
        bill_to_name="Test Company SRL",
        bill_to_country="RO",
        issuer_provider=ISSUER_SMARTBILL,
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
    return ProviderIssuance.objects.create(
        invoice=invoice,
        provider=ISSUER_SMARTBILL,
        state=IssuanceState.OUTCOME_UNKNOWN.value,
        last_error=f"No usable reply from SmartBill for {number}",
    )


class ReconciliationQueueAccessTests(TestCase):
    """Same gate every operator control uses: admin or billing only, 403 otherwise."""

    def setUp(self) -> None:
        self.billing_user = create_staff_user(username="recon_billing", staff_role="billing")
        self.support_user = create_staff_user(username="recon_support", staff_role="support")
        self.manager_user = create_staff_user(username="recon_manager", staff_role="manager")
        self.admin_user = create_admin_user(username="recon_admin")

    def test_the_queue_requires_admin_or_billing(self) -> None:
        url = reverse("billing:provider_reconciliation_queue")

        self.assertEqual(self.client.get(url).status_code, 302)

        for user in (self.support_user, self.manager_user):
            with self.subTest(role=user.staff_role):
                self.client.force_login(user)
                self.assertEqual(self.client.get(url).status_code, 403)

        for user in (self.billing_user, self.admin_user):
            with self.subTest(role=user.staff_role):
                self.client.force_login(user)
                self.assertEqual(self.client.get(url).status_code, 200)


class ReconciliationQueueContentTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self.client.force_login(create_admin_user(username="recon_content"))

    def test_an_unresolved_issuance_is_listed(self) -> None:
        _unresolved_issuance(self.customer, self.currency, number="A")

        response = self.client.get(reverse("billing:provider_reconciliation_queue"))

        self.assertContains(response, "No usable reply from SmartBill")

    def test_a_resolved_issuance_is_not_listed(self) -> None:
        """The queue is the work list, not a history."""
        issuance = _unresolved_issuance(self.customer, self.currency, number="B")
        ProviderIssuance.objects.filter(pk=issuance.pk).update(state=IssuanceState.ISSUED.value)

        response = self.client.get(reverse("billing:provider_reconciliation_queue"))

        self.assertNotContains(response, "No usable reply from SmartBill")


class AdoptProviderDocumentTests(TransactionTestCase):
    """`TransactionTestCase` so a rollback inside the command is a real rollback.

    A `TestCase` wraps each test in its own transaction, which would turn the command's
    atomic block into a savepoint and hide whether the adoption actually survives an
    audit failure - the one thing these tests exist to prove.
    """

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self.operator = create_admin_user(username="recon_service")

    def _actor(
        self, reason: str = "Checked SmartBill Cloud; found FCT 000900 for this customer."
    ) -> BillingControlActor:
        return BillingControlActor(user=self.operator, reason=reason, ip_address="10.0.0.1")

    def test_adopting_a_document_numbers_the_invoice(self) -> None:
        issuance = _unresolved_issuance(self.customer, self.currency, number="C")

        legal_number = adopt_provider_document(
            issuance_id=issuance.pk, series="FCT", number="000900", actor=self._actor()
        )

        self.assertEqual(legal_number, "FCT-000900")
        adopted = ProviderIssuance.objects.select_related("invoice").get(pk=issuance.pk)
        self.assertEqual(adopted.state, IssuanceState.ISSUED.value)
        self.assertEqual(adopted.invoice.number, "FCT-000900")

    def test_adopting_writes_an_audit_event_naming_the_operator(self) -> None:
        """It assigns a legal fiscal number on a human's word; ADR-0016 requires a trace."""
        issuance = _unresolved_issuance(self.customer, self.currency, number="D")

        adopt_provider_document(issuance_id=issuance.pk, series="FCT", number="000901", actor=self._actor())

        events = AuditEvent.objects.filter(user=self.operator, action="configuration_changed")
        self.assertTrue(events.exists(), "the adoption must be attributable to who decided it")
        event = events.order_by("-timestamp").first()
        assert event is not None
        self.assertEqual(event.new_values.get("invoice_number"), "FCT-000901")
        self.assertIn("Checked SmartBill Cloud", str(event.metadata.get("reason", "")))

    def test_a_blank_reason_is_refused_against_the_reason_field(self) -> None:
        """Both layers reject a blank note, so the thing worth asserting is WHERE.

        The issuer service answers with a generic `Err`, which this module turns into a
        non-field error; the local guard raises against `reason` instead, so the
        operator sees the complaint on the box they left empty rather than at the top
        of the form. Asserting only "it was refused" would pass with the guard removed.
        """
        issuance = _unresolved_issuance(self.customer, self.currency, number="E")

        with self.assertRaises(ValidationError) as caught:
            adopt_provider_document(
                issuance_id=issuance.pk, series="FCT", number="000902", actor=self._actor(reason="   ")
            )

        self.assertIn(
            "reason",
            caught.exception.message_dict,
            f"the error must name the field; got {caught.exception.message_dict}",
        )
        unchanged = ProviderIssuance.objects.get(pk=issuance.pk)
        self.assertEqual(unchanged.state, IssuanceState.OUTCOME_UNKNOWN.value)

    def test_an_audit_failure_rolls_the_adoption_back(self) -> None:
        """Attribution is the point of this command, so it cannot be best-effort.

        The audit was written AFTER `reconcile_confirmed_issued` had committed, so a
        failure between the two left a legal fiscal number assigned to an invoice with
        no record of who decided it or why - which ADR-0016 does not permit for a manual
        act of this kind. The number is unchangeable afterwards, so there is no second
        chance to attach the missing attribution.
        """
        issuance = _unresolved_issuance(self.customer, self.currency, number="H")

        with (
            patch(
                "apps.billing.operator_controls._audit_configuration_change",
                side_effect=RuntimeError("audit backend unavailable"),
            ),
            self.assertRaises(RuntimeError),
        ):
            adopt_provider_document(
                issuance_id=issuance.pk, series="FCT", number="000904", actor=self._actor()
            )

        unchanged = ProviderIssuance.objects.select_related("invoice").get(pk=issuance.pk)
        self.assertEqual(unchanged.state, IssuanceState.OUTCOME_UNKNOWN.value)
        self.assertIsNone(
            unchanged.invoice.number,
            "a fiscal number assigned with no record of who ordered it must not survive",
        )

    def test_adopting_a_settled_invoice_converges_it_to_paid(self) -> None:
        """Money can already be recorded against a document that was an unnumbered draft.

        `_finalize` converges payment state the moment the document legally exists, for
        exactly this reason; the manual path numbered the invoice and stopped. It then
        sat at `issued` with a zero balance, so `paid_at` was never set, payment history
        and pending-service activation never ran, and the issue signal could schedule
        payment reminders for a customer who owes nothing.
        """
        issuance = _unresolved_issuance(self.customer, self.currency, number="I")
        create_payment(
            PaymentCreationRequest(
                customer=self.customer,
                invoice=issuance.invoice,
                currency=self.currency,
                amount_cents=issuance.invoice.total_cents,
                status="succeeded",
            )
        )

        adopt_provider_document(issuance_id=issuance.pk, series="FCT", number="000905", actor=self._actor())

        settled = Invoice.objects.get(pk=issuance.invoice_id)
        self.assertEqual(settled.status, "paid", "a fully covered invoice must not stay issued")
        self.assertIsNotNone(settled.paid_at)

    def test_adopting_an_unpaid_invoice_leaves_it_issued(self) -> None:
        """The regression guard: convergence must not invent a payment."""
        issuance = _unresolved_issuance(self.customer, self.currency, number="J")

        adopt_provider_document(issuance_id=issuance.pk, series="FCT", number="000906", actor=self._actor())

        self.assertEqual(Invoice.objects.get(pk=issuance.invoice_id).status, "issued")

    def test_a_number_already_adopted_elsewhere_is_refused(self) -> None:
        """Two PRAHO records claiming one legal number is the failure to prevent."""
        taken = _unresolved_issuance(self.customer, self.currency, number="F")
        adopt_provider_document(issuance_id=taken.pk, series="FCT", number="000903", actor=self._actor())
        second = _unresolved_issuance(self.customer, self.currency, number="G")

        with self.assertRaises(ValidationError):
            adopt_provider_document(issuance_id=second.pk, series="FCT", number="000903", actor=self._actor())

        unchanged = ProviderIssuance.objects.get(pk=second.pk)
        self.assertEqual(unchanged.state, IssuanceState.OUTCOME_UNKNOWN.value)
