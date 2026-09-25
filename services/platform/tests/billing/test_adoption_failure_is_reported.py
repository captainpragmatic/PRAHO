"""The adoption screen answered a 500 on the one page whose output cannot be corrected.

`adopt_provider_document` translates `reconcile_confirmed_issued`'s `Err` into a
`ValidationError`, which the view turns into a form error. Three things bypassed that and
escaped as a server error instead.

`invoice.issue()` is `@transition(source="draft")`, and `reconcile_confirmed_issued` checks the
ISSUANCE's state but never the invoice's - so an invoice that has moved on raises
`TransitionNotAllowed`, which is caught nowhere in `apps/billing/`. `invoice.save()` can raise
`IntegrityError` on the unique number, because the clash pre-check does not lock the row it
checked. And an over-long composed number reaches the column as a `DataError`; the form guards
that, but the service function is public and callable directly.

The sibling already does this: `rotate_invoice_series` converts an `IntegrityError` from a
concurrent create into a `ValidationError` keyed to a field. No savepoint work is needed here -
`reconcile_confirmed_issued` opens its own unconditional `transaction.atomic()`, and the
translation raises immediately, so the outer block rolls back whole either way.

What matters for an operator is the pair below: the failure is reported on the field they would
retype, and NOTHING is half-adopted - the issuance is still awaiting reconciliation and the
invoice still has no number, so they can try again.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import TransactionTestCase
from django.urls import reverse

from apps.billing.invoice_models import ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.operator_controls import BillingControlActor, adopt_provider_document
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory
from tests.factories.core_factories import create_admin_user


class AdoptionFailureIsReportedTests(TransactionTestCase):
    """`TransactionTestCase` so the command's atomic block is a real transaction."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self.user = create_admin_user(username="adopt_failure")

    def _unresolved(self, *, invoice_status: str = "draft") -> ProviderIssuance:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
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
        if invoice_status != "draft":
            Invoice.objects.filter(pk=invoice.pk).update(status=invoice_status)
        issuance = ProviderIssuance.objects.create(
            invoice=invoice,
            provider=ISSUER_SMARTBILL,
            last_error="No usable reply from SmartBill",
        )
        ProviderIssuance.objects.filter(pk=issuance.pk).update(state=IssuanceState.OUTCOME_UNKNOWN.value)
        return ProviderIssuance.objects.get(pk=issuance.pk)

    def _actor(self) -> BillingControlActor:
        return BillingControlActor(
            user=self.user,
            reason="Checked the SmartBill web UI and found this document.",
            ip_address="127.0.0.1",
        )

    def _adopt(self, issuance: ProviderIssuance, number: str = "0000123") -> str:
        return adopt_provider_document(
            issuance_id=issuance.pk,
            series="FCT",
            number=number,
            actor=self._actor(),
        )

    def test_an_invoice_that_can_no_longer_be_issued_is_reported(self) -> None:
        """`issue()` is source="draft"; the service checks the issuance's state, not this one."""
        issuance = self._unresolved(invoice_status="void")

        with self.assertRaises(ValidationError):
            self._adopt(issuance)

    def test_nothing_is_half_adopted_when_the_transition_fails(self) -> None:
        issuance = self._unresolved(invoice_status="void")

        with self.assertRaises(ValidationError):
            self._adopt(issuance)

        after = ProviderIssuance.objects.get(pk=issuance.pk)
        self.assertEqual(after.state, IssuanceState.OUTCOME_UNKNOWN.value)
        self.assertIsNone(Invoice.objects.get(pk=issuance.invoice_id).number)

    def test_a_number_that_collides_under_the_lock_is_reported_on_the_number_field(self) -> None:
        """The clash pre-check does not lock the row it checked, so two adoptions can collide.

        `select_for_update` is a no-op on SQLite, so the real race is not reproducible in this
        suite; the collaborator is made to raise what the database would.
        """
        issuance = self._unresolved()

        with (
            patch(
                "apps.billing.issuers.service.reconcile_confirmed_issued",
                side_effect=IntegrityError("UNIQUE constraint failed: billing_invoices.number"),
            ),
            self.assertRaises(ValidationError) as caught,
        ):
            self._adopt(issuance)

        self.assertIn("number", caught.exception.message_dict)

    def test_the_screen_shows_an_error_instead_of_failing(self) -> None:
        """The whole point: this page's output cannot be corrected afterwards."""
        issuance = self._unresolved(invoice_status="void")
        self.client.force_login(self.user)

        response = self.client.post(
            reverse("billing:provider_reconciliation_adopt", args=[issuance.pk]),
            {
                "series": "FCT",
                "number": "0000123",
                "confirmation": "0000123",
                "reason": "Checked the SmartBill web UI and found this document.",
            },
        )

        self.assertEqual(response.status_code, 200, "a 500 here leaves the operator with no next move")
        self.assertContains(response, "can no longer be issued")
        self.assertIsNone(Invoice.objects.get(pk=issuance.invoice_id).number)

    def test_a_clean_adoption_still_works(self) -> None:
        issuance = self._unresolved()

        legal_number = self._adopt(issuance)

        self.assertEqual(legal_number, "FCT-0000123")
        self.assertEqual(Invoice.objects.get(pk=issuance.invoice_id).number, "FCT-0000123")
