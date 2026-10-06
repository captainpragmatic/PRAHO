"""WP14: observable draft editing, recorded taxation and atomic refusals."""

from __future__ import annotations

import uuid
from decimal import Decimal

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.invoice_models import Invoice, InvoiceLine
from apps.billing.metering_models import BillingCycle
from apps.billing.payment_models import CreditLedger, Payment
from apps.billing.subscription_models import Subscription
from apps.billing.tax_evidence import capture_vat_evidence
from apps.common.tax_service import VATCalculationResult, VATScenario
from apps.common.types import Err
from apps.customers.models import Customer
from apps.products.models import Product
from apps.promotions.models import GiftCard, GiftCardReservation
from apps.provisioning.models import Service, ServicePlan
from apps.users.models import User
from tests.factories.billing_factories import create_currency


class DraftInvoiceEditTests(TestCase):
    def setUp(self) -> None:
        self.currency = create_currency()
        self.customer = Customer.objects.create(name="WP14 customer", customer_type="company")
        self.staff = User.objects.create_user(email="wp14@example.ro", staff_role="billing", is_staff=True)
        plan = ServicePlan.objects.create(name="WP14 plan", plan_type="shared_hosting", price_monthly=Decimal("10"))
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency=self.currency,
            service_name="WP14 hosting",
            username="wp14",
            price=Decimal("10"),
            billing_cycle="monthly",
        )
        self.client.force_login(self.staff)

    def _draft(
        self, *, scenario: VATScenario = VATScenario.ROMANIA_B2B, rate: Decimal = Decimal("21")
    ) -> tuple[Invoice, InvoiceLine]:
        decision = VATCalculationResult(
            scenario=scenario,
            vat_rate=rate,
            subtotal_cents=1000,
            vat_cents=int(rate * 10),
            total_cents=1000 + int(rate * 10),
            country_code="DE" if scenario == VATScenario.EU_B2B_REVERSE_CHARGE else "RO",
            is_business=True,
            vat_number=None,
            reasoning="Recorded test decision",
            audit_data={"calculated_at": timezone.now().isoformat()},
        )
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"WP14-{uuid.uuid4().hex}",
            due_at=timezone.now() + timezone.timedelta(days=14),
            vat_evidence=capture_vat_evidence(decision),
            meta={"keep": "untouched"},
        )
        line = InvoiceLine.objects.create(
            invoice=invoice,
            kind="service",
            service=self.service,
            description="Original hosting",
            quantity=Decimal("1.000"),
            unit_price_cents=1000,
            tax_rate=rate / 100,
            tax_category_code=invoice.vat_evidence["category"],
        )
        invoice.recalculate_totals()
        invoice.save()
        return invoice, line

    def _post_data(self, invoice: Invoice, line: InvoiceLine) -> dict[str, str]:
        return {
            "customer": str(invoice.customer_id),
            "currency": invoice.currency_id,
            "line_0_id": str(line.pk),
            "line_0_description": "Edited hosting",
            "line_0_quantity": "1.000",
            "line_0_unit_price": "10.00",
        }

    def _assert_refused(self, invoice: Invoice, data: dict[str, str], error: str) -> None:
        before = list(invoice.lines.order_by("pk").values())
        totals = (invoice.subtotal_cents, invoice.tax_cents, invoice.total_cents)
        metadata = dict(invoice.meta)
        response = self.client.post(reverse("billing:invoice_edit", args=[invoice.pk]), data)
        self.assertContains(response, error)
        invoice.refresh_from_db()
        self.assertEqual(list(invoice.lines.order_by("pk").values()), before)
        self.assertEqual((invoice.subtotal_cents, invoice.tax_cents, invoice.total_cents), totals)
        self.assertEqual(invoice.meta, metadata)
        self.assertFalse(AuditEvent.objects.filter(action="invoice_edited", object_id=str(invoice.pk)).exists())

    def test_half_up_cents(self) -> None:
        invoice, line = self._draft()
        data = self._post_data(invoice, line)
        data["line_0_unit_price"] = "0.125"
        self.client.post(reverse("billing:invoice_edit", args=[invoice.pk]), data)
        line.refresh_from_db()
        self.assertEqual(line.unit_price_cents, 13)
        invoice.refresh_from_db()
        self.assertEqual((invoice.subtotal_cents, invoice.tax_cents, invoice.total_cents), (13, 3, 16))

    def test_new_lines_use_recorded_domestic_and_reverse_charge_decisions(self) -> None:
        for scenario, rate, category in (
            (VATScenario.ROMANIA_B2B, Decimal("21"), "S"),
            (VATScenario.EU_B2B_REVERSE_CHARGE, Decimal("0"), "AE"),
        ):
            with self.subTest(scenario=scenario):
                invoice, line = self._draft(scenario=scenario, rate=rate)
                evidence = dict(invoice.vat_evidence)
                data = self._post_data(invoice, line)
                data.update(
                    {
                        "line_1_description": "Added line",
                        "line_1_quantity": "1",
                        "line_1_unit_price": "1.00",
                        "line_1_vat_rate": "NaN",
                        "line_1_tax_category_code": "O",
                    }
                )
                self.client.post(reverse("billing:invoice_edit", args=[invoice.pk]), data)
                self.assertTrue(invoice.lines.filter(description="Added line").exists())
                added = invoice.lines.get(description="Added line")
                self.assertEqual((added.tax_rate, added.tax_category_code), (rate / 100, category))
                invoice.refresh_from_db()
                self.assertEqual(invoice.vat_evidence, evidence)
                self.assertEqual(invoice.total_cents, 1331 if category == "S" else 1100)

    def test_customer_and_recorded_vat_edits_are_refused(self) -> None:
        other = Customer.objects.create(name="Another Romanian customer", customer_type="company")
        for field, value, error in (
            ("customer", str(other.pk), "The invoice customer cannot be changed."),
            ("line_0_vat_rate", "0.1100", "The recorded VAT rate and category cannot be edited."),
            ("line_0_tax_category_code", "AE", "The recorded VAT rate and category cannot be edited."),
        ):
            with self.subTest(field=field):
                invoice, line = self._draft()
                data = self._post_data(invoice, line)
                data[field] = value
                self._assert_refused(invoice, data, error)

    def test_late_validation_rolls_back_earlier_updates_and_creates(self) -> None:
        for field in ("quantity", "unit_price"):
            for value in ("NaN", "Infinity", "-Infinity", "garbage", "1_000"):
                with self.subTest(field=field, value=value):
                    invoice, line = self._draft()
                    data = self._post_data(invoice, line)
                    data.update(
                        {
                            "public_notes": "Must roll back",
                            "line_1_description": "Earlier create",
                            "line_1_quantity": "1",
                            "line_1_unit_price": "1",
                            "line_2_description": "Late invalid line",
                            "line_2_quantity": "1",
                            "line_2_unit_price": "1",
                            f"line_2_{field}": value,
                        }
                    )
                    self._assert_refused(invoice, data, "Line quantities and prices must be valid finite numbers.")

    def _allocate(self, invoice: Invoice, case: str) -> None:
        if case == "payment":
            Payment.objects.create(
                invoice=invoice,
                customer=self.customer,
                currency=self.currency,
                amount_cents=100,
                payment_method="bank_transfer",
                status="pending",
            )
        elif case == "credit":
            CreditLedger.objects.create(
                invoice=invoice,
                customer=self.customer,
                currency=self.currency,
                delta_cents=100,
                reason="Draft allocation",
            )
        else:
            card = GiftCard.objects.create(
                code=f"WP14-{uuid.uuid4().hex}",
                currency=self.currency,
                status="active",
                initial_value_cents=100,
                current_balance_cents=100,
            )
            GiftCardReservation.objects.create(
                gift_card=card,
                invoice=invoice,
                customer=self.customer,
                amount_cents=100,
                operation_key=f"wp14-{uuid.uuid4().hex}",
            )

    def _link_cycle(self, line: InvoiceLine) -> None:
        product = Product.objects.create(
            name="WP14 recurring",
            slug=f"wp14-{uuid.uuid4().hex}",
            product_type="hosting",
        )
        subscription = Subscription.objects.create(
            customer=self.customer,
            product=product,
            currency=self.currency,
            subscription_number=f"WP14-{uuid.uuid4().hex}",
            unit_price_cents=1000,
            next_billing_date=timezone.now(),
            current_period_start=timezone.now(),
            current_period_end=timezone.now() + timezone.timedelta(days=30),
        )
        line.billing_cycle = BillingCycle.objects.create(
            subscription=subscription,
            period_start=timezone.now(),
            period_end=timezone.now() + timezone.timedelta(days=30),
        )
        line.save()

    def test_each_refusal_preserves_rows(self) -> None:
        cases = (
            "external",
            "credit_note",
            "payment",
            "credit",
            "gift",
            "document_discount",
            "line_discount",
            "allowance",
            "charge",
            "currency",
            "cycle_delete",
            "cycle_price",
            "cycle_quantity",
            "duplicate_id",
            "foreign_id",
        )
        for case in cases:
            with self.subTest(case=case):
                invoice, line = self._draft()
                data = self._post_data(invoice, line)
                error = "Invoices with discounts or adjustments cannot be edited."
                if case == "external":
                    invoice.issuer_provider = "smartbill"
                    invoice.save()
                    error = "External issuer drafts are read-only. Use issuance reconciliation."
                elif case == "credit_note":
                    invoice = Invoice.objects.create(
                        customer=self.customer,
                        currency=self.currency,
                        document_kind="credit_note",
                        reverses_invoice=invoice,
                        number=f"WP14-CN-{uuid.uuid4().hex}",
                    )
                    line = InvoiceLine.objects.create(
                        invoice=invoice,
                        kind="credit",
                        description="Credit",
                        unit_price_cents=0,
                    )
                    data = self._post_data(invoice, line)
                    error = "Credit notes cannot be edited."
                elif case in {"payment", "credit", "gift"}:
                    self._allocate(invoice, case)
                    error = "Invoices with payment, credit or gift-card allocations cannot be edited."
                elif case == "document_discount":
                    invoice.discount_cents = 100
                    invoice.save()
                elif case == "line_discount":
                    line.discount_amount_cents = 100
                    line.save()
                elif case in {"allowance", "charge"}:
                    invoice.meta["allowances" if case == "allowance" else "charges"] = [{"amount_cents": 100}]
                    invoice.save()
                elif case == "currency":
                    data["currency"] = create_currency("EUR").pk
                    error = "The invoice currency cannot be changed."
                elif case.startswith("cycle_"):
                    self._link_cycle(line)
                    data = (
                        {"customer": str(self.customer.pk), "currency": self.currency.pk}
                        if case == "cycle_delete"
                        else {**data, "line_0_unit_price" if case == "cycle_price" else "line_0_quantity": "2"}
                    )
                    error = "Billing-cycle lines cannot be deleted or repriced."
                elif case == "duplicate_id":
                    data.update(
                        {
                            "line_1_id": str(line.pk),
                            "line_1_description": "Duplicate",
                            "line_1_quantity": "1",
                            "line_1_unit_price": "1",
                        }
                    )
                    error = "Duplicate invoice line ID."
                else:
                    _, foreign_line = self._draft()
                    data["line_0_id"] = str(foreign_line.pk)
                    error = "An invoice line belongs to another invoice or no longer exists."
                self._assert_refused(invoice, data, error)

    def test_issued_and_locked_invoices_are_refused(self) -> None:
        for issued in (True, False):
            with self.subTest(issued=issued):
                invoice, line = self._draft()
                if issued:
                    invoice.issue()
                else:
                    invoice.locked_at = timezone.now()
                invoice.save()
                self._assert_refused(
                    invoice, self._post_data(invoice, line), "Only an unlocked draft invoice can be edited."
                )

    def test_foreign_customer_and_permissions_are_refused(self) -> None:
        invoice, line = self._draft()
        foreign = Customer.objects.create(name="Foreign customer", customer_type="company")
        data = self._post_data(invoice, line)
        data["customer"] = str(foreign.pk)
        self._assert_refused(invoice, data, "The invoice customer cannot be changed.")

        from apps.billing.invoice_service import update_draft_invoice  # noqa: PLC0415

        for role in ("support", ""):
            with self.subTest(role=role):
                user = User.objects.create_user(
                    email=f"wp14-{role or 'customer'}@example.ro",
                    staff_role=role,
                    is_staff=bool(role),
                )
                result = update_draft_invoice(
                    invoice.pk,
                    {
                        "lines": [
                            {
                                "id": str(line.pk),
                                "description": "Forbidden",
                                "quantity": "1",
                                "unit_price": "1",
                            }
                        ]
                    },
                    user,
                )
                self.assertIsInstance(result, Err)
                if isinstance(result, Err):
                    self.assertEqual(result.error, "You do not have permission to edit this invoice.")
                self.client.force_login(user)
                response = self.client.post(reverse("billing:invoice_edit", args=[invoice.pk]), data)
                self.assertEqual(response.status_code, 302)
                line.refresh_from_db()
                self.assertEqual(line.description, "Original hosting")
        self.client.logout()
        self.assertEqual(self.client.post(reverse("billing:invoice_edit", args=[invoice.pk]), data).status_code, 302)

    def test_one_audit_event_records_field_and_line_diff(self) -> None:
        invoice, line = self._draft()
        data = self._post_data(invoice, line)
        data["internal_notes"] = "Reviewed draft"
        self.client.post(reverse("billing:invoice_edit", args=[invoice.pk]), data)
        events = AuditEvent.objects.filter(
            action="invoice_edited",
            content_type=ContentType.objects.get_for_model(Invoice),
            object_id=str(invoice.pk),
        )
        self.assertEqual(events.count(), 1)
        event = events.get()
        self.assertEqual(event.user_id, self.staff.pk)
        self.assertEqual(event.old_values["lines"][str(line.pk)]["description"], "Original hosting")
        self.assertEqual(event.new_values["lines"][str(line.pk)]["description"], "Edited hosting")
        self.assertEqual(event.metadata["diff"]["fields"]["internal_notes"], {"before": "", "after": "Reviewed draft"})
        self.assertIn(str(line.pk), event.metadata["diff"]["lines"]["updated"])

    def test_external_draft_get_and_post_show_reconciliation_notice(self) -> None:
        invoice, line = self._draft()
        invoice.issuer_provider = "smartbill"
        invoice.number = None
        invoice.save()
        url = reverse("billing:invoice_edit", args=[invoice.pk])
        response = self.client.get(url)
        self.assertContains(response, "External issuer drafts are read-only. Use issuance reconciliation.")
        self.assertContains(response, reverse("billing:provider_reconciliation_queue"))
        self.assertNotContains(response, 'id="invoice-form"')
        self._assert_refused(invoice, self._post_data(invoice, line), "External issuer drafts are read-only.")
        self.assertNotContains(
            self.client.get(reverse("billing:invoice_detail", args=[invoice.pk])),
            reverse("billing:invoice_edit", args=[invoice.pk]),
        )
