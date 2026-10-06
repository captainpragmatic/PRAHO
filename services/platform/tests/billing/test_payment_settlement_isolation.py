"""Settlement ownership and optional billing effects on real database rows."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.db import DatabaseError, connection, transaction
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from django_fsm import TransitionNotAllowed

from apps.billing import signals
from apps.billing.invoice_models import Invoice
from apps.billing.models import Currency, Payment, PaymentRetryAttempt, ProformaInvoice, TaxRule, VATValidation
from apps.billing.payment_convergence import PaymentSuccessService
from apps.billing.views import process_payment
from apps.common.types import Ok, Result
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.provisioning.models import Service, ServicePlan
from apps.users.models import User
from tests.factories.billing_factories import CurrencyFactory, CustomerFactory, InvoiceFactory


def prepare_case(test: SimpleTestCase) -> tuple[Customer, Currency, Invoice, User]:
    for target in ("django_q.tasks.async_task", "apps.notifications.services.EmailService.send_template_email"):
        quiet = patch(target, return_value="test-delivery")
        quiet.start()
        test.addCleanup(quiet.stop)
    customer = CustomerFactory()
    currency = CurrencyFactory()
    invoice = InvoiceFactory(customer=customer, currency=currency, number=f"WP13-{uuid4().hex}", bill_to_country="DE")
    staff = User.objects.create_user(email=f"{uuid4().hex}@example.test", password="test", is_superuser=True)
    return customer, currency, invoice, staff


def offline_request(invoice: Invoice, staff: User, amount: str = "100.00") -> HttpResponse:
    request = RequestFactory().post("/", {"amount": amount, "payment_method": "bank", "reference": "WP13"})
    request.user = staff
    SessionMiddleware(lambda _request: HttpResponse()).process_request(request)
    MessageMiddleware(lambda _request: HttpResponse()).process_request(request)
    return process_payment(request, invoice.pk)


def fail_write(*_args: object, **_kwargs: object) -> None:
    Currency.objects.create(code="RON", symbol="duplicate")


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class PaymentSettlementTests(TestCase):
    def setUp(self) -> None:
        self.customer, self.currency, self.invoice, self.staff = prepare_case(self)

    def payment(self, amount_cents: int = 10000) -> Payment:
        return Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=amount_cents,
            payment_method="bank",
        )

    def assert_isolated(self, effect: Callable[[], None]) -> None:
        with transaction.atomic():
            effect()
            self.assertFalse(connection.needs_rollback, "optional effect poisoned its caller")
            self.customer.company_name = "Outer write survived"
            self.customer.save(update_fields=["company_name"])
        self.customer.refresh_from_db()
        self.assertEqual(self.customer.company_name, "Outer write survived")

    def test_failed_payment_audit_still_settles(self) -> None:
        payment = self.payment()
        with (
            transaction.atomic(),
            patch.object(signals.BillingAuditService, "log_payment_event", side_effect=fail_write),
        ):
            payment.succeed()
            payment.save(update_fields=["status"])
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")
        self.assertIsNotNone(self.invoice.paid_at)
        self.assertEqual(Payment.objects.get(pk=payment.pk).status, "succeeded")

    def test_staff_required_settlement_failure_is_409_and_rolls_back_payment(self) -> None:
        original = Invoice.mark_as_paid
        refused = False

        def refuse_first(invoice: Invoice) -> None:
            nonlocal refused
            if not refused:
                refused = True
                raise DatabaseError("required settlement failed")
            original(invoice)

        with patch.object(Invoice, "mark_as_paid", refuse_first):
            response = offline_request(self.invoice, self.staff)
        self.assertEqual(response.status_code, 409)
        self.assertFalse(Payment.objects.filter(invoice=self.invoice).exists())
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "issued")

    def test_convergence_persists_pending_success_and_settlement_together(self) -> None:
        payment = self.payment()
        result = PaymentSuccessService.converge_local_paid_document(payment.pk)
        self.assertTrue(result.is_ok(), str(result))
        payment.refresh_from_db()
        self.invoice.refresh_from_db()
        self.assertEqual((payment.status, self.invoice.status), ("succeeded", "paid"))

    def test_convergence_failure_rolls_back_pending_success(self) -> None:
        payment = self.payment()
        failure = DatabaseError("required settlement failed")
        with patch.object(Invoice, "mark_as_paid", side_effect=failure):
            result = PaymentSuccessService.converge_local_paid_document(payment.pk)
        self.assertTrue(result.is_err())
        self.assertIn("required settlement failed", result.unwrap_err())
        payment.refresh_from_db()
        self.invoice.refresh_from_db()
        self.assertEqual((payment.status, self.invoice.status), ("pending", "issued"))

    def test_replay_survives_failed_audit_without_second_settlement(self) -> None:
        response = offline_request(self.invoice, self.staff)
        self.assertEqual(response.status_code, 200)
        payment = Payment.objects.get(invoice=self.invoice)
        self.invoice.refresh_from_db()
        paid_at = self.invoice.paid_at
        with (
            transaction.atomic(),
            patch.object(signals.BillingAuditService, "log_payment_event", side_effect=fail_write),
        ):
            payment.meta = {**payment.meta, "replay": True}
            payment.save(update_fields=["meta"])
            self.assertFalse(connection.needs_rollback, "replay audit poisoned its caller")
            result = PaymentSuccessService.converge_local_paid_document(payment.pk)
            self.assertTrue(result.is_ok(), str(result))
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.paid_at, paid_at)
        self.assertEqual(Payment.objects.filter(invoice=self.invoice, status="succeeded").count(), 1)
        self.assertTrue(Payment.objects.get(pk=payment.pk).meta["replay"])

    def test_deferral_is_honoured_even_when_audit_fails(self) -> None:
        payment = self.payment()
        payment._defer_document_settlement = True
        payment.succeed()
        with patch.object(signals.BillingAuditService, "log_payment_event", side_effect=fail_write):
            self.assert_isolated(lambda: payment.save(update_fields=["status"]))
        self.assertEqual(Payment.objects.get(pk=payment.pk).status, "succeeded")
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "issued")

    def test_external_unnumbered_draft_is_an_explicit_skip(self) -> None:
        draft = InvoiceFactory(
            customer=self.customer,
            currency=self.currency,
            status="draft",
            number=None,
            issuer_provider="smartbill",
            bill_to_country="DE",
        )
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=draft,
            currency=self.currency,
            amount_cents=draft.total_cents,
            payment_method="other",
        )
        with self.assertLogs("apps.billing.signals", level="INFO") as logged:
            payment.succeed()
            payment.save(update_fields=["status"])
        draft.refresh_from_db()
        self.assertEqual(draft.status, "draft")
        self.assertIsNone(draft.paid_at)
        self.assertEqual(Payment.objects.get(pk=payment.pk).status, "succeeded")
        self.assertIn("unnumbered external draft", " ".join(logged.output))
        self.assertFalse(any("Cannot mark invoice" in entry for entry in logged.output))

    def test_undeferred_required_settlement_failure_propagates(self) -> None:
        payment = self.payment()
        failure = DatabaseError("required settlement failed")
        with (
            patch.object(Invoice, "mark_as_paid", side_effect=failure),
            self.assertRaises(DatabaseError) as raised,
            transaction.atomic(),
        ):
            payment.succeed()
            payment.save(update_fields=["status"])
        self.assertIs(raised.exception, failure)
        self.assertEqual(Payment.objects.get(pk=payment.pk).status, "pending")
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "issued")

    def test_non_external_transition_refusal_propagates(self) -> None:
        payment = self.payment()
        failure = TransitionNotAllowed("refused for a reason other than already paid")
        with (
            patch.object(Invoice, "mark_as_paid", side_effect=failure),
            self.assertRaises(TransitionNotAllowed) as raised,
            transaction.atomic(),
        ):
            payment.succeed()
            payment.save(update_fields=["status"])
        self.assertIs(raised.exception, failure)
        self.assertEqual(Payment.objects.get(pk=payment.pk).status, "pending")

    def test_convergence_preserves_provisioning_after_document_payment_commits(self) -> None:
        payment = self.payment()
        payment._defer_document_settlement = True
        payment.succeed()
        payment.save(update_fields=["status"])
        queued: list[Invoice] = []
        with patch.object(signals, "_trigger_virtualmin_provisioning_on_payment", side_effect=queued.append):
            with self.captureOnCommitCallbacks(execute=True):
                result = PaymentSuccessService.converge_local_paid_document(payment.pk)
                self.assertTrue(result.is_ok(), str(result))
                self.assertEqual(queued, [])
            self.assertEqual([invoice.pk for invoice in queued], [self.invoice.pk])
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")

    def test_required_original_state_reads_propagate(self) -> None:
        payment = self.payment()
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"PF-{uuid4().hex}",
            valid_until=timezone.now() + timedelta(days=7),
        )
        for model, instance in ((Payment, payment), (ProformaInvoice, proforma)):
            with (
                self.subTest(model=model.__name__),
                patch.object(model.objects, "get", side_effect=DatabaseError("original read failed")),
                self.assertRaises(DatabaseError),
                transaction.atomic(),
            ):
                instance.save()

    def test_optional_payment_effects_have_independent_savepoints(self) -> None:
        payment = self.payment()
        payment._defer_document_settlement = True
        payment.succeed()
        payment.save(update_fields=["status"])
        cases: tuple[tuple[str, str, Callable[[], None]], ...] = (
            (
                "security",
                "log_security_event",
                lambda: signals._handle_payment_status_change(payment, "pending", "succeeded"),
            ),
            (
                "credit",
                "_apply_customer_payment_credit",
                lambda: signals._update_customer_payment_credit(payment, "pending"),
            ),
            (
                "failure",
                "_handle_payment_failure",
                lambda: signals._handle_payment_status_change(payment, "pending", "failed"),
            ),
            (
                "refund",
                "_handle_payment_refund",
                lambda: signals._handle_payment_status_change(payment, "succeeded", "refunded"),
            ),
            ("cleanup", "_revert_customer_credit_score", lambda: signals.handle_payment_cleanup(Payment, payment)),
        )
        for name, target, effect in cases:
            with self.subTest(effect=name), patch.object(signals, target, side_effect=fail_write):
                self.assert_isolated(effect)

    def test_conversion_tax_and_vat_audits_are_isolated(self) -> None:
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"PF-{uuid4().hex}",
            valid_until=timezone.now() + timedelta(days=7),
        )
        rule = TaxRule.objects.create(
            country_code="DE", tax_type="vat", rate=Decimal("0.19"), valid_from=timezone.localdate()
        )
        vat = VATValidation.objects.create(
            country_code="DE",
            vat_number="123456789",
            is_valid=True,
            validation_source="manual",
        )
        cases: tuple[tuple[object, str, Callable[[], None]], ...] = (
            (signals.BillingAuditService, "log_proforma_event", proforma.save),
            (signals.AuditService, "log_event", rule.save),
            (
                signals.AuditService,
                "log_compliance_event",
                lambda: signals.handle_vat_validation_result(VATValidation, vat, True),
            ),
        )
        for owner, method, effect in cases:
            with self.subTest(effect=method), patch.object(owner, method, side_effect=fail_write):
                self.assert_isolated(effect)

    def test_payment_email_effects_have_independent_savepoints(self) -> None:
        payment = self.payment()
        retry = PaymentRetryAttempt(payment=payment, status="success")
        effects: tuple[Callable[[], None], ...] = (
            lambda: signals._send_payment_success_email(payment),
            lambda: signals._send_payment_failed_email(payment),
            lambda: signals._send_payment_refund_email(payment),
            lambda: signals._send_retry_success_email(retry),
        )
        for index, effect in enumerate(effects):
            with (
                self.subTest(email=index),
                patch("apps.notifications.services.EmailService.send_template_email", side_effect=fail_write),
            ):
                self.assert_isolated(effect)

    def test_credit_revert_helper_rolls_back_its_own_failed_write(self) -> None:
        with patch("apps.customers.services.CustomerCreditService.revert_credit_change", side_effect=fail_write):
            self.assert_isolated(lambda: signals._revert_customer_credit_score(self.customer, "positive_payment"))

    def test_one_failed_service_does_not_skip_the_other(self) -> None:
        payment = self.payment()
        plan = ServicePlan.objects.create(name="WP13", plan_type="shared_hosting", price_monthly=Decimal("10"))
        product = Product.objects.create(name="WP13", slug="wp13-services", product_type="shared_hosting")
        order = Order.objects.create(customer=self.customer, currency=self.currency, invoice=self.invoice)
        services = [
            Service.objects.create(
                customer=self.customer,
                currency=self.currency,
                service_plan=plan,
                service_name=f"WP13-{index}",
                username=f"wp13-{index}",
                price=Decimal("10"),
            )
            for index in range(2)
        ]
        for service in services:
            OrderItem.objects.create(
                order=order,
                product=product,
                service=service,
                unit_price_cents=1000,
                product_name="WP13",
            )
        attempted: list[object] = []

        def activate(service: Service, **_kwargs: object) -> Result[Service, str]:
            attempted.append(service.pk)
            if len(attempted) == 1:
                fail_write()
            service.start_provisioning()
            service.save(update_fields=["status"])
            return Ok(service)

        with patch("apps.provisioning.services.ServiceActivationService.activate_service", side_effect=activate):
            self.assert_isolated(lambda: signals._activate_payment_services(payment))
        statuses = list(
            Service.objects.filter(pk__in=[service.pk for service in services]).values_list("status", flat=True)
        )
        self.assertCountEqual(statuses, ["pending", "provisioning"])

    def test_receipt_rollback_preserves_file_and_commit_uses_captured_path(self) -> None:
        payment = self.payment()
        payment.meta = {"receipt_file": "receipts/original.pdf"}
        files = {"receipts/original.pdf", "receipts/changed.pdf"}
        with (
            patch.object(signals.default_storage, "exists", side_effect=lambda path: path in files),
            patch.object(signals.default_storage, "delete", side_effect=files.remove),
        ):
            with transaction.atomic():
                signals._cleanup_payment_files(payment)
                transaction.set_rollback(True)
            self.assertIn("receipts/original.pdf", files)
            with self.captureOnCommitCallbacks(execute=True):
                with transaction.atomic():
                    signals._cleanup_payment_files(payment)
                    payment.meta["receipt_file"] = "receipts/changed.pdf"
                self.assertIn("receipts/original.pdf", files)
            self.assertNotIn("receipts/original.pdf", files)
            self.assertIn("receipts/changed.pdf", files)

    def test_retry_success_email_is_discarded_on_rollback(self) -> None:
        retry = PaymentRetryAttempt(payment=self.payment(), status="success")
        deliveries: list[PaymentRetryAttempt] = []
        with patch.object(signals, "_send_retry_success_email", side_effect=deliveries.append):
            with transaction.atomic():
                signals._handle_retry_completion(retry)
                transaction.set_rollback(True)
            self.assertEqual(deliveries, [])
            with self.captureOnCommitCallbacks(execute=True):
                signals._handle_retry_completion(retry)
                self.assertEqual(deliveries, [])
            self.assertEqual(deliveries, [retry])
