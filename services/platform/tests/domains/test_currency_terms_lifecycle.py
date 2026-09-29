"""Domain currency commitments survive preparation, registrar delays and retries."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from decimal import Decimal
from threading import Barrier
from unittest import skipUnless
from unittest.mock import patch

from dateutil.relativedelta import relativedelta
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, transaction
from django.test import TestCase, TransactionTestCase
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.audit.models import AuditEvent
from apps.billing.currency_models import Currency, FXRate
from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.currency_transition_notice import terms_fingerprint
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.domains.currency_terms import (
    apply_effective_domain_terms,
    committed_domain_terms,
    domain_renewal_quote,
    purchase_renewal_terms,
)
from apps.domains.gateways import DomainInfoResult
from apps.domains.models import (
    TLD,
    Domain,
    DomainCurrencyTransition,
    DomainOperation,
    DomainOrderItem,
    Registrar,
    TLDRegistrarAssignment,
    TLDRetailPrice,
)
from apps.domains.operation_services import DomainOperationService
from apps.domains.services import DomainLifecycleService, DomainOrderService
from apps.notifications.models import EmailLog
from apps.orders.models import Order
from apps.settings.services import SettingsService
from tests.domains.test_gateway_registration_wiring import _give_registrant_data


class DomainCurrencyFixture:
    def setUp(self):
        for code in ("RON", "EUR"):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
        FXRate.objects.create(
            base_code_id="EUR", quote_code_id="RON", rate=Decimal("4.97"), as_of=timezone.localdate(),
            source=FXRate.Source.BNR, source_reference="domain-lifecycle-test", fetched_at=timezone.now(),
        )
        self.customer = Customer.objects.create(name="Domain owner", primary_email="owner@example.test")
        self.tld = TLD.objects.create(extension="com", registration_price_cents=6000,
                                      renewal_price_cents=5000, transfer_price_cents=4500)
        TLDRetailPrice.objects.create(tld=self.tld, currency_id="EUR", registration_price_cents=1200,
                                      renewal_price_cents=1100, transfer_price_cents=900)
        self.registrar = Registrar.objects.create(name="gandi", api_endpoint="https://api.sandbox.gandi.net/v5")
        self.domain = Domain.objects.create(
            name="lifecycle.com", customer=self.customer, tld=self.tld, registrar=self.registrar,
            status="active", registrar_domain_id="lifecycle", expires_at=timezone.now() + timedelta(days=90),
        )

    def accepted_offer(self, target_code="EUR"):
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", target_code), Ok)
        target = purchase_renewal_terms(self.tld, self.domain.name, self.customer.pk, target_code, False)
        sent_at = timezone.now() - timedelta(days=31)
        with patch("django.utils.timezone.now", return_value=sent_at):
            offer = DomainCurrencyTransition.objects.create(
                domain=self.domain, policy_revision=get_selling_currency_policy().revision,
                old_terms=committed_domain_terms(self.domain), target_terms=target, target_fingerprint=terms_fingerprint(target),
                notice_recipient=self.customer.primary_email, notice_subject="Renewal terms",
                notice_body="Renewal changes from 50 RON to 11 EUR after 30 days", notice_attempted_at=sent_at,
            )
            offer.notice_email = EmailLog.objects.create(
                customer=self.customer, to_addr=self.customer.primary_email, subject=offer.notice_subject,
                body_text=offer.notice_body, template_key=f"domain_currency_notice:{offer.pk}", status="sent",
            )
            offer.accept_notice()
            offer.save()
        return offer

    def prepare_eur_item(self):
        order = Order.objects.create(customer=self.customer, currency_id="EUR")
        ok, item = DomainOrderService.create_domain_order_item(order, self.domain.name, "renew")
        self.assertTrue(ok, item)
        return item


class DomainCurrencyCommitmentTests(DomainCurrencyFixture, TestCase):
    def test_manual_protection_retains_original_price_despite_mature_notice(self):
        self.accepted_offer()
        self.domain.currency_hold_reason = "Indefinite fixed-currency commitment"
        self.domain.save(update_fields=["currency_hold_reason"])
        quote = domain_renewal_quote(self.domain)
        self.assertEqual((quote.currency_code, quote.unit_price_cents), ("RON", 5000))

    def test_committed_terms_start_at_boundary_and_never_modify_old_document(self):
        offer = self.accepted_offer()
        item = self.prepare_eur_item()
        with transaction.atomic():
            locked = Domain.objects.select_for_update().get(pk=self.domain.pk)
            self.assertFalse(apply_effective_domain_terms(locked, effective_at=self.domain.expires_at - timedelta(seconds=1)))
            self.assertTrue(apply_effective_domain_terms(locked, effective_at=self.domain.expires_at))
            self.assertFalse(apply_effective_domain_terms(locked, effective_at=self.domain.expires_at + timedelta(days=1)))
        self.domain.refresh_from_db()
        self.assertEqual((self.domain.billing_currency_id, self.domain.renewal_unit_price_cents), ("EUR", 1100))
        item.refresh_from_db()
        self.assertEqual((item.order.currency_id, item.total_price_cents), ("EUR", 1100))
        offer.refresh_from_db()
        self.assertEqual(offer.committed_item_id, item.pk)

    def test_accepted_notice_and_prepared_order_item_cannot_be_repriced(self):
        offer = self.accepted_offer()
        item = self.prepare_eur_item()
        offer.target_terms = {**offer.target_terms, "unit_price_cents": 9000}
        with self.assertRaises(ValidationError):
            offer.save()
        item.unit_price_cents = 9000
        with self.assertRaises(ValidationError):
            item.save()

    def test_offer_creation_and_commit_are_audited(self):
        offer = self.accepted_offer()
        self.prepare_eur_item()
        states = list(AuditEvent.objects.filter(object_id=str(offer.pk)).values_list("new_values", flat=True))
        self.assertTrue(any(row.get("status") == "pending" for row in states))
        self.assertTrue(any(row.get("status") == "notified" for row in states))
        self.assertTrue(any(row.get("status") == "committed" for row in states))

    def test_failed_commit_leaves_no_half_prepared_document(self):
        self.accepted_offer()
        order = Order.objects.create(customer=self.customer, currency_id="EUR")
        with patch("apps.domains.currency_terms.commit_domain_quote", side_effect=ValueError("commit failed")):
            ok, _ = DomainOrderService.create_domain_order_item(order, self.domain.name, "renew")
        self.assertFalse(ok)
        self.assertFalse(order.domain_items.exists())

    def test_original_promise_remains_usable_when_its_catalog_price_is_retired(self):
        self.accepted_offer()
        self.domain.currency_hold_reason = "Indefinite fixed-currency commitment"
        self.domain.save(update_fields=["currency_hold_reason"])
        TLDRetailPrice.objects.filter(tld=self.tld, currency_id="RON").delete()
        order = Order.objects.create(customer=self.customer, currency_id="RON")
        ok, item = DomainOrderService.create_domain_order_item(order, self.domain.name, "renew")
        self.assertTrue(ok, item)
        self.assertEqual((item.order.currency_id, item.unit_price_cents), ("RON", 5000))

    def test_expired_domain_activates_committed_terms_after_notice_without_backdating_money(self):
        self.domain.expires_at = timezone.now() - timedelta(days=1)
        self.domain.save(update_fields=["expires_at"])
        self.accepted_offer()
        item = self.prepare_eur_item()
        with transaction.atomic():
            locked = Domain.objects.select_for_update().get(pk=self.domain.pk)
            self.assertTrue(apply_effective_domain_terms(locked))
        self.domain.refresh_from_db()
        self.assertEqual(self.domain.billing_currency_id, "EUR")
        self.assertEqual(item.order.currency_id, "EUR")

    def test_prepared_old_currency_period_defers_future_terms_to_next_unprepared_period(self):
        old_order = Order.objects.create(customer=self.customer, currency_id="RON")
        ok, old_item = DomainOrderService.create_domain_order_item(old_order, self.domain.name, "renew", years=2)
        self.assertTrue(ok, old_item)
        offer = self.accepted_offer()
        item = self.prepare_eur_item()
        offer.refresh_from_db()
        self.assertEqual(offer.effective_period_start, self.domain.expires_at + relativedelta(years=2))
        self.assertEqual(parse_datetime(item.renewal_terms["period_start"]), offer.effective_period_start)
        with transaction.atomic():
            locked = Domain.objects.select_for_update().get(pk=self.domain.pk)
            self.assertFalse(apply_effective_domain_terms(locked, effective_at=self.domain.expires_at))
        old_item.refresh_from_db()
        self.assertEqual((old_item.order.currency_id, old_item.total_price_cents), ("RON", 10000))

    def test_cancelled_old_document_releases_its_period_without_changing_its_money(self):
        old_order = Order.objects.create(customer=self.customer, currency_id="RON")
        ok, old_item = DomainOrderService.create_domain_order_item(old_order, self.domain.name, "renew", years=2)
        self.assertTrue(ok, old_item)
        Order.objects.filter(pk=old_order.pk).update(status="cancelled")
        offer = self.accepted_offer()
        self.prepare_eur_item()
        offer.refresh_from_db()
        self.assertEqual(offer.effective_period_start, self.domain.expires_at)
        old_item.refresh_from_db()
        self.assertEqual((old_item.order.currency_id, old_item.total_price_cents), ("RON", 10000))

    def test_unknown_legacy_prepared_period_defers_currency_change(self):
        old_order = Order.objects.create(customer=self.customer, currency_id="RON", status="awaiting_payment")
        DomainOrderItem.objects.create(
            order=old_order, domain=self.domain, domain_name=self.domain.name, tld=self.tld,
            action="renew", years=1, unit_price_cents=5000, total_price_cents=5000,
        )
        self.accepted_offer()
        quote = domain_renewal_quote(self.domain)
        self.assertEqual((quote.currency_code, quote.unit_price_cents), ("RON", 5000))

    def test_malformed_imported_period_holds_the_original_currency(self):
        order = Order.objects.create(customer=self.customer, currency_id="RON")
        ok, item = DomainOrderService.create_domain_order_item(order, self.domain.name, "renew")
        self.assertTrue(ok, item)
        DomainOrderItem.objects.filter(pk=item.pk).update(renewal_terms="unproven import")
        self.accepted_offer()
        quote = domain_renewal_quote(self.domain)
        self.assertEqual((quote.currency_code, quote.unit_price_cents), ("RON", 5000))

    def test_second_currency_change_cannot_overwrite_an_earlier_prepared_period(self):
        first = self.accepted_offer()
        first_item = self.prepare_eur_item()
        second = self.accepted_offer("RON")
        second_order = Order.objects.create(customer=self.customer, currency_id="RON")
        ok, second_item = DomainOrderService.create_domain_order_item(second_order, self.domain.name, "renew")
        self.assertTrue(ok, second_item)
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual(second.effective_period_start, first.effective_period_start + relativedelta(years=1))
        with transaction.atomic():
            locked = Domain.objects.select_for_update().get(pk=self.domain.pk)
            self.assertTrue(apply_effective_domain_terms(locked, effective_at=first.effective_period_start))
            self.assertEqual(locked.billing_currency_id, "EUR")
            self.assertTrue(apply_effective_domain_terms(locked, effective_at=second.effective_period_start))
            self.assertEqual(locked.billing_currency_id, "RON")
        first_item.refresh_from_db()
        self.assertEqual((first_item.order.currency_id, first_item.unit_price_cents), ("EUR", 1100))
        self.assertEqual((second_item.order.currency_id, second_item.unit_price_cents), ("RON", 5000))

    def test_effective_term_activation_records_original_and_new_currency_in_audit(self):
        offer = self.accepted_offer()
        self.prepare_eur_item()
        offer.refresh_from_db()
        with transaction.atomic():
            locked = Domain.objects.select_for_update().get(pk=self.domain.pk)
            apply_effective_domain_terms(locked, effective_at=offer.effective_period_start)
        events = AuditEvent.objects.filter(object_id=str(self.domain.pk), action="domain_updated")
        self.assertTrue(any(
            event.old_values.get("billing_currency") == "RON"
            and event.new_values.get("billing_currency") == "EUR"
            and event.new_values.get("renewal_unit_price_cents") == 1100
            for event in events
        ))


class DomainCurrencyGatewayTests(DomainCurrencyFixture, TransactionTestCase):
    def test_late_registration_keeps_the_original_order_currency_and_renewal_promise(self):
        self.customer.customer_type = "individual"
        self.customer.primary_phone = "+40712345678"
        self.customer.save(update_fields=["customer_type", "primary_phone"])
        _give_registrant_data(self.customer, cnp="1900101123456")
        TLDRegistrarAssignment.objects.create(tld=self.tld, registrar=self.registrar, is_primary=True)
        order = Order.objects.create(customer=self.customer, currency_id="RON")
        ok, item = DomainOrderService.create_domain_order_item(order, "later.com", "register")
        self.assertTrue(ok, item)
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)
        TLDRetailPrice.objects.filter(tld=self.tld, currency_id="RON").update(renewal_price_cents=9900)
        expiry = timezone.now() + relativedelta(years=1)
        with patch(
            "apps.domains.services.DomainRegistrarGateway.register_domain",
            return_value=(True, {"registrar_domain_id": "later", "expires_at": expiry, "nameservers": []}),
        ) as register:
            result = DomainLifecycleService.create_domain_registration(
                self.customer, item.domain_name, order_item=item,
            )
        self.assertTrue(result.is_ok(), result)
        register.assert_called_once()
        created = result.unwrap()
        self.assertEqual((created.status, created.billing_currency_id, created.renewal_unit_price_cents),
                         ("active", "RON", 5000))
        item.refresh_from_db()
        self.assertEqual((item.order.currency_id, item.unit_price_cents), ("RON", 6000))

    def renew_from_registrar(self, token):
        self.domain.refresh_from_db()
        previous = self.domain.expires_at
        expiry = previous + relativedelta(years=1)
        info = DomainInfoResult("lifecycle", self.domain.name, "active", previous, [])
        with (
            patch("apps.domains.services.DomainRegistrarGateway.get_domain_info", return_value=Ok(info)),
            patch("apps.domains.services.DomainRegistrarGateway.renew_domain", return_value=(True, {"new_expires_at": expiry})),
        ):
            result = DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token=token)
        self.assertTrue(result.is_ok(), result)
        return expiry

    def test_successful_early_renewal_and_late_old_settlement_do_not_roll_terms_backward(self):
        old_order = Order.objects.create(customer=self.customer, currency_id="RON")
        ok, old_item = DomainOrderService.create_domain_order_item(old_order, self.domain.name, "renew")
        self.assertTrue(ok, old_item)
        self.accepted_offer()
        item = self.prepare_eur_item()
        boundary = parse_datetime(item.renewal_terms["period_start"])
        expiry = self.renew_from_registrar(f"order_item:{item.pk}")
        self.domain.refresh_from_db()
        self.assertEqual(self.domain.expires_at, expiry)
        self.assertEqual(self.domain.billing_currency_id, "RON")
        with patch("django.utils.timezone.now", return_value=boundary + timedelta(days=1)):
            self.renew_from_registrar(f"order_item:{old_item.pk}")
        self.domain.refresh_from_db()
        self.assertEqual((self.domain.billing_currency_id, self.domain.renewal_unit_price_cents), ("EUR", 1100))
        self.assertEqual(old_order.currency_id, "RON")
        old_item.refresh_from_db()
        self.assertEqual(old_item.unit_price_cents, 5000)

    def test_late_registrar_success_does_not_revive_cancelled_domain_or_activate_price(self):
        self.accepted_offer()
        self.prepare_eur_item()
        boundary = self.domain.expires_at
        operation = DomainOperation.objects.create(
            domain=self.domain, registrar=self.registrar, operation_type="renew", state="submitted",
            parameters={"years": 1, "prev_expires_at": boundary.isoformat()},
        )
        self.domain.suspend()
        self.domain.cancel()
        self.domain.save()
        with patch("django.utils.timezone.now", return_value=boundary + timedelta(days=1)):
            self.assertTrue(DomainOperationService.confirm_renewal(operation, boundary + relativedelta(years=1)))
        self.domain.refresh_from_db()
        self.assertEqual(self.domain.status, "cancelled")
        self.assertEqual(self.domain.billing_currency_id, "RON")

    def test_currency_ambiguity_does_not_erase_confirmed_registrar_extension(self):
        offer = self.accepted_offer()
        self.prepare_eur_item()
        boundary = self.domain.expires_at
        # Simulate an imported/corrupt old promise; registrar proof must still persist.
        DomainCurrencyTransition.objects.filter(pk=offer.pk).update(target_terms={"schema": 0})
        operation = DomainOperation.objects.create(
            domain=self.domain, registrar=self.registrar, operation_type="renew", state="submitted",
            parameters={"years": 1, "prev_expires_at": boundary.isoformat()},
        )
        expiry = boundary + relativedelta(years=1)
        with patch("django.utils.timezone.now", return_value=boundary + timedelta(days=1)):
            self.assertTrue(DomainOperationService.confirm_renewal(operation, expiry))
        self.domain.refresh_from_db()
        operation.refresh_from_db()
        self.assertEqual((operation.state, self.domain.expires_at), ("completed", expiry))
        self.assertEqual(self.domain.billing_currency_id, "RON")
        self.assertTrue(self.domain.currency_hold_reason)

    @skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL row locks")
    def test_concurrent_document_preparation_commits_one_offer(self):
        offer = self.accepted_offer()
        orders = [Order.objects.create(customer=self.customer, currency_id="EUR") for _ in range(2)]
        barrier = Barrier(2)

        def prepare(order_id):
            close_old_connections()
            try:
                order = Order.objects.get(pk=order_id)
                barrier.wait(timeout=10)
                ok, item = DomainOrderService.create_domain_order_item(order, self.domain.name, "renew")
                return ok, item.unit_price_cents if ok else item
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(prepare, [order.pk for order in orders]))
        self.assertEqual(results, [(True, 1100), (True, 1100)])
        offer.refresh_from_db()
        self.assertEqual(offer.status, "committed")
        self.assertEqual(DomainCurrencyTransition.objects.filter(status="committed").count(), 1)
        starts = [item.renewal_terms["period_start"] for item in self.domain.order_items.all()]
        self.assertCountEqual(starts, [
            self.domain.expires_at.isoformat(), (self.domain.expires_at + relativedelta(years=1)).isoformat(),
        ])
