"""Domain renewals retain old terms until a successful notice has matured."""

# ruff: noqa: PLC0415 -- staged helpers are imported per test so missing code does not prevent collection

from datetime import timedelta
from decimal import Decimal
from typing import Any
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.currency_models import Currency, FXRate
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, DomainOrderItem, Registrar, TLDRetailPrice
from apps.notifications.models import EmailLog
from apps.notifications.services import EmailResult
from apps.orders.models import Order
from apps.settings.services import SettingsService


class DomainCurrencyTermsTests(TestCase):
    def setUp(self) -> None:
        for code in ("RON", "EUR"):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
        FXRate.objects.create(
            base_code_id="EUR", quote_code_id="RON", rate=Decimal("4.97"), as_of=timezone.localdate(),
            source=FXRate.Source.BNR, source_reference="domain-transition-test", fetched_at=timezone.now(),
        )
        self.customer = Customer.objects.create(name="Domain owner", primary_email="domain-owner@example.test")
        self.tld = TLD.objects.create(
            extension="com", registration_price_cents=6000, renewal_price_cents=5000, transfer_price_cents=4500,
        )
        TLDRetailPrice.objects.create(
            tld=self.tld, currency_id="EUR", registration_price_cents=1200,
            renewal_price_cents=1100, transfer_price_cents=900,
        )
        registrar = Registrar.objects.create(name="term-registrar", display_name="Term registrar")
        self.domain = Domain.objects.create(
            name="terms.com", customer=self.customer, tld=self.tld, registrar=registrar,
            status="active", registrar_domain_id="terms", expires_at=timezone.now() + timedelta(days=90),
        )

    def switch(self) -> None:
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)

    @staticmethod
    def accepted_email(**kwargs: Any) -> EmailResult:
        log = EmailLog.objects.create(
            to_addr=kwargs["to"], from_addr="billing@example.test", customer=kwargs["customer"],
            subject=kwargs["subject"], body_text=kwargs["body_text"], status="sent", provider="test",
            template_key=kwargs.get("template_key", ""),
        )
        return EmailResult(success=True, email_log_id=str(log.pk))

    def test_new_domain_records_explicit_renewal_currency_and_amount(self) -> None:
        self.assertEqual(self.domain.billing_currency_id, "RON")
        self.assertEqual(self.domain.renewal_unit_price_cents, 5000)
        self.switch()
        self.domain.refresh_from_db()
        self.assertEqual((self.domain.billing_currency_id, self.domain.renewal_unit_price_cents), ("RON", 5000))

    def test_failed_notice_keeps_original_terms(self) -> None:
        from apps.domains.currency_terms import domain_renewal_quote, reconcile_domain_currency_notices

        self.switch()
        with patch("apps.notifications.services.EmailService.send_email", return_value=EmailResult(success=False)):
            result = reconcile_domain_currency_notices()
        self.assertEqual(result["sent"], 0)
        quote = domain_renewal_quote(self.domain)
        self.assertEqual((quote.currency_code, quote.unit_price_cents), ("RON", 5000))

    def test_notice_waits_thirty_days_before_new_currency_document(self) -> None:
        from apps.domains.currency_terms import domain_renewal_quote, reconcile_domain_currency_notices
        from apps.domains.models import DomainCurrencyTransition

        self.switch()
        with patch("apps.notifications.services.EmailService.send_email", side_effect=self.accepted_email):
            self.assertEqual(reconcile_domain_currency_notices()["sent"], 1)
        transition = DomainCurrencyTransition.objects.get()
        now = transition.notice_sent_at
        quote = domain_renewal_quote(self.domain, prepared_at=now + timedelta(days=29, hours=23))
        self.assertEqual(quote.currency_code, "RON")
        quote = domain_renewal_quote(self.domain, prepared_at=now + timedelta(days=30))
        self.assertEqual((quote.currency_code, quote.unit_price_cents), ("EUR", 1100))

    def test_repriced_uncommitted_offer_requires_new_notice(self) -> None:
        from apps.domains.currency_terms import domain_renewal_quote, reconcile_domain_currency_notices
        from apps.domains.models import DomainCurrencyTransition

        self.switch()
        with patch("apps.notifications.services.EmailService.send_email", side_effect=self.accepted_email):
            reconcile_domain_currency_notices()
        original = DomainCurrencyTransition.objects.get()
        TLDRetailPrice.objects.filter(tld=self.tld, currency_id="EUR").update(renewal_price_cents=1300)
        quote = domain_renewal_quote(self.domain, prepared_at=original.notice_sent_at + timedelta(days=31))
        self.assertEqual(quote.currency_code, "RON")
        with patch("apps.notifications.services.EmailService.send_email", side_effect=self.accepted_email):
            reconcile_domain_currency_notices()
        self.assertEqual(DomainCurrencyTransition.objects.count(), 2)
        original.refresh_from_db()
        self.assertEqual(original.status, "superseded")

    def test_order_helper_refuses_early_currency_change_and_preserves_frozen_order_item(self) -> None:
        from apps.domains.services import DomainOrderService

        self.switch()
        eur_order = Order.objects.create(customer=self.customer, currency_id="EUR")
        ok, _error = DomainOrderService.create_domain_order_item(eur_order, self.domain.name, "renew")
        self.assertFalse(ok)
        ron_order = Order.objects.create(customer=self.customer, currency_id="RON")
        ok, item = DomainOrderService.create_domain_order_item(ron_order, self.domain.name, "renew")
        self.assertTrue(ok, item)
        self.assertEqual(item.unit_price_cents, 5000)
        TLDRetailPrice.objects.filter(tld=self.tld, currency_id="RON").update(renewal_price_cents=9999)
        item.refresh_from_db()
        self.assertEqual(item.unit_price_cents, 5000)

    def test_boolean_success_is_not_an_accepted_notice(self) -> None:
        from apps.domains.currency_terms import domain_renewal_quote, reconcile_domain_currency_notices

        self.switch()
        with patch("apps.notifications.services.EmailService.send_email", return_value=EmailResult(success=True)):
            self.assertEqual(reconcile_domain_currency_notices()["sent"], 0)
        quote = domain_renewal_quote(self.domain, prepared_at=timezone.now() + timedelta(days=60))
        self.assertEqual(quote.currency_code, "RON")

    def test_wrong_recipient_or_body_cannot_start_the_wait(self) -> None:
        from apps.domains.currency_terms import reconcile_domain_currency_notices

        self.switch()

        def wrong_email(**kwargs: Any) -> EmailResult:
            return self.accepted_email(**{**kwargs, "to": "other@example.test", "body_text": "Another offer"})

        with patch("apps.notifications.services.EmailService.send_email", side_effect=wrong_email):
            self.assertEqual(reconcile_domain_currency_notices()["sent"], 0)

    def test_unknown_historical_terms_are_held_without_relabelling(self) -> None:
        from apps.domains.currency_terms import domain_currency_switch_blockers, domain_renewal_quote

        Domain.objects.filter(pk=self.domain.pk).update(
            billing_currency=None, renewal_unit_price_cents=None, renewal_terms={},
        )
        with self.assertRaisesMessage(ValueError, "original renewal terms"):
            domain_renewal_quote(self.domain)
        self.assertTrue(domain_currency_switch_blockers("EUR"))
        self.domain.refresh_from_db()
        self.assertIsNone(self.domain.billing_currency_id)
        self.assertEqual(self.domain.last_paid_amount_cents, 0)

    def test_legacy_renewal_evidence_retains_original_currency_and_zero_price(self) -> None:
        from apps.domains.currency_terms import domain_renewal_quote

        Domain.objects.filter(pk=self.domain.pk).update(
            billing_currency=None, renewal_unit_price_cents=None, renewal_terms={},
        )
        order = Order.objects.create(customer=self.customer, currency_id="RON", status="completed")
        DomainOrderItem.objects.create(
            domain=self.domain, domain_name=self.domain.name, tld=self.tld, order=order,
            action="renew", years=1, unit_price_cents=0, total_price_cents=0,
        )
        self.switch()
        quote = domain_renewal_quote(self.domain)
        self.assertEqual((quote.currency_code, quote.unit_price_cents), ("RON", 0))
        self.domain.refresh_from_db()
        self.assertIsNone(self.domain.billing_currency_id)

    def test_registration_price_alone_cannot_prove_legacy_renewal_price(self) -> None:
        from apps.domains.currency_terms import domain_currency_switch_blockers

        Domain.objects.filter(pk=self.domain.pk).update(
            billing_currency=None, renewal_unit_price_cents=None, renewal_terms={},
        )
        order = Order.objects.create(customer=self.customer, currency_id="RON", status="completed")
        DomainOrderItem.objects.create(
            domain=self.domain, domain_name=self.domain.name, tld=self.tld, order=order,
            action="register", years=1, unit_price_cents=6000, total_price_cents=6000,
        )
        self.assertTrue(domain_currency_switch_blockers("EUR"))

    def test_early_document_keeps_current_terms_and_freezes_its_future_offer(self) -> None:
        from apps.domains.currency_terms import domain_renewal_quote, reconcile_domain_currency_notices
        from apps.domains.models import DomainCurrencyTransition
        from apps.domains.services import DomainOrderService

        self.switch()
        with patch("apps.notifications.services.EmailService.send_email", side_effect=self.accepted_email):
            reconcile_domain_currency_notices()
        transition = DomainCurrencyTransition.objects.get()
        prepared_at = transition.notice_sent_at + timedelta(days=30)
        order = Order.objects.create(customer=self.customer, currency_id="EUR")
        with patch("apps.domains.currency_terms.timezone.now", return_value=prepared_at):
            ok, item = DomainOrderService.create_domain_order_item(order, self.domain.name, "renew")
        self.assertTrue(ok, item)
        self.assertEqual(item.unit_price_cents, 1100)
        transition.refresh_from_db()
        self.assertEqual(transition.status, "committed")
        self.assertEqual(transition.effective_period_start, self.domain.expires_at)
        self.domain.refresh_from_db()
        self.assertEqual(self.domain.billing_currency_id, "RON")
        TLDRetailPrice.objects.filter(tld=self.tld, currency_id="EUR").update(renewal_price_cents=1300)
        quote = domain_renewal_quote(self.domain, prepared_at=prepared_at + timedelta(days=1))
        self.assertEqual((quote.currency_code, quote.unit_price_cents), ("EUR", 1100))
        item.refresh_from_db()
        self.assertEqual(item.total_price_cents, 1100)

    def test_new_purchase_freezes_renewal_terms_in_its_original_currency(self) -> None:
        from apps.domains.currency_terms import domain_fields_from_order_item
        from apps.domains.services import DomainOrderService

        order = Order.objects.create(customer=self.customer, currency_id="RON")
        ok, item = DomainOrderService.create_domain_order_item(order, "new-terms.com", "register")
        self.assertTrue(ok, item)
        self.switch()
        TLDRetailPrice.objects.filter(tld=self.tld, currency_id="RON").update(renewal_price_cents=9999)
        fields = domain_fields_from_order_item(item)
        self.assertEqual((fields["billing_currency_id"], fields["renewal_unit_price_cents"]), ("RON", 5000))
