"""Domain follow-up logging must not undo writes after an isolated audit failure."""

from django.test import override_settings

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, DomainOrderItem, Registrar
from apps.orders.models import Order
from tests.common._deferred_audit_reads import DeferredAuditReadTestCase


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class DeferredDomainPayloadTests(DeferredAuditReadTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.customer = Customer.objects.create(name="Deferred", primary_email="deferred-domain@example.com")
        self.tld = TLD.objects.create(
            extension="test", registration_price_cents=1000, renewal_price_cents=1000, transfer_price_cents=1000
        )
        self.registrar = Registrar.objects.create(
            name="deferred", display_name="Before", api_endpoint="https://registrar.example.com"
        )

    def test_registrar_update_commits_when_deferred_display_name_fetch_fails(self) -> None:
        registrar = Registrar.objects.defer("name").get(pk=self.registrar.pk)
        registrar.display_name = "Persisted"
        self.run_deferred_read(registrar, lambda: registrar.save(update_fields=["display_name"]))
        self.assertEqual(Registrar.objects.get(pk=registrar.pk).display_name, "Persisted")

    def test_order_item_update_commits_when_deferred_domain_name_fetch_fails(self) -> None:
        order = Order.objects.create(customer=self.customer, currency=self.currency)
        item = DomainOrderItem.objects.create(
            order=order,
            tld=self.tld,
            domain_name="deferred.test",
            action="register",
            unit_price_cents=1000,
            total_price_cents=1000,
        )
        item = DomainOrderItem.objects.defer("domain_name").get(pk=item.pk)
        item.auto_renew = False
        self.run_deferred_read(item, lambda: item.save(update_fields=["auto_renew"]))
        self.assertFalse(DomainOrderItem.objects.get(pk=item.pk).auto_renew)

    def test_domain_deletion_commits_when_deferred_domain_name_fetch_fails(self) -> None:
        domain = Domain.objects.create(
            customer=self.customer, tld=self.tld, registrar=self.registrar, name="delete.test"
        )
        domain = Domain.objects.defer("name").get(pk=domain.pk)
        domain_id = domain.pk
        self.run_deferred_read(domain, domain.delete)
        self.assertFalse(Domain.objects.filter(pk=domain_id).exists())
