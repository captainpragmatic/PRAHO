"""The additive domain schema leaves original financial records untouched."""

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

from apps.domains.currency_terms import original_domain_terms
from apps.domains.models import Domain, DomainOrderItem


class DomainCurrencyMigrationTests(TransactionTestCase):
    def test_upgrade_keeps_historical_amounts_and_resolves_only_recorded_order_currency(self):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        self.addCleanup(lambda: MigrationExecutor(connection).migrate(latest))
        previous = [("domains", "0010_currency_specific_retail_prices")]
        executor.migrate(previous)
        historical = executor.loader.project_state(previous).apps
        currency = historical.get_model("billing", "Currency").objects.create(code="USD", symbol="$")
        customer = historical.get_model("customers", "Customer").objects.create(
            name="Historical domain owner", primary_email="historical@example.test",
        )
        tld = historical.get_model("domains", "TLD").objects.create(
            extension="migration", registration_price_cents=6000, renewal_price_cents=5000, transfer_price_cents=4500,
        )
        registrar = historical.get_model("domains", "Registrar").objects.create(name="migration-registrar")
        domain = historical.get_model("domains", "Domain").objects.create(
            name="original.migration", customer=customer, tld=tld, registrar=registrar,
            last_paid_amount_cents=12345,
        )
        order = historical.get_model("orders", "Order").objects.create(
            customer=customer, currency=currency, status="completed", total_cents=24690,
        )
        item = historical.get_model("domains", "DomainOrderItem").objects.create(
            domain=domain, order=order, domain_name=domain.name, tld=tld, action="renew", years=2,
            unit_price_cents=12345, total_price_cents=24690,
        )

        MigrationExecutor(connection).migrate(latest)
        upgraded = Domain.objects.get(pk=domain.pk)
        original_item = DomainOrderItem.objects.select_related("order").get(pk=item.pk)
        self.assertIsNone(upgraded.billing_currency_id)
        self.assertIsNone(upgraded.renewal_unit_price_cents)
        self.assertEqual(upgraded.renewal_terms, {})
        self.assertEqual(upgraded.last_paid_amount_cents, 12345)
        self.assertEqual((original_item.order.currency_id, original_item.unit_price_cents, original_item.total_price_cents),
                         ("USD", 12345, 24690))
        evidence = original_domain_terms(upgraded)
        self.assertEqual((evidence["currency"], evidence["unit_price_cents"]), ("USD", 12345))
        upgraded.refresh_from_db()
        self.assertIsNone(upgraded.billing_currency_id)
