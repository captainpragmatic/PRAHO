"""Accounts created before Virtualmin 8 keep a template name Virtualmin 8 does not have.

Migration 0003 changed only the field default to "Default Settings", the name Virtualmin 8 gives
its built-in template. Rows written earlier kept "Default", so reprovisioning or recovering them
would ask Virtualmin 8 for a template that does not exist. Migration 0004 renames that legacy
default and leaves custom template names alone.
"""

from __future__ import annotations

import importlib
from decimal import Decimal

from django.apps import apps as global_apps
from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.provisioning.virtualmin_validators import DEFAULT_VIRTUALMIN_TEMPLATE

migration = importlib.import_module("apps.provisioning.migrations.0004_virtualmin_legacy_template_name")


class LegacyTemplateNameMigrationTests(TestCase):
    def setUp(self) -> None:
        customer = Customer.objects.create(name="Legacy", customer_type="individual", primary_email="l@example.com")
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        plan = ServicePlan.objects.create(name="Legacy plan", plan_type="shared_hosting", price_monthly=Decimal("10"))
        self.server = VirtualminServer.objects.create(name="legacy-node", hostname="legacy.example.com")
        self.services = [
            Service.objects.create(
                customer=customer,
                currency=currency,
                service_plan=plan,
                service_name=f"site{index}.example.com",
                domain=f"site{index}.example.com",
                username=f"legacyuser{index}",
                billing_cycle="monthly",
                price=Decimal("10"),
                status="active",
            )
            for index in range(2)
        ]

    def _account(self, index: int, template: str) -> VirtualminAccount:
        return VirtualminAccount.objects.create(
            domain=self.services[index].domain,
            service=self.services[index],
            server=self.server,
            virtualmin_username=f"legacy{index}",
            template_name=template,
        )

    def test_the_legacy_default_becomes_the_virtualmin_8_name_and_custom_names_stay(self) -> None:
        legacy, custom = self._account(0, "Default"), self._account(1, "Reseller Gold")

        migration.rename_legacy_default_template(global_apps, None)

        legacy.refresh_from_db()
        custom.refresh_from_db()
        self.assertEqual(legacy.template_name, DEFAULT_VIRTUALMIN_TEMPLATE)
        self.assertEqual(custom.template_name, "Reseller Gold")
