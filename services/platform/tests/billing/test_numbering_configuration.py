"""Number allocation must consume configured families only."""

from datetime import timedelta
from importlib import import_module
from types import SimpleNamespace

from django.apps import apps
from django.core.exceptions import ImproperlyConfigured
from django.db import connection
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import InvoiceSequence
from apps.billing.numbering_service import InvoiceNumberingService
from apps.billing.subscription_models import Subscription
from apps.products.models import Product
from tests.billing import _fiscal_correction_helpers as fiscal


class NumberingConfigurationTests(TestCase):
    def seed(self) -> None:
        migration = import_module("apps.billing.migrations.0015_seed_invoice_families")
        migration.seed_invoice_families(apps, SimpleNamespace(connection=connection))

    def test_seed_creates_only_missing_families_without_resetting_existing_series(self) -> None:
        InvoiceSequence.objects.all().delete()
        current = InvoiceSequence.objects.create(scope="default", prefix="CURRENT", last_value=27)
        archived = InvoiceSequence.objects.create(scope="archived:OLD", prefix="OLD", last_value=100)
        self.seed()
        identities = dict(InvoiceSequence.objects.values_list("scope", "pk"))
        self.seed()
        current.refresh_from_db()
        archived.refresh_from_db()
        self.assertEqual((current.prefix, current.last_value), ("CURRENT", 27))
        self.assertEqual(archived.last_value, 100)
        self.assertEqual(InvoiceSequence.objects.get(scope="subscription").prefix, "SUB")
        self.assertEqual(dict(InvoiceSequence.objects.values_list("scope", "pk")), identities)

    def test_seed_refuses_zero_counter_when_issued_history_exists(self) -> None:
        InvoiceSequence.objects.get_or_create(scope="default")
        fiscal.issued_invoice(fiscal.customer())
        InvoiceSequence.objects.filter(scope="default").delete()
        with self.assertRaisesMessage(ValueError, "issued numbers exist"):
            self.seed()
        self.assertFalse(InvoiceSequence.objects.filter(scope="default").exists())

    def test_unknown_scope_cannot_create_or_consume_a_sequence(self) -> None:
        before = list(InvoiceSequence.objects.values())
        with self.assertRaises(ValueError):
            InvoiceNumberingService.get_next_number(scope="subcription")
        self.assertEqual(list(InvoiceSequence.objects.values()), before)

    def test_seed_refuses_zero_counter_when_subscription_numbers_exist(self) -> None:
        now = timezone.now()
        Subscription.objects.create(
            customer=fiscal.customer(),
            product=Product.objects.create(name="Historical subscription", slug="historical-subscription"),
            currency=fiscal.ron(),
            subscription_number="SUB-000017",
            unit_price_cents=1000,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )
        InvoiceSequence.objects.filter(scope="subscription").delete()
        with self.assertRaisesMessage(ValueError, "issued numbers exist"):
            self.seed()
        self.assertFalse(InvoiceSequence.objects.filter(scope="subscription").exists())

    def test_missing_known_family_is_a_configuration_error(self) -> None:
        InvoiceSequence.objects.filter(scope="subscription").delete()
        with self.assertRaises(ImproperlyConfigured):
            InvoiceNumberingService.get_next_number(scope="subscription")
        self.assertFalse(InvoiceSequence.objects.filter(scope="subscription").exists())

    def test_existing_rotated_prefix_and_counter_are_preserved(self) -> None:
        sequence, _ = InvoiceSequence.objects.update_or_create(
            scope="default",
            defaults={"prefix": "CURRENT", "last_value": 27},
        )
        self.assertEqual(InvoiceNumberingService.get_next_number(), "CURRENT-000028")
        sequence.refresh_from_db()
        self.assertEqual(sequence.last_value, 28)
