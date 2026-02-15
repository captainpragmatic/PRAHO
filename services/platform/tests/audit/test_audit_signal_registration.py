"""
Signal registration verification tests.

Verifies that signal receivers are actually connected at runtime for each
critical app. This catches the class of bug where `AppConfig.ready()` fails
to import signals (e.g., empty `ready()` methods).
"""

from __future__ import annotations

from collections.abc import Iterable

from django.db.models.signals import post_delete, post_save, pre_delete, pre_save
from django.test import SimpleTestCase

AUDIT_SIGNALS = (post_save, pre_save, post_delete, pre_delete)


def _has_receiver_from_module(model: type, module_prefix: str) -> bool:
    """Return True if a live receiver from module_prefix is connected for model."""
    for sig in AUDIT_SIGNALS:
        raw_receivers = sig._live_receivers(model)

        # Django 5.x may return (sync_receivers, async_receivers).
        if isinstance(raw_receivers, tuple):
            receiver_groups: Iterable[Iterable[object]] = raw_receivers
        else:
            receiver_groups = (raw_receivers,)

        for group in receiver_groups:
            for receiver in group:
                receiver_module = getattr(receiver, "__module__", "")
                if receiver_module.startswith(module_prefix):
                    return True
    return False


# ---------------------------------------------------------------------------
# Billing
# ---------------------------------------------------------------------------


class TestBillingSignalRegistration(SimpleTestCase):
    """Billing models must have signal receivers connected."""

    def test_invoice_has_signal_receivers(self) -> None:
        from apps.billing.models import Invoice

        self.assertTrue(
            _has_receiver_from_module(Invoice, "apps.billing.signals"),
            "Invoice has no billing signal receivers",
        )

    def test_payment_has_signal_receivers(self) -> None:
        from apps.billing.models import Payment

        self.assertTrue(
            _has_receiver_from_module(Payment, "apps.billing.signals"),
            "Payment has no billing signal receivers",
        )

    def test_proforma_invoice_has_signal_receivers(self) -> None:
        from apps.billing.models import ProformaInvoice

        self.assertTrue(
            _has_receiver_from_module(ProformaInvoice, "apps.billing.signals"),
            "ProformaInvoice has no billing signal receivers",
        )


# ---------------------------------------------------------------------------
# Orders
# ---------------------------------------------------------------------------


class TestOrdersSignalRegistration(SimpleTestCase):
    """Order models must have signal receivers connected."""

    def test_order_has_signal_receivers(self) -> None:
        from apps.orders.models import Order

        self.assertTrue(
            _has_receiver_from_module(Order, "apps.orders.signals"),
            "Order has no orders signal receivers",
        )

    def test_order_item_has_signal_receivers(self) -> None:
        from apps.orders.models import OrderItem

        self.assertTrue(
            _has_receiver_from_module(OrderItem, "apps.orders.signals"),
            "OrderItem has no orders signal receivers",
        )


# ---------------------------------------------------------------------------
# Customers
# ---------------------------------------------------------------------------


class TestCustomersSignalRegistration(SimpleTestCase):
    """Customer models must have signal receivers connected."""

    def test_customer_has_signal_receivers(self) -> None:
        from apps.customers.models import Customer

        self.assertTrue(
            _has_receiver_from_module(Customer, "apps.customers.signals"),
            "Customer has no customers signal receivers",
        )


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------


class TestDomainsSignalRegistration(SimpleTestCase):
    """Domain models must have signal receivers connected."""

    def test_domain_has_signal_receivers(self) -> None:
        from apps.domains.models import Domain

        self.assertTrue(
            _has_receiver_from_module(Domain, "apps.domains.signals"),
            "Domain has no domains signal receivers",
        )


# ---------------------------------------------------------------------------
# Products
# ---------------------------------------------------------------------------


class TestProductsSignalRegistration(SimpleTestCase):
    """Product models must have signal receivers connected."""

    def test_product_has_signal_receivers(self) -> None:
        from apps.products.models import Product

        self.assertTrue(
            _has_receiver_from_module(Product, "apps.products.signals"),
            "Product has no products signal receivers",
        )


# ---------------------------------------------------------------------------
# Tickets
# ---------------------------------------------------------------------------


class TestTicketsSignalRegistration(SimpleTestCase):
    """Ticket models must have signal receivers connected."""

    def test_ticket_has_signal_receivers(self) -> None:
        from apps.tickets.models import Ticket

        self.assertTrue(
            _has_receiver_from_module(Ticket, "apps.tickets.signals"),
            "Ticket has no tickets signal receivers",
        )


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


class TestNotificationsSignalRegistration(SimpleTestCase):
    """Notification models must have signal receivers connected."""

    def test_email_template_has_signal_receivers(self) -> None:
        from apps.notifications.models import EmailTemplate

        self.assertTrue(
            _has_receiver_from_module(EmailTemplate, "apps.notifications.signals"),
            "EmailTemplate has no notifications signal receivers",
        )

    def test_email_suppression_has_signal_receivers(self) -> None:
        from apps.notifications.models import EmailSuppression

        self.assertTrue(
            _has_receiver_from_module(EmailSuppression, "apps.notifications.signals"),
            "EmailSuppression has no notifications signal receivers",
        )

    def test_email_preference_has_signal_receivers(self) -> None:
        from apps.notifications.models import EmailPreference

        self.assertTrue(
            _has_receiver_from_module(EmailPreference, "apps.notifications.signals"),
            "EmailPreference has no notifications signal receivers",
        )


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class TestSettingsSignalRegistration(SimpleTestCase):
    """SystemSetting must have signal receivers connected."""

    def test_system_setting_has_signal_receivers(self) -> None:
        from apps.settings.models import SystemSetting

        self.assertTrue(
            _has_receiver_from_module(SystemSetting, "apps.settings.signals"),
            "SystemSetting has no settings signal receivers",
        )
