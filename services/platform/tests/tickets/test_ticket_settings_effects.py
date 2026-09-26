"""`tickets.auto_close_inactive_hours` — the setting that closes a customer's ticket.

`test_ticket_tasks.py` covers the worker's logic thoroughly, but it does so by patching
`SettingsService.get_integer_setting` to return the number it wants. That proves the task behaves
correctly given a value; it cannot prove the value an operator stores ever reaches the task, and the
patch is applied at `apps.settings.services`, so every settings read in the call path returns the same
number. If the key string in `tasks.py` were changed, or the read replaced by a constant, those tests
would stay green.

Nothing is mocked here except the outbound notification. The setting is written, a stale ticket is
seeded, the worker runs, and the ticket's status is what gets asserted - because closing a customer's
open ticket early is the consequence that matters, and the default of 0 exists precisely so the
behaviour is off until someone chooses it.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.customers.models import Customer
from apps.settings.services import SettingsService
from apps.tickets.models import SupportCategory, Ticket
from apps.tickets.services import TicketStatusService
from apps.tickets.tasks import auto_close_inactive_tickets
from apps.users.models import User

AUTO_CLOSE_KEY = "tickets.auto_close_inactive_hours"


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class AutoCloseSettingEffectTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.customer = Customer.objects.create(
            name="Effect Co SRL",
            company_name="Effect Co SRL",
            customer_type="company",
            status="active",
            primary_email="effect-customer@example.test",
            primary_phone="+40712345678",
        )
        self.customer_user = User.objects.create_user(email="effect-customer@example.test", password="customer123")
        self.agent = User.objects.create_user(
            email="effect-agent@example.test", password="agent123", is_staff=True, staff_role="support"
        )
        self.category = SupportCategory.objects.create(name="Support", name_en="Support")

    def set_hours(self, hours: int) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(AUTO_CLOSE_KEY, hours)
        self.assertTrue(result.is_ok(), result)

    def waiting_ticket(self, title: str, *, updated_at: datetime) -> Ticket:
        ticket = TicketStatusService.handle_agent_reply(
            ticket=TicketStatusService.create_ticket(
                customer=self.customer,
                title=title,
                description="Test description",
                priority="normal",
                category=self.category,
                created_by=self.customer_user,
                contact_email=self.customer.primary_email,
            ),
            agent=self.agent,
            reply_action="reply_and_wait",
        )
        Ticket.objects.filter(pk=ticket.pk).update(updated_at=updated_at)
        ticket.refresh_from_db()
        return ticket

    @patch("apps.tickets.tasks.NotificationService.send_customer_notification", return_value=True)
    def test_the_stored_policy_decides_which_tickets_close(self, _notify) -> None:
        """One setting, two tickets either side of the window it defines."""
        self.set_hours(48)
        stale = self.waiting_ticket("Stale", updated_at=timezone.now() - timedelta(hours=72))
        fresh = self.waiting_ticket("Fresh", updated_at=timezone.now() - timedelta(hours=24))

        result = auto_close_inactive_tickets()

        stale.refresh_from_db()
        fresh.refresh_from_db()
        self.assertEqual(stale.status, "closed")
        self.assertEqual(fresh.status, "waiting_on_customer")
        self.assertEqual(result["closed"], 1)

    @patch("apps.tickets.tasks.NotificationService.send_customer_notification", return_value=True)
    def test_a_longer_window_spares_the_same_ticket(self, _notify) -> None:
        """The discriminator: identical ticket, only the setting differs, opposite outcome."""
        self.set_hours(96)
        ticket = self.waiting_ticket("Borderline", updated_at=timezone.now() - timedelta(hours=72))

        auto_close_inactive_tickets()

        ticket.refresh_from_db()
        self.assertEqual(ticket.status, "waiting_on_customer")

        self.set_hours(48)
        auto_close_inactive_tickets()

        ticket.refresh_from_db()
        self.assertEqual(ticket.status, "closed")

    def test_the_catalog_default_of_zero_leaves_every_ticket_open(self) -> None:
        """Shipping this on by accident would close live tickets, so the default has to be inert."""
        self.assertEqual(SettingsService.DEFAULT_SETTINGS[AUTO_CLOSE_KEY], 0)
        stale = self.waiting_ticket("Stale", updated_at=timezone.now() - timedelta(days=90))

        result = auto_close_inactive_tickets()

        stale.refresh_from_db()
        self.assertEqual(stale.status, "waiting_on_customer")
        self.assertTrue(result["disabled"])

    def test_storing_zero_explicitly_also_disables_it(self) -> None:
        """`0` is a legitimate stored value, not an absent one, and the guard is `<= 0`."""
        self.set_hours(0)
        stale = self.waiting_ticket("Stale", updated_at=timezone.now() - timedelta(days=90))

        result = auto_close_inactive_tickets()

        stale.refresh_from_db()
        self.assertEqual(stale.status, "waiting_on_customer")
        self.assertTrue(result["disabled"])
