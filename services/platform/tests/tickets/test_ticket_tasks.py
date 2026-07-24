"""Regression tests for scheduled ticket-lifecycle policies."""

from datetime import datetime, timedelta
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from django_q.models import Schedule

from apps.customers.models import Customer
from apps.notifications.models import EmailTemplate
from apps.tickets.models import SupportCategory, Ticket
from apps.tickets.services import TicketStatusService
from apps.tickets.tasks import auto_close_inactive_tickets, setup_ticket_scheduled_tasks
from apps.users.models import User


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class AutoCloseInactiveTicketsTests(TestCase):
    """Inactive closure applies only to tickets waiting on the customer."""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Test Company SRL",
            company_name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="customer@example.com",
            primary_phone="+40712345678",
        )
        self.customer_user = User.objects.create_user(
            email="customer@example.com",
            password="customer123",
            first_name="Customer",
            last_name="User",
        )
        self.agent = User.objects.create_user(
            email="agent@example.com",
            password="agent123",
            first_name="Support",
            last_name="Agent",
            is_staff=True,
            staff_role="support",
        )
        self.category = SupportCategory.objects.create(name="Support", name_en="Support")

    def _ticket(self, title: str) -> Ticket:
        return TicketStatusService.create_ticket(
            customer=self.customer,
            title=title,
            description="Test description",
            priority="normal",
            category=self.category,
            created_by=self.customer_user,
            contact_email=self.customer.primary_email,
        )

    def _waiting_ticket(self, title: str, *, updated_at: datetime) -> Ticket:
        ticket = TicketStatusService.handle_agent_reply(
            ticket=self._ticket(title),
            agent=self.agent,
            reply_action="reply_and_wait",
        )
        Ticket.objects.filter(pk=ticket.pk).update(updated_at=updated_at)
        ticket.refresh_from_db()
        return ticket

    @patch("apps.settings.services.SettingsService.get_integer_setting", return_value=0)
    def test_disabled_policy_is_a_noop(self, get_setting) -> None:
        stale = self._waiting_ticket("Stale", updated_at=timezone.now() - timedelta(days=30))

        result = auto_close_inactive_tickets()

        stale.refresh_from_db()
        self.assertEqual(stale.status, "waiting_on_customer")
        self.assertEqual(result, {"eligible": 0, "closed": 0, "notification_failures": 0, "disabled": True})
        get_setting.assert_called_once_with("tickets.auto_close_inactive_hours", 0)

    @patch("apps.tickets.tasks.NotificationService.send_customer_notification", return_value=True)
    @patch("apps.settings.services.SettingsService.get_integer_setting", return_value=72)
    def test_closes_only_stale_waiting_tickets(self, _get_setting, send_notification) -> None:
        now = timezone.now()
        stale = self._waiting_ticket("Stale", updated_at=now - timedelta(hours=73))
        boundary = self._waiting_ticket("Boundary", updated_at=now - timedelta(hours=72))
        fresh = self._waiting_ticket("Fresh", updated_at=now - timedelta(hours=71))
        open_ticket = self._ticket("Open")
        Ticket.objects.filter(pk=open_ticket.pk).update(updated_at=now - timedelta(days=30))

        result = auto_close_inactive_tickets(now=now)

        for ticket in (stale, boundary, fresh, open_ticket):
            ticket.refresh_from_db()
        self.assertEqual(stale.status, "closed")
        self.assertEqual(boundary.status, "closed")
        self.assertEqual(fresh.status, "waiting_on_customer")
        self.assertEqual(open_ticket.status, "open")
        self.assertEqual(stale.resolution_code, "auto_closed")
        self.assertEqual(boundary.resolution_code, "auto_closed")
        self.assertEqual(result, {"eligible": 2, "closed": 2, "notification_failures": 0, "disabled": False})
        self.assertEqual(send_notification.call_count, 2)

    @patch("apps.tickets.tasks.NotificationService.send_customer_notification", return_value=True)
    @patch("apps.settings.services.SettingsService.get_integer_setting", return_value=24)
    def test_closure_resets_reply_state_and_notifies_customer(self, _get_setting, send_notification) -> None:
        now = timezone.now()
        ticket = self._waiting_ticket("Waiting for reply", updated_at=now - timedelta(hours=25))
        Ticket.objects.filter(pk=ticket.pk).update(
            has_customer_replied=True,
            customer_replied_at=now - timedelta(hours=25),
        )

        result = auto_close_inactive_tickets(now=now)

        ticket.refresh_from_db()
        self.assertFalse(ticket.has_customer_replied)
        self.assertIsNone(ticket.customer_replied_at)
        self.assertIsNotNone(ticket.closed_at)
        self.assertEqual(result["notification_failures"], 0)
        send_notification.assert_called_once_with(
            customer_id=str(self.customer.pk),
            notification_type="ticket_auto_closed",
            context={
                "customer_name": self.customer.get_display_name(),
                "ticket_number": ticket.ticket_number,
                "ticket_subject": ticket.title,
                "inactive_hours": 24,
            },
        )

    @patch("apps.tickets.tasks.NotificationService.send_customer_notification", return_value=False)
    @patch("apps.settings.services.SettingsService.get_integer_setting", return_value=24)
    def test_notification_failure_does_not_reopen_closed_ticket(self, _get_setting, _send_notification) -> None:
        ticket = self._waiting_ticket("Stale", updated_at=timezone.now() - timedelta(hours=25))

        result = auto_close_inactive_tickets()

        ticket.refresh_from_db()
        self.assertEqual(ticket.status, "closed")
        self.assertEqual(result["closed"], 1)
        self.assertEqual(result["notification_failures"], 1)

    @patch("apps.tickets.tasks.NotificationService.send_customer_notification", return_value=True)
    @patch("apps.settings.services.SettingsService.get_integer_setting", return_value=24)
    def test_rechecks_candidate_after_lock_before_closing(self, _get_setting, send_notification) -> None:
        """A reply/update racing the candidate query must keep the ticket open."""
        now = timezone.now()
        ticket = self._waiting_ticket("Racing update", updated_at=now - timedelta(hours=25))
        original_select_for_update = Ticket.objects.select_for_update

        def refresh_candidate_before_lock(*args, **kwargs):
            Ticket.objects.filter(pk=ticket.pk).update(updated_at=now)
            return original_select_for_update(*args, **kwargs)

        with patch.object(Ticket.objects, "select_for_update", side_effect=refresh_candidate_before_lock):
            result = auto_close_inactive_tickets(now=now)

        ticket.refresh_from_db()
        self.assertEqual(ticket.status, "waiting_on_customer")
        self.assertEqual(result, {"eligible": 1, "closed": 0, "notification_failures": 0, "disabled": False})
        send_notification.assert_not_called()


class TicketScheduleTests(TestCase):
    """The global scheduler setup must register the inactive-ticket worker."""

    def test_ticket_schedule_registration_is_idempotent(self) -> None:
        first = setup_ticket_scheduled_tasks()
        second = setup_ticket_scheduled_tasks()

        schedule = Schedule.objects.get(name="tickets-auto-close-inactive")
        self.assertEqual(schedule.func, "apps.tickets.tasks.auto_close_inactive_tickets")
        self.assertEqual(schedule.schedule_type, Schedule.HOURLY)
        self.assertEqual(first, {"auto_close_inactive": "created"})
        self.assertEqual(second, {"auto_close_inactive": "already_exists"})
        self.assertEqual(Schedule.objects.filter(name="tickets-auto-close-inactive").count(), 1)

    @patch(
        "apps.common.management.commands.setup_scheduled_tasks.setup_ticket_scheduled_tasks",
        return_value={"auto_close_inactive": "created"},
    )
    def test_global_setup_command_includes_ticket_tasks(self, setup_tickets) -> None:
        call_command("setup_scheduled_tasks", "--tickets-only")

        setup_tickets.assert_called_once_with()

    def test_auto_close_email_template_is_seeded_in_both_locales(self) -> None:
        call_command("setup_email_templates")

        locales = set(
            EmailTemplate.objects.filter(key="ticket_auto_closed").values_list("locale", flat=True)
        )
        self.assertEqual(locales, {"en", "ro"})
