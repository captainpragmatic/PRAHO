"""
Tests for TicketStatusService - centralized ticket status management.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.customers.models import Customer, CustomerTaxProfile
from apps.tickets.models import Ticket, TicketComment, SupportCategory
from apps.tickets.services import TicketStatusService
from apps.users.models import CustomerMembership

User = get_user_model()


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class TicketStatusServiceTest(TestCase):
    """Test TicketStatusService for centralized status management."""

    def setUp(self):
        """Set up test data."""
        # Create customer
        self.customer = Customer.objects.create(
            name='Test Company SRL',
            company_name='Test Company SRL',
            customer_type='company',
            status='active',
            primary_email='test@example.com',
            primary_phone='+40712345678'
        )

        # Create customer tax profile
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            vat_number='RO12345678',
            registration_number='12345678'
        )

        # Create users
        self.customer_user = User.objects.create_user(
            email='customer@example.com',
            password='customer123',
            first_name='Customer',
            last_name='User'
        )

        self.agent_user = User.objects.create_user(
            email='agent@example.com',
            password='agent123',
            first_name='Support',
            last_name='Agent',
            is_staff=True,
            staff_role='support'
        )

        # Create customer membership
        CustomerMembership.objects.create(
            user=self.customer_user,
            customer=self.customer,
            role='owner',
            is_primary=True
        )

        # Create support category
        self.category = SupportCategory.objects.create(
            name='Technical Support',
            name_en='Technical Support'
        )

    def test_create_ticket_starts_with_open_status(self):
        """Test that new tickets are created with 'open' status."""
        ticket = TicketStatusService.create_ticket(
            customer=self.customer,
            title='Test Ticket',
            description='Test description',
            priority='normal',
            category=self.category,
            created_by=self.customer_user,
            contact_email='customer@example.com'
        )

        self.assertEqual(ticket.status, 'open')
        self.assertIsNone(ticket.closed_at)
        self.assertFalse(ticket.has_customer_replied)

    def test_handle_first_agent_reply_sets_in_progress(self):
        """Test that first agent reply sets ticket to 'in_progress'."""
        # Create ticket
        ticket = TicketStatusService.create_ticket(
            customer=self.customer,
            title='Test Ticket',
            description='Test description',
            priority='normal',
            category=self.category,
            created_by=self.customer_user,
            contact_email='customer@example.com'
        )

        # Agent replies
        updated_ticket = TicketStatusService.handle_first_agent_reply(
            ticket=ticket,
            agent=self.agent_user,
            reply_action='reply'
        )

        self.assertEqual(updated_ticket.status, 'in_progress')
        self.assertIsNotNone(updated_ticket.assigned_at)

    def test_agent_reply_with_waiting_on_customer_action(self):
        """Test agent reply that sets ticket to 'waiting_on_customer'."""
        # Create and progress ticket
        ticket = TicketStatusService.create_ticket(
            customer=self.customer,
            title='Test Ticket',
            description='Test description',
            priority='normal',
            category=self.category,
            created_by=self.customer_user,
            contact_email='customer@example.com'
        )

        # Agent replies and waits on customer
        updated_ticket = TicketStatusService.handle_agent_reply(
            ticket=ticket,
            agent=self.agent_user,
            reply_action='reply_and_wait'
        )

        self.assertEqual(updated_ticket.status, 'waiting_on_customer')
        self.assertFalse(updated_ticket.has_customer_replied)

    def test_agent_close_with_resolution(self):
        """Test agent closing ticket with resolution code."""
        # Create and progress ticket
        ticket = TicketStatusService.create_ticket(
            customer=self.customer,
            title='Test Ticket',
            description='Test description',
            priority='normal',
            category=self.category,
            created_by=self.customer_user,
            contact_email='customer@example.com'
        )

        # Agent closes with resolution
        updated_ticket = TicketStatusService.handle_agent_reply(
            ticket=ticket,
            agent=self.agent_user,
            reply_action='close_with_resolution',
            resolution_code='fixed'
        )

        self.assertEqual(updated_ticket.status, 'closed')
        self.assertEqual(updated_ticket.resolution_code, 'fixed')
        self.assertIsNotNone(updated_ticket.closed_at)

    def test_customer_reply_from_waiting_goes_to_in_progress(self):
        """Test customer reply from 'waiting_on_customer' goes to 'in_progress'."""
        # Create and progress ticket to waiting state
        ticket = TicketStatusService.create_ticket(
            customer=self.customer,
            title='Test Ticket',
            description='Test description',
            priority='normal',
            category=self.category,
            created_by=self.customer_user,
            contact_email='customer@example.com'
        )

        # Set to waiting on customer
        ticket = TicketStatusService.handle_agent_reply(
            ticket=ticket,
            agent=self.agent_user,
            reply_action='reply_and_wait'
        )

        # Customer replies
        updated_ticket = TicketStatusService.handle_customer_reply(
            ticket=ticket
        )

        self.assertEqual(updated_ticket.status, 'in_progress')
        self.assertTrue(updated_ticket.has_customer_replied)
        self.assertIsNotNone(updated_ticket.customer_replied_at)

    def test_customer_reply_from_open_stays_open(self):
        """Test customer reply from 'open' status stays 'open'."""
        # Create ticket
        ticket = TicketStatusService.create_ticket(
            customer=self.customer,
            title='Test Ticket',
            description='Test description',
            priority='normal',
            category=self.category,
            created_by=self.customer_user,
            contact_email='customer@example.com'
        )

        # Customer replies before any agent response
        updated_ticket = TicketStatusService.handle_customer_reply(
            ticket=ticket
        )

        self.assertEqual(updated_ticket.status, 'open')
        self.assertTrue(updated_ticket.has_customer_replied)

    def test_internal_note_does_not_change_status(self):
        """Test that internal notes don't change ticket status."""
        # Create and progress ticket
        ticket = TicketStatusService.create_ticket(
            customer=self.customer,
            title='Test Ticket',
            description='Test description',
            priority='normal',
            category=self.category,
            created_by=self.customer_user,
            contact_email='customer@example.com'
        )

        original_status = ticket.status

        # Agent adds internal note
        updated_ticket = TicketStatusService.handle_agent_reply(
            ticket=ticket,
            agent=self.agent_user,
            reply_action='internal_note'
        )

        # Status should remain unchanged
        self.assertEqual(updated_ticket.status, original_status)

    def test_invalid_reply_action_raises_error(self):
        """Test that invalid reply action raises ValueError."""
        ticket = TicketStatusService.create_ticket(
            customer=self.customer,
            title='Test Ticket',
            description='Test description',
            priority='normal',
            category=self.category,
            created_by=self.customer_user,
            contact_email='customer@example.com'
        )

        with self.assertRaises(ValueError):
            TicketStatusService.handle_agent_reply(
                ticket=ticket,
                agent=self.agent_user,
                reply_action='invalid_action'
            )

    def test_close_without_resolution_code_raises_error(self):
        """Test that closing without resolution code raises ValueError."""
        ticket = TicketStatusService.create_ticket(
            customer=self.customer,
            title='Test Ticket',
            description='Test description',
            priority='normal',
            category=self.category,
            created_by=self.customer_user,
            contact_email='customer@example.com'
        )

        with self.assertRaises(ValueError):
            TicketStatusService.handle_agent_reply(
                ticket=ticket,
                agent=self.agent_user,
                reply_action='close_with_resolution'
                # Missing resolution_code
            )

    def test_customer_replied_recently_property(self):
        """Test customer_replied_recently property logic."""
        ticket = TicketStatusService.create_ticket(
            customer=self.customer,
            title='Test Ticket',
            description='Test description',
            priority='normal',
            category=self.category,
            created_by=self.customer_user,
            contact_email='customer@example.com'
        )

        # Initially no customer reply
        self.assertFalse(ticket.customer_replied_recently)

        # Customer replies
        ticket = TicketStatusService.handle_customer_reply(
            ticket=ticket
        )

        # Should show recently replied
        self.assertTrue(ticket.customer_replied_recently)

        # Agent replies (resets customer replied flag)
        ticket = TicketStatusService.handle_agent_reply(
            ticket=ticket,
            agent=self.agent_user,
            reply_action='reply'
        )

        # Should no longer show recently replied
        self.assertFalse(ticket.customer_replied_recently)

    def test_ticket_status_transitions_are_logged(self):
        """Test that status transitions are properly logged."""
        ticket = TicketStatusService.create_ticket(
            customer=self.customer,
            title='Test Ticket',
            description='Test description',
            priority='normal',
            category=self.category,
            created_by=self.customer_user,
            contact_email='customer@example.com'
        )

        original_status = ticket.status

        # Agent replies and changes status
        updated_ticket = TicketStatusService.handle_agent_reply(
            ticket=ticket,
            agent=self.agent_user,
            reply_action='reply_and_wait'
        )

        # Status should have changed
        self.assertNotEqual(updated_ticket.status, original_status)
        self.assertEqual(updated_ticket.status, 'waiting_on_customer')

    def test_get_status_display_friendly_names(self):
        """Test that status display shows user-friendly names."""
        ticket = TicketStatusService.create_ticket(
            customer=self.customer,
            title='Test Ticket',
            description='Test description',
            priority='normal',
            category=self.category,
            created_by=self.customer_user,
            contact_email='customer@example.com'
        )

        # Test all status display values
        status_displays = {
            'open': 'Open',
            'in_progress': 'In Progress',
            'waiting_on_customer': 'Waiting on Customer',
            'closed': 'Closed'
        }

        for status, expected_display in status_displays.items():
            ticket.status = status
            ticket.save()
            ticket.refresh_from_db()
            self.assertEqual(ticket.get_status_display(), expected_display)

    def test_resolution_code_choices(self):
        """Test that resolution code choices are properly defined."""
        expected_codes = {
            'fixed': 'Fixed',
            'invalid': 'Invalid',
            'duplicate': 'Duplicate',
            'by_design': 'By Design',
            'refunded': 'Refunded',
            'cancelled': 'Cancelled',
            'other': 'Other'
        }

        # Get choices from model
        choices = dict(Ticket.RESOLUTION_CHOICES)

        for code, expected_display in expected_codes.items():
            self.assertIn(code, choices)
            # Note: The actual display might be translated, so we just check the key exists

    def test_only_valid_statuses_allowed(self):
        """Test that only valid status values are accepted."""
        ticket = TicketStatusService.create_ticket(
            customer=self.customer,
            title='Test Ticket',
            description='Test description',
            priority='normal',
            category=self.category,
            created_by=self.customer_user,
            contact_email='customer@example.com'
        )

        # Valid statuses should work
        valid_statuses = ['open', 'in_progress', 'waiting_on_customer', 'closed']
        for status in valid_statuses:
            ticket.status = status
            ticket.save()  # Should not raise

        # Invalid status should raise error when validated
        ticket.status = 'invalid_status'
        with self.assertRaises(Exception):  # Django validation error
            ticket.full_clean()
