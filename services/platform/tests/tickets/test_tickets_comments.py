"""
Test ticket internal comments security and visibility
"""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from apps.customers.models import Customer, CustomerTaxProfile
from apps.tickets.models import Ticket, TicketComment
from apps.users.models import CustomerMembership

User = get_user_model()


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class TicketInternalCommentsSecurityTest(TestCase):
    """Test security of internal comments visibility"""

    def setUp(self):
        """Set up test data"""
        # Create staff user (admin)
        self.staff_user = User.objects.create_user(
            email='admin@example.com',
            password='testpass123'
        )
        self.staff_user.first_name = 'Admin'
        self.staff_user.last_name = 'User'
        self.staff_user.is_staff = True
        self.staff_user.staff_role = 'admin'
        self.staff_user.save()

        # Create support staff user
        self.support_user = User.objects.create_user(
            email='support@example.com',
            password='testpass123'
        )
        self.support_user.first_name = 'Support'
        self.support_user.last_name = 'Agent'
        self.support_user.is_staff = True
        self.support_user.staff_role = 'support'
        self.support_user.save()

        # Create a support agent WITHOUT the Django is_staff flag (staff_role only).
        # This is the discriminating fixture for the is_staff_user migration: the
        # support_user above sets is_staff=True, so it cannot detect a regression
        # from is_staff_user back to is_staff.
        self.support_no_django_staff = User.objects.create_user(
            email='support-no-flag@example.com',
            password='testpass123'
        )
        self.support_no_django_staff.is_staff = False
        self.support_no_django_staff.staff_role = 'support'
        self.support_no_django_staff.save()

        # Create customer user (non-staff)
        self.customer_user = User.objects.create_user(
            email='customer@example.com',
            password='testpass123'
        )
        self.customer_user.first_name = 'Customer'
        self.customer_user.last_name = 'User'
        self.customer_user.save()

        # Create test customer organization
        self.customer = Customer.objects.create(
            name='Test Company SRL',
            company_name='Test Company SRL',
            customer_type='company',
            status='active',
            primary_email='customer@example.com',
            primary_phone='+40712345678'
        )

        # Create customer tax profile
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            vat_number='RO12345678',
            registration_number='12345678'
        )

        # Create customer membership for customer user
        CustomerMembership.objects.create(
            user=self.customer_user,
            customer=self.customer,
            role='owner',
            is_primary=True
        )

        # Create test ticket
        self.ticket = Ticket.objects.create(
            customer=self.customer,
            title='Test Support Ticket',
            description='Test ticket description',
            priority='normal',
            status='open',
            created_by=self.customer_user
        )

        # Create different types of comments
        self.customer_comment = TicketComment.objects.create(
            ticket=self.ticket,
            content='Customer comment - visible to all',
            comment_type='customer',
            author=self.customer_user,
            author_name=self.customer_user.get_full_name(),
            author_email=self.customer_user.email,
            is_public=True
        )

        self.support_comment = TicketComment.objects.create(
            ticket=self.ticket,
            content='Support comment - visible to all',
            comment_type='support',
            author=self.support_user,
            author_name=self.support_user.get_full_name(),
            author_email=self.support_user.email,
            is_public=True
        )

        self.internal_comment = TicketComment.objects.create(
            ticket=self.ticket,
            content='Internal staff note - CONFIDENTIAL - customer should not see this',
            comment_type='internal',
            author=self.staff_user,
            author_name=self.staff_user.get_full_name(),
            author_email=self.staff_user.email,
            is_public=False
        )

        self.client = Client()

    def test_staff_can_see_all_comments(self):
        """Test that staff users can see all comments including internal notes"""
        # Test admin user
        self.client.login(email='admin@example.com', password='testpass123')
        response = self.client.get(reverse('tickets:detail', kwargs={'pk': self.ticket.pk}))
        self.assertEqual(response.status_code, 200)

        # Check that admin sees all comment types
        self.assertContains(response, 'Customer comment - visible to all')
        self.assertContains(response, 'Support comment - visible to all')
        self.assertContains(response, 'Internal staff note - CONFIDENTIAL')
        self.assertContains(response, 'STAFF INTERNAL NOTE')

        # Test support user
        self.client.login(email='support@example.com', password='testpass123')
        response = self.client.get(reverse('tickets:detail', kwargs={'pk': self.ticket.pk}))
        self.assertEqual(response.status_code, 200)

        # Check that support sees all comment types
        self.assertContains(response, 'Customer comment - visible to all')
        self.assertContains(response, 'Support comment - visible to all')
        self.assertContains(response, 'Internal staff note - CONFIDENTIAL')
        self.assertContains(response, 'STAFF INTERNAL NOTE')

    def test_customer_cannot_see_internal_comments(self):
        """Test that customer users cannot see internal staff notes"""
        self.client.login(email='customer@example.com', password='testpass123')
        response = self.client.get(reverse('tickets:detail', kwargs={'pk': self.ticket.pk}))
        self.assertEqual(response.status_code, 200)

        # Check that customer sees public comments only
        self.assertContains(response, 'Customer comment - visible to all')
        self.assertContains(response, 'Support comment - visible to all')

        # Check that customer does NOT see internal comments
        self.assertNotContains(response, 'Internal staff note - CONFIDENTIAL')
        self.assertNotContains(response, 'STAFF INTERNAL NOTE')

    def test_support_role_without_django_staff_flag_sees_internal_comments(self):
        """A support agent with staff_role='support' but is_staff=False (is_staff_user=True)
        must see internal staff notes on the ticket detail page.

        Regression guard for the is_staff_user migration in comments_list.html and the
        ticket_detail comment filter (views.py:163). Uses a fixture WITHOUT the Django
        is_staff flag, so reverting either gate to `is_staff` would re-lock this agent
        and fail this test (the existing staff/support fixtures set is_staff=True and
        cannot detect that regression).
        """
        self.client.login(email='support-no-flag@example.com', password='testpass123')
        response = self.client.get(reverse('tickets:detail', kwargs={'pk': self.ticket.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Internal staff note - CONFIDENTIAL')
        self.assertContains(response, 'STAFF INTERNAL NOTE')

    def test_reopen_button_gated_on_is_staff_user_not_django_is_staff(self):
        """The reopen action on a CLOSED ticket must show for staff_role agents
        (is_staff_user=True) even without the Django is_staff flag, and stay hidden
        from customers. Template gate: tickets/detail.html user.is_staff_user.
        """
        closed_ticket = Ticket.objects.create(
            customer=self.customer,
            title='Closed Ticket',
            description='Closed ticket for reopen test',
            priority='normal',
            status='closed',
            created_by=self.customer_user,
        )
        reopen_url = reverse('tickets:reopen', kwargs={'pk': closed_ticket.pk})

        # Support agent (is_staff=False, staff_role='support') sees the reopen action
        self.client.login(email='support-no-flag@example.com', password='testpass123')
        staff_response = self.client.get(reverse('tickets:detail', kwargs={'pk': closed_ticket.pk}))
        self.assertEqual(staff_response.status_code, 200)
        self.assertContains(staff_response, reopen_url)

        # Customer must NOT see the reopen action
        self.client.login(email='customer@example.com', password='testpass123')
        customer_response = self.client.get(reverse('tickets:detail', kwargs={'pk': closed_ticket.pk}))
        self.assertEqual(customer_response.status_code, 200)
        self.assertNotContains(customer_response, reopen_url)

    def test_htmx_comments_endpoint_security(self):
        """Test that HTMX comments endpoint respects internal comment security"""
        # Test staff user via HTMX
        self.client.login(email='admin@example.com', password='testpass123')
        response = self.client.get(
            reverse('tickets:comments_htmx', kwargs={'pk': self.ticket.pk}),
            HTTP_HX_REQUEST='true'
        )
        self.assertEqual(response.status_code, 200)

        # Staff should see internal comments in HTMX response
        self.assertContains(response, 'Internal staff note - CONFIDENTIAL')
        self.assertContains(response, 'STAFF INTERNAL NOTE')

        # Test customer user via HTMX
        self.client.login(email='customer@example.com', password='testpass123')
        response = self.client.get(
            reverse('tickets:comments_htmx', kwargs={'pk': self.ticket.pk}),
            HTTP_HX_REQUEST='true'
        )
        self.assertEqual(response.status_code, 200)

        # Customer should NOT see internal comments in HTMX response
        self.assertNotContains(response, 'Internal staff note - CONFIDENTIAL')
        self.assertNotContains(response, 'STAFF INTERNAL NOTE')

    def test_reply_htmx_response_filters_internal_notes_for_customer(self):
        """Reply POST (HX-Request) must not leak internal notes to non-staff.

        Regression: the reply HTMX branch refreshed comments with comments.all(),
        relying solely on the template gate. A customer posting a reply received
        the internal-note content in the rendered swap.
        """
        self.client.login(email='customer@example.com', password='testpass123')
        response = self.client.post(
            reverse('tickets:reply', kwargs={'pk': self.ticket.pk}),
            {'reply': 'Customer follow-up reply'},
            HTTP_HX_REQUEST='true',
        )
        self.assertEqual(response.status_code, 200)
        # Customer-visible comments are present...
        self.assertContains(response, 'Customer comment - visible to all')
        self.assertContains(response, 'Support comment - visible to all')
        # ...but the internal note is not in the rendered swap.
        self.assertNotContains(response, 'Internal staff note - CONFIDENTIAL')
        # Lock in the server-side filter: the internal note must not even reach
        # the rendering context. The template gate alone hides the content, so a
        # body-only assertion would still pass if the queryset filter regressed.
        self.assertNotIn(self.internal_comment, list(response.context['comments']))

    def test_reply_htmx_response_includes_internal_notes_for_staff(self):
        """Staff posting a reply via HX-Request still see internal notes."""
        self.client.login(email='admin@example.com', password='testpass123')
        response = self.client.post(
            reverse('tickets:reply', kwargs={'pk': self.ticket.pk}),
            {'reply': 'Staff follow-up reply'},
            HTTP_HX_REQUEST='true',
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Internal staff note - CONFIDENTIAL')
        self.assertIn(self.internal_comment, list(response.context['comments']))

    def test_invalid_staff_reply_action_does_not_persist_comment_or_mutate_ticket(self):
        """Reject a forged action before writing either the reply or assignment."""
        original_comment_count = self.ticket.comments.count()
        self.client.login(email='admin@example.com', password='testpass123')

        response = self.client.post(
            reverse('tickets:reply', kwargs={'pk': self.ticket.pk}),
            {
                'reply': 'This comment must never be stored',
                'reply_action': 'forged_action',
            },
        )

        self.assertRedirects(response, reverse('tickets:detail', kwargs={'pk': self.ticket.pk}))
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.comments.count(), original_comment_count)
        self.assertIsNone(self.ticket.assigned_to)
        self.assertEqual(self.ticket.status, 'open')

    def test_detail_page_shows_empty_state_when_only_internal_notes_exist(self):
        """The detail page must render the filtered queryset, not ticket.comments.all.

        Regression: detail.html included the comments partial with
        comments=ticket.comments.all, discarding the server-side filter from
        ticket_detail(). For a ticket whose only comment is an internal note,
        a customer must get the empty state instead of a loop over hidden rows.
        """
        internal_only_ticket = Ticket.objects.create(
            customer=self.customer,
            title='Internal-only Ticket',
            description='Ticket with only an internal note',
            priority='normal',
            status='open',
            created_by=self.customer_user,
        )
        TicketComment.objects.create(
            ticket=internal_only_ticket,
            content='Internal-only staff note - CONFIDENTIAL',
            comment_type='internal',
            author=self.staff_user,
            author_name=self.staff_user.get_full_name(),
            author_email=self.staff_user.email,
            is_public=False,
        )

        self.client.login(email='customer@example.com', password='testpass123')
        response = self.client.get(reverse('tickets:detail', kwargs={'pk': internal_only_ticket.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'Internal-only staff note - CONFIDENTIAL')
        self.assertContains(response, 'No replies yet. Be the first to respond!')

    def test_conversation_count_excludes_hidden_comments_for_customer(self):
        """The conversation header count must not disclose hidden internal notes.

        A customer seeing "(3 replies)" with only 2 rendered comments leaks the
        existence of internal notes. The count must come from the filtered
        queryset, not ticket.comments.count.
        """
        self.client.login(email='customer@example.com', password='testpass123')
        response = self.client.get(reverse('tickets:detail', kwargs={'pk': self.ticket.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '(2 replies)')
        self.assertNotContains(response, '(3 replies)')

        # Staff still see the full count including the internal note.
        self.client.login(email='admin@example.com', password='testpass123')
        response = self.client.get(reverse('tickets:detail', kwargs={'pk': self.ticket.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '(3 replies)')

    def test_comment_filtering_in_views(self):
        """Test that view-level comment filtering works correctly"""
        # Test with staff user - should see all comments
        self.client.login(email='admin@example.com', password='testpass123')
        response = self.client.get(reverse('tickets:detail', kwargs={'pk': self.ticket.pk}))
        self.assertEqual(response.status_code, 200)

        # Staff should see all 3 comments
        comments_in_context = response.context['comments']
        self.assertEqual(comments_in_context.count(), 3)

        # Test with customer user - should see only public comments
        self.client.login(email='customer@example.com', password='testpass123')
        response = self.client.get(reverse('tickets:detail', kwargs={'pk': self.ticket.pk}))
        self.assertEqual(response.status_code, 200)

        # Customer should see only 2 public comments
        comments_in_context = response.context['comments']
        self.assertEqual(comments_in_context.count(), 2)

    def test_internal_comment_styling(self):
        """Test that internal comments have proper styling when visible to staff"""
        self.client.login(email='admin@example.com', password='testpass123')
        response = self.client.get(reverse('tickets:detail', kwargs={'pk': self.ticket.pk}))

        # Check for internal comment styling
        self.assertContains(response, 'bg-amber-900/50')  # Internal comment background
        self.assertContains(response, 'border-amber-600')  # Internal comment border
        self.assertContains(response, 'bg-red-700')  # Internal badge background

    def test_non_staff_user_properties(self):
        """Test user property checks for staff vs customer users"""
        # Test staff user properties
        self.assertTrue(self.staff_user.is_staff)
        self.assertTrue(self.staff_user.is_staff_user)
        self.assertEqual(self.staff_user.staff_role, 'admin')

        self.assertTrue(self.support_user.is_staff)
        self.assertTrue(self.support_user.is_staff_user)
        self.assertEqual(self.support_user.staff_role, 'support')

        # Test customer user properties
        self.assertFalse(self.customer_user.is_staff)
        self.assertFalse(self.customer_user.is_staff_user)
        self.assertEqual(self.customer_user.staff_role, '')

    def test_unauthorized_access_to_other_customer_tickets(self):
        """Test that customers cannot access tickets from other customers"""
        # Create another customer and user
        other_customer = Customer.objects.create(
            name='Other Company SRL',
            company_name='Other Company SRL',
            customer_type='company',
            status='active',
            primary_email='other@example.com',
            primary_phone='+40712345679'
        )

        other_user = User.objects.create_user(
            email='other@example.com',
            password='testpass123'
        )
        other_user.first_name = 'Other'
        other_user.last_name = 'User'
        other_user.save()

        CustomerMembership.objects.create(
            user=other_user,
            customer=other_customer,
            role='owner',
            is_primary=True
        )

        # Try to access ticket from different customer
        self.client.login(email='other@example.com', password='testpass123')
        response = self.client.get(reverse('tickets:detail', kwargs={'pk': self.ticket.pk}))

        # Should redirect with error message
        self.assertEqual(response.status_code, 302)  # Redirect due to no permission

    def test_comment_count_by_type(self):
        """Test that comment counts are correct for different user types"""
        # Get all comments from database
        all_comments = TicketComment.objects.filter(ticket=self.ticket)
        customer_comments = all_comments.filter(comment_type__in=['customer', 'support'])
        internal_comments = all_comments.filter(comment_type='internal')

        self.assertEqual(all_comments.count(), 3)  # Total comments
        self.assertEqual(customer_comments.count(), 2)  # Public comments
        self.assertEqual(internal_comments.count(), 1)  # Internal comments

    def test_comment_author_information(self):
        """Test that comment author information is properly displayed"""
        self.client.login(email='admin@example.com', password='testpass123')
        response = self.client.get(reverse('tickets:detail', kwargs={'pk': self.ticket.pk}))

        # Check that author names are displayed
        self.assertContains(response, self.customer_user.get_full_name())
        self.assertContains(response, self.support_user.get_full_name())
        self.assertContains(response, self.staff_user.get_full_name())

        # Check role badges
        self.assertContains(response, 'Customer')  # Customer badge
        self.assertContains(response, 'Support')   # Support badge
