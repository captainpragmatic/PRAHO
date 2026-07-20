"""
Rendering smoke tests for the ticket list page (shared-component refactor, #152).

The list page is assembled from shared components (list_page_header,
list_page_filters, list_page_skeleton) driven entirely by context variables.
No other test exercises that contract — these render the real templates so a
renamed component parameter or missing context key fails loudly here instead
of in production.

The platform is staff-only (StaffOnlyPlatformMiddleware logs out customer
users before any view runs; the customer ticket UI lives in the portal
service), so all assertions target the staff experience.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

User = get_user_model()


class TicketListRenderingTests(TestCase):
    """GET /app/tickets/ must render the shared-component page end to end."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(
            email="staff@test.com", password="StrongPass123!", is_staff=True
        )
        self.client.force_login(self.user)

    def test_list_page_renders_with_shared_components(self) -> None:
        response = self.client.get(reverse("tickets:list"))

        self.assertEqual(response.status_code, 200)
        templates = {t.name for t in response.templates if t.name}
        self.assertIn("tickets/list.html", templates)

    def test_list_page_shows_status_tabs_and_search(self) -> None:
        response = self.client.get(reverse("tickets:list"))
        content = response.content.decode()

        for label in ("Open", "In Progress", "Waiting on Customer", "Closed"):
            self.assertIn(label, content)
        self.assertIn("tickets-content", content)
        self.assertIn("tickets-skeleton", content)

    def test_list_page_shows_staff_copy_and_search_guidance(self) -> None:
        """Title, subtitle, and the staff search placeholder from the pre-refactor page."""
        content = self.client.get(reverse("tickets:list")).content.decode()

        self.assertIn("Support Tickets", content)
        self.assertIn("Manage customer support requests", content)
        self.assertIn("Search by number, title or customer", content)
        # Staff table has 5 columns (incl. Customer) — skeleton must match.
        self.assertIn("grid-cols-5", content)

    def test_filter_tabs_expose_complete_keyboard_and_panel_contract(self) -> None:
        content = self.client.get(reverse("tickets:list")).content.decode()

        tab_count = content.count('role="tab" data-tab-value=')
        self.assertGreater(tab_count, 0)
        self.assertEqual(content.count('aria-controls="tickets-content"'), tab_count)
        self.assertEqual(content.count('onkeydown="handleTabKeydown(event, this)"'), tab_count)
        self.assertIn('tabindex="0"', content)
        self.assertIn('tabindex="-1"', content)
        self.assertIn(
            'id="tickets-content" role="tabpanel" tabindex="0" aria-label="Filtered results"',
            content,
        )

        self.assertIn("function handleTabKeydown(event, el)", content)
        for key in ("ArrowLeft", "ArrowRight", "Home", "End"):
            self.assertIn(key, content)
        self.assertIn("target.focus()", content)
        self.assertIn("target.click()", content)
        self.assertIn("t.classList.remove(t.dataset.tabBorder, t.dataset.tabText)", content)
        self.assertNotIn(".className.replace(", content)

    def test_search_htmx_returns_table_partial(self) -> None:
        response = self.client.get(reverse("tickets:search_htmx"), {"status": "open"})

        self.assertEqual(response.status_code, 200)
        templates = {t.name for t in response.templates if t.name}
        self.assertIn("tickets/partials/tickets_table.html", templates)


class TicketListHtmxSyncTests(TestCase):
    """Tab clicks and search share one hx-sync group so a stale response can't win.

    The pre-refactor form carried hx-sync="this:replace"; the shared filters
    component issues independent requests per element, so without a shared sync
    root a slow earlier response can overwrite a newer tab's rows.
    """

    def test_filter_requests_are_synchronized(self) -> None:
        user = User.objects.create_user(email="sync@test.com", password="StrongPass123!", is_staff=True)
        self.client.force_login(user)
        content = self.client.get(reverse("tickets:list")).content.decode()

        self.assertIn("list-filters-sync", content)
        self.assertGreaterEqual(content.count("hx-sync="), 2)
