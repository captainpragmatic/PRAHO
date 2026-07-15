"""
Rendering smoke tests for the ticket list page (shared-component refactor, #152).

The list page is assembled from shared components (list_page_header,
list_page_filters, list_page_skeleton) driven entirely by context variables.
No unit test exercises that contract — these render the real templates so a
renamed component parameter or missing context key fails loudly here instead
of in production.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

User = get_user_model()


class TicketListRenderingTests(TestCase):
    """GET /app/tickets/ must render the shared-component page end to end."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(email="staff@test.com", password="StrongPass123!")
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

    def test_search_htmx_returns_table_partial(self) -> None:
        response = self.client.get(reverse("tickets:search_htmx"), {"status": "open"})

        self.assertEqual(response.status_code, 200)
        templates = {t.name for t in response.templates if t.name}
        self.assertIn("tickets/partials/tickets_table.html", templates)


class TicketListAudienceCopyTests(TestCase):
    """Staff and customers must keep their distinct copy (parity with the pre-refactor page).

    The old inline template branched on user.is_staff_user for the title,
    subtitle, search placeholder, and skeleton column count. The shared-component
    context must preserve those branches — ticket_list is @login_required, so
    customers reach this page too.
    """

    def _page_for(self, *, staff: bool) -> str:
        user = User.objects.create_user(
            email=f"{'staff' if staff else 'customer'}-copy@test.com",
            password="StrongPass123!",
            is_staff=staff,
        )
        self.client.force_login(user)
        return self.client.get(reverse("tickets:list")).content.decode()

    def test_customer_sees_customer_copy(self) -> None:
        content = self._page_for(staff=False)
        self.assertIn("My Support Tickets", content)
        self.assertIn("Get help with your hosting services", content)
        self.assertNotIn("Manage customer support requests", content)

    def test_staff_sees_staff_copy_and_search_guidance(self) -> None:
        content = self._page_for(staff=True)
        self.assertIn("Manage customer support requests", content)
        self.assertIn("Search by number, title or customer", content)

    def test_skeleton_columns_match_audience(self) -> None:
        self.assertIn("grid-cols-4", self._page_for(staff=False))
        self.assertIn("grid-cols-5", self._page_for(staff=True))


class TicketListHtmxSyncTests(TestCase):
    """Tab clicks and search share one hx-sync group so a stale response can't win.

    The pre-refactor form carried hx-sync="this:replace"; the shared filters
    component issues independent requests per element, so without a shared sync
    root a slow earlier response can overwrite a newer tab's rows.
    """

    def test_filter_requests_are_synchronized(self) -> None:
        user = User.objects.create_user(email="sync@test.com", password="StrongPass123!")
        self.client.force_login(user)
        content = self.client.get(reverse("tickets:list")).content.decode()

        self.assertIn("list-filters-sync", content)
        self.assertGreaterEqual(content.count("hx-sync="), 2)
