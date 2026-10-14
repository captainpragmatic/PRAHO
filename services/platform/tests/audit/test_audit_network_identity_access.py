"""Who may see where someone signed in from: administrators only (#689).

The audit log records IP addresses, user agents and session keys. Every staff role
could read them, search by them, export them and pull them from search suggestions.
Other roles keep the audit log, without those details.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.contenttypes.models import ContentType
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent, AuditSearchQuery, DataExport
from apps.audit.services import AuditSearchService
from apps.users.models import User

WATCHED_IP = "203.0.113.77"
OTHER_IP = "198.51.100.9"
WATCHED_AGENT = "Mozilla/5.0 (Watched Agent 7.7)"
WATCHED_SESSION = "watchedsessionkey0123456789abcdef"


class NetworkIdentityAccessTests(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        self.admin = User.objects.create_user(
            email="admin@example.com", password="x-pass-123", is_staff=True, staff_role="admin"
        )
        self.support = User.objects.create_user(
            email="support@example.com", password="x-pass-123", is_staff=True, staff_role="support"
        )
        self.customer = User.objects.create_user(email="customer@example.com", password="x-pass-123")
        content_type = ContentType.objects.get_for_model(User)
        self.watched = AuditEvent.objects.create(
            action="login_success",
            category="authentication",
            severity="low",
            content_type=content_type,
            object_id=str(self.customer.pk),
            user=self.customer,
            description="Signed in",
            ip_address=WATCHED_IP,
            user_agent=WATCHED_AGENT,
            session_key=WATCHED_SESSION,
            new_values={"last_login_ip": WATCHED_IP, "nested": {"client_ip": WATCHED_IP}, "plan": "basic"},
        )
        self.unrelated = AuditEvent.objects.create(
            action="login_success",
            category="authentication",
            severity="low",
            content_type=content_type,
            object_id=str(self.admin.pk),
            user=self.admin,
            description="Signed in",
            ip_address=OTHER_IP,
        )

    def _event_ids(self, user: User, **filters: object) -> set[uuid.UUID]:
        queryset, _info = AuditSearchService.build_advanced_query(dict(filters), user)
        return set(queryset.values_list("id", flat=True))

    # --- the search service is the chokepoint every view goes through ---------------

    def test_other_roles_cannot_narrow_by_ip_session_or_ip_text(self) -> None:
        everything = self._event_ids(self.support)
        self.assertTrue({self.watched.id, self.unrelated.id} <= everything)
        self.assertEqual(self._event_ids(self.support, ip_addresses=WATCHED_IP), everything)
        self.assertEqual(self._event_ids(self.support, session_keys=WATCHED_SESSION), everything)
        # Text search reaches into the recorded values, which can hold an address.
        self.assertEqual(self._event_ids(self.support, search_text=WATCHED_IP), set())

    def test_administrators_can_search_by_ip_and_session(self) -> None:
        self.assertEqual(self._event_ids(self.admin, ip_addresses=WATCHED_IP), {self.watched.id})
        self.assertEqual(self._event_ids(self.admin, session_keys=WATCHED_SESSION), {self.watched.id})
        self.assertEqual(self._event_ids(self.admin, search_text=WATCHED_IP), {self.watched.id})

    # --- pages ------------------------------------------------------------------------

    def test_other_roles_see_no_ip_agent_or_session_anywhere(self) -> None:
        self.client.force_login(self.support)
        pages = {
            "list": self.client.get(reverse("audit:logs_list")),
            "list filtered": self.client.get(reverse("audit:logs_list") + f"?ip_address={WATCHED_IP}"),
            "detail": self.client.get(reverse("audit:event_detail", args=[self.watched.id])),
            "logs page": self.client.get(reverse("audit:logs")),
        }
        for name, response in pages.items():
            with self.subTest(page=name):
                self.assertEqual(response.status_code, 200)
                for secret in (WATCHED_IP, OTHER_IP, WATCHED_AGENT, WATCHED_SESSION[-8:]):
                    self.assertNotContains(response, secret)
        # The recorded change itself stays readable.
        self.assertContains(pages["detail"], "basic")
        # No IP search box and no list of every account to pick from.
        self.assertNotContains(pages["logs page"], 'name="ip_address"')
        self.assertNotContains(pages["logs page"], self.customer.email)

    def test_administrators_still_see_them(self) -> None:
        self.client.force_login(self.admin)
        detail = self.client.get(reverse("audit:event_detail", args=[self.watched.id]))
        self.assertContains(detail, WATCHED_IP)
        self.assertContains(detail, WATCHED_AGENT)
        self.assertContains(self.client.get(reverse("audit:logs_list")), WATCHED_IP)
        logs_page = self.client.get(reverse("audit:logs"))
        self.assertContains(logs_page, 'name="ip_address"')
        self.assertContains(logs_page, self.customer.email)

    def test_export_is_for_administrators(self) -> None:
        self.client.force_login(self.support)
        self.assertEqual(self.client.get(reverse("audit:export_logs")).status_code, 403)
        self.assertEqual(self.client.get(reverse("audit:export_logs_csv")).status_code, 403)

        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(reverse("audit:export_logs")).status_code, 200)

    def test_suggestions_offer_other_roles_no_addresses_or_accounts(self) -> None:
        for_support = AuditSearchService.get_search_suggestions("203.0", self.support)
        self.assertEqual(for_support["ip_addresses"], [])
        self.assertEqual(AuditSearchService.get_search_suggestions("customer", self.support)["users"], [])
        # Action names are not personal data; autocomplete keeps working for every role.
        self.assertIn("login_success", AuditSearchService.get_search_suggestions("login", self.support)["actions"])

        for_admin = AuditSearchService.get_search_suggestions("203.0", self.admin)
        self.assertEqual(for_admin["ip_addresses"], [WATCHED_IP])
        self.assertIn(self.customer.email, AuditSearchService.get_search_suggestions("customer", self.admin)["users"])


class GDPRExportDownloadAccessTests(TestCase):
    """Anyone's full personal-data export: administrators only (#689)."""

    def setUp(self) -> None:
        self.client = Client()
        self.admin = User.objects.create_user(
            email="admin@example.com", password="x-pass-123", is_staff=True, staff_role="admin"
        )
        self.billing = User.objects.create_user(
            email="billing@example.com", password="x-pass-123", is_staff=True, staff_role="billing"
        )
        customer = User.objects.create_user(email="customer@example.com", password="x-pass-123")
        self.export = DataExport.objects.create(
            requested_by=customer,
            export_type="gdpr",
            scope={},
            status="completed",
            expires_at=timezone.now() + timedelta(days=7),
        )

    def test_other_roles_cannot_download_or_see_the_link(self) -> None:
        download = reverse("audit:download_user_export", args=[self.export.id])
        detail_url = reverse("audit:gdpr_export_detail", args=[self.export.id])
        self.export.file_path = "exports/example.json"
        self.export.save(update_fields=["file_path"])
        with patch("apps.audit.views.default_storage.exists", return_value=True):
            self.client.force_login(self.billing)
            self.assertEqual(self.client.get(download).status_code, 403)
            detail = self.client.get(detail_url)
            self.assertEqual(detail.status_code, 200)
            self.assertNotContains(detail, download)

            # The same page offers it to an administrator, so the absence above is the role check.
            self.client.force_login(self.admin)
            self.assertContains(self.client.get(detail_url), download)

    def test_administrators_are_not_refused(self) -> None:
        self.client.force_login(self.admin)
        download = reverse("audit:download_user_export", args=[self.export.id])
        # No file on disk in this test: the view redirects with "not found", which is past the role check.
        self.assertNotEqual(self.client.get(download).status_code, 403)


class ReviewFollowUpTests(TestCase):
    """Gaps found reviewing the first pass (#689)."""

    def setUp(self) -> None:
        self.admin = User.objects.create_user(
            email="admin@example.com", password="x-pass-123", is_staff=True, staff_role="admin"
        )
        self.support = User.objects.create_user(
            email="support@example.com", password="x-pass-123", is_staff=True, staff_role="support"
        )
        content_type = ContentType.objects.get_for_model(User)
        self.event = AuditEvent.objects.create(
            action="profile_updated",
            category="account_management",
            severity="low",
            content_type=content_type,
            object_id=str(self.support.pk),
            user=self.support,
            description="Profile changed",
            new_values={
                "last_login_ip": WATCHED_IP,
                "note": f"seen from {WATCHED_IP}:443 and [2001:db8::7]:443",
                "HTTP_X_FORWARDED_FOR": f"{OTHER_IP}, 10.0.0.1",
                WATCHED_IP: "an address used as a key",
                "login": {"user_agent_info": {"raw": WATCHED_AGENT}},
                "invoice": "INV-12345",
            },
        )

    def _ids(self, user: User, text: str) -> set[uuid.UUID]:
        queryset, _info = AuditSearchService.build_advanced_query({"search_text": text}, user)
        return set(queryset.values_list("id", flat=True))

    def test_other_roles_never_search_inside_recorded_values(self) -> None:
        # A quote anchors a match to the start of a value, one octet at a time.
        for probe in (f'"{WATCHED_IP}"', '"203.', "Mozilla", "12345"):
            with self.subTest(probe=probe):
                self.assertNotIn(self.event.id, self._ids(self.support, probe))
        # Descriptions and action names stay searchable.
        self.assertIn(self.event.id, self._ids(self.support, "Profile changed"))
        # Administrators keep the full search.
        self.assertIn(self.event.id, self._ids(self.admin, "12345"))
        self.assertIn(self.event.id, self._ids(self.admin, f'"{WATCHED_IP}"'))

    def test_addresses_and_agents_are_hidden_wherever_they_sit_in_recorded_values(self) -> None:
        self.client.force_login(self.support)
        detail = self.client.get(reverse("audit:event_detail", args=[self.event.id]))
        for secret in (WATCHED_IP, OTHER_IP, "10.0.0.1", "2001:db8::7", WATCHED_AGENT):
            with self.subTest(secret=secret):
                self.assertNotContains(detail, secret)
        self.assertContains(detail, "INV-12345")

    def test_buttons_that_would_refuse_other_roles_are_not_shown_to_them(self) -> None:
        self.client.force_login(self.support)
        logs_page = self.client.get(reverse("audit:logs"))
        self.assertNotContains(logs_page, 'data-invoke="exportCSV"')

        customer = User.objects.create_user(email="customer@example.com", password="x-pass-123")
        export = DataExport.objects.create(
            requested_by=customer,
            export_type="gdpr",
            scope={},
            status="completed",
            expires_at=timezone.now() + timedelta(days=7),
        )
        listing = self.client.get(reverse("audit:gdpr_export_requests_list"))
        self.assertNotContains(listing, reverse("audit:download_user_export", args=[export.id]))

        self.client.force_login(self.admin)
        self.assertContains(self.client.get(reverse("audit:logs")), 'data-invoke="exportCSV"')
        listing = self.client.get(reverse("audit:gdpr_export_requests_list"))
        self.assertContains(listing, reverse("audit:download_user_export", args=[export.id]))

    def test_a_shared_saved_search_does_not_carry_an_address_to_other_roles(self) -> None:
        saved = AuditSearchQuery.objects.create(
            name="From one address",
            query_params={"ip_address": WATCHED_IP, "session_key": WATCHED_SESSION, "action": "login_success"},
            created_by=self.admin,
            is_shared=True,
        )
        self.client.force_login(self.support)
        response = self.client.get(reverse("audit:load_saved_search", args=[saved.id]))
        self.assertEqual(response.status_code, 302)
        self.assertIn("action=login_success", response["Location"])
        self.assertNotIn(WATCHED_IP, response["Location"])
        self.assertNotIn(WATCHED_SESSION, response["Location"])
