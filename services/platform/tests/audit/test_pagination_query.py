"""Audit pagination preserves search and repeated filter keys."""

from datetime import timedelta

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent, DataExport
from apps.users.models import User
from tests.common.pagination_assertions import SEARCH, assert_next_query


class AuditPaginationQueryTests(TestCase):
    def setUp(self) -> None:
        self.staff = User.objects.create_user(email="audit-pagination@example.test", is_staff=True, staff_role="admin")
        self.client.force_login(self.staff)

    def test_logs_next_link_round_trips_filters(self) -> None:
        content_type = ContentType.objects.get_for_model(User)
        for _ in range(3):
            AuditEvent.objects.create(
                user=self.staff,
                action="create",
                category="business_operation",
                severity="low",
                content_type=content_type,
                object_id=str(self.staff.pk),
                description=SEARCH,
            )
        response = self.client.get(
            reverse("audit:logs_list"),
            {"q": SEARCH, "search": SEARCH, "action": ["create", "update"], "page_size": "2", "page": "1"},
        )
        assert_next_query(
            self, response, {"q": [SEARCH], "search": [SEARCH], "action": ["create", "update"], "page_size": ["2"]}
        )

    def test_export_requests_next_link_round_trips_filters(self) -> None:
        for _ in range(26):
            DataExport.objects.create(
                requested_by=self.staff, export_type="gdpr", expires_at=timezone.now() + timedelta(days=1)
            )
        response = self.client.get(
            reverse("audit:gdpr_export_requests_list"),
            {"q": SEARCH, "status": "pending", "facet": ["one", "two"], "page": "1"},
        )
        assert_next_query(self, response, {"q": [SEARCH], "status": ["pending"], "facet": ["one", "two"]})
