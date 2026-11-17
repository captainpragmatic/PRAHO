"""The cross-service list of database overage episodes that need staff."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.common.context_processors import navigation_dropdowns
from apps.provisioning.database_overage_attention import episodes_needing_attention
from apps.provisioning.database_overage_models import DatabaseOverageEpisode
from apps.users.models import User
from tests.provisioning.database_overage_fixtures import make_overage_account


class DatabaseOverageAttentionTests(TestCase):
    def setUp(self):
        self.now = timezone.now()

    def episode(self, label: str, **fields) -> DatabaseOverageEpisode:
        fixture = make_overage_account(label)
        return DatabaseOverageEpisode.objects.create(
            account=fixture.account,
            service=fixture.service,
            service_id_snapshot=fixture.service.pk,
            customer_id_snapshot=fixture.customer.pk,
            owner_scope=fixture.usage.owner_scope,
            server_id=fixture.server.pk,
            domain_id=fixture.usage.domain_id,
            domain=fixture.account.domain,
            opened_at=self.now - timedelta(days=16),
            deadline_at=self.now - timedelta(days=2),
            **fields,
        )

    def releasing(self, label: str, **fields) -> DatabaseOverageEpisode:
        episode = self.episode(label, **fields)
        episode.start_hold(token=uuid4(), generation=1)
        episode.start_release("waived")
        episode.save()
        return episode

    def test_the_list_holds_exactly_the_episodes_staff_must_look_at(self):
        listed = {
            self.episode("deferred-long", deferred_since=self.now - timedelta(hours=25)).pk,
            self.episode("refused", hold_refused_at=self.now - timedelta(hours=1)).pk,
            self.releasing("release-failing", last_error="release pending: no response").pk,
            self.episode("drift", needs_reconcile=True).pk,
        }
        self.episode("deferred-short", deferred_since=self.now - timedelta(hours=2))
        self.releasing("release-first-try")
        self.episode("ordinary")
        closed = self.episode("closed", hold_refused_at=self.now)
        closed.close("waived")
        closed.save()
        self.assertEqual({episode.pk for episode in episodes_needing_attention(at=self.now)}, listed)

    def test_any_staff_member_sees_the_list_with_links_to_each_service_page(self):
        episode = self.episode("linked", hold_refused_at=self.now)
        url = reverse("provisioning:database_overage_attention")
        customer = User.objects.create_user("customer-attention@example.test", "fixture-password")
        self.client.force_login(customer)
        self.assertNotEqual(self.client.get(url).status_code, 200)
        staff = User.objects.create_user(
            "support-attention@example.test", "fixture-password", is_staff=True, staff_role="support"
        )
        self.client.force_login(staff)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, reverse("provisioning:service_database_overage", kwargs={"pk": episode.service_id})
        )

    def test_staff_navigation_has_the_entry(self):
        staff = User.objects.create_user(
            "nav-attention@example.test", "fixture-password", is_staff=True, staff_role="support"
        )
        request = RequestFactory().get("/")
        request.user = staff
        urls = [item.get("url") for item in navigation_dropdowns(request)["business_items"]]
        self.assertIn(reverse("provisioning:database_overage_attention"), urls)

    def test_the_list_pages_rather_than_hiding_episodes(self):
        for index in range(26):
            self.episode(f"many-{index:02}", hold_refused_at=self.now)
        staff = User.objects.create_user("pager@example.test", "fixture-password", is_staff=True, staff_role="support")
        self.client.force_login(staff)
        url = reverse("provisioning:database_overage_attention")
        last = DatabaseOverageEpisode.objects.order_by("deadline_at", "pk").last()
        self.assertNotContains(self.client.get(url), last.domain)
        self.assertContains(self.client.get(url, {"page": 2}), last.domain)

    def test_support_can_read_a_service_page_but_not_act_on_it(self):
        episode = self.episode("read-only", hold_refused_at=self.now)
        support = User.objects.create_user("reader@example.test", "fixture-password", is_staff=True, staff_role="support")
        self.client.force_login(support)
        url = reverse("provisioning:service_database_overage", kwargs={"pk": episode.service_id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'name="action"')
        post = self.client.post(url, {"action": "waive", "reason": "Support should not waive", "episode": str(episode.pk)})
        self.assertEqual(post.status_code, 403)
