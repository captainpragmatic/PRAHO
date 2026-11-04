"""Security reads stored observations under the same explicit role policy as navigation."""

from __future__ import annotations

from dataclasses import asdict
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import Client, TestCase, override_settings
from django.utils import timezone

from apps.security.addresses import address_bounds
from apps.security.models import SecurityAlert, SecurityDecision, SecuritySource, SecuritySyncState
from apps.users.models import User


class SecurityViewPermissionTests(TestCase):
    def test_only_explicit_security_roles_can_open_the_page(self) -> None:
        for role, staff, expected in (
            ("admin", True, 200),
            ("support", True, 200),
            ("manager", True, 200),
            ("billing", True, 403),
            ("", True, 403),
            ("", False, 403),
        ):
            with self.subTest(role=role, staff=staff):
                user = User.objects.create_user(
                    email=f"security-{role or 'plain'}-{staff}@example.test",
                    password="test-only-password",
                    staff_role=role,
                    is_staff=staff,
                )
                self.client.force_login(user)
                self.assertEqual(self.client.get("/security/").status_code, expected)

    def test_page_rendering_never_calls_a_host(self) -> None:
        admin = User.objects.create_user(email="security-admin@example.test", staff_role="admin", is_staff=True)
        self.client.force_login(admin)
        with (
            patch("apps.common.crowdsec_transport.remote_rpc", side_effect=AssertionError("Remote I/O during render")),
            patch("apps.common.crowdsec_transport.local_rpc", side_effect=AssertionError("Local RPC during render")),
        ):
            response = self.client.get("/security/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No sources enrolled")

    def test_desktop_and_mobile_navigation_follow_the_same_role_policy(self) -> None:
        for role, visible in (("admin", True), ("support", True), ("manager", True), ("billing", False), ("", False)):
            with self.subTest(role=role):
                user = User.objects.create_user(
                    email=f"nav-{role or 'plain'}@example.test", staff_role=role, is_staff=True
                )
                self.client.force_login(user)
                response = self.client.get("/dashboard/")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.content.decode().count('href="/security/"'), 2 if visible else 0)

    def test_superuser_override_and_anonymous_login_redirect(self) -> None:
        self.assertEqual(self.client.get("/security/").status_code, 302)
        user = User.objects.create_user(email="security-super@example.test", is_superuser=True)
        self.client.force_login(user)
        self.assertEqual(self.client.get("/security/").status_code, 200)

    def test_post_without_csrf_is_refused(self) -> None:
        user = User.objects.create_user(email="security-csrf@example.test", staff_role="admin", is_staff=True)
        client = Client(enforce_csrf_checks=True)
        client.force_login(user)
        self.assertEqual(client.post("/security/", {}).status_code, 403)


@override_settings(PRAHO_CROWDSEC_SYNC_ENABLED=True)
class SecurityStoredDataViewTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(email="security-reader@example.test", staff_role="support", is_staff=True)
        self.client.force_login(self.user)
        self.source = SecuritySource.objects.create(
            kind="portal",
            transport="ssh",
            hostname="portal.example.test",
            installation_id=uuid4(),
            configuration_digest="a" * 64,
            sync_enabled=True,
        )
        self.now = timezone.now()

    def decision(self, remote_id: int, value: str, *, expires: timedelta = timedelta(minutes=5)) -> SecurityDecision:
        scope = "range" if "/" in value else "ip"
        return SecurityDecision.objects.create(
            source=self.source,
            remote_id=remote_id,
            source_created_at=self.now,
            expires_at=self.now + expires,
            scenario=f"qualification/decision-{remote_id}",
            type="ban",
            scope=scope,
            value=value,
            origin="crowdsec",
            **asdict(address_bounds(scope, value)),
        )

    def test_decision_filters_include_ip_and_network_overlap_in_both_families(self) -> None:
        self.decision(1, "198.51.100.8/30")
        self.decision(2, "fd00:767::8/126")
        for address, wanted, absent in (
            ("198.51.100.9", "decision-1", "decision-2"),
            ("fd00:767::b", "decision-2", "decision-1"),
            ("198.51.100.0/24", "decision-1", "decision-2"),
        ):
            with self.subTest(address=address):
                response = self.client.get("/security/", {"address": address})
                self.assertContains(response, wanted)
                self.assertNotContains(response, absent)
        self.assertContains(self.client.get("/security/", {"address": "198.51.100.12"}), "No matching records")

    def test_expired_decisions_and_simulated_alerts_are_independently_filtered(self) -> None:
        self.decision(1, "198.51.100.8")
        self.decision(2, "198.51.100.9", expires=timedelta(seconds=-1))
        SecurityAlert.objects.create(
            source=self.source,
            remote_id=1,
            source_created_at=self.now,
            scenario="qualification/simulation",
            event_count=7,
            scope="",
            value="",
            simulated=True,
        )
        self.assertNotContains(self.client.get("/security/"), "decision-2")
        ended = self.client.get("/security/", {"state": "ended"})
        self.assertContains(ended, "decision-2")
        self.assertNotContains(ended, "decision-1")
        alerts = self.client.get("/security/", {"kind": "alerts", "simulated": "yes"})
        self.assertContains(alerts, "qualification/simulation")
        self.assertContains(alerts, "Simulated")

    def test_alert_filter_matches_range_interior(self) -> None:
        SecurityAlert.objects.create(
            source=self.source,
            remote_id=1,
            source_created_at=self.now,
            scenario="qualification/range-alert",
            event_count=9,
            scope="range",
            value="fd00:767::8/126",
            simulated=True,
            **asdict(address_bounds("range", "fd00:767::8/126")),
        )
        self.assertContains(
            self.client.get("/security/", {"kind": "alerts", "address": "fd00:767::9"}), "qualification/range-alert"
        )

    def test_decision_freshness_alert_catchup_and_enforcement_are_separate(self) -> None:
        state = SecuritySyncState.objects.create(
            source=self.source,
            last_published_generation=self.source.generation,
            last_decision_sync_at=self.now,
            has_more=True,
            health={
                "simulation": True,
                "engine": {"active": True},
                "bouncer": {"active": False},
                "configuration": {"qualified": True},
                "firewall": {"qualified": True, "ban_sets_empty": True},
                "clock": {"qualified": False},
            },
        )
        response = self.client.get("/security/")
        for text in ("Decisions current", "Catch-up pending", "Simulation; bans cleared", "Unqualified or unknown"):
            self.assertContains(response, text)
        state.last_published_generation = 0
        state.save(update_fields=["last_published_generation"])
        self.assertContains(self.client.get("/security/"), "Stale")

    def test_filters_reject_invalid_addresses_and_output_escapes_stored_labels(self) -> None:
        response = self.client.get("/security/", {"address": "not-an-ip"})
        self.assertEqual(response.status_code, 400)
        row = self.decision(1, "198.51.100.8")
        row.scenario = '<img src=x onerror="alert(1)">'
        row.save(update_fields=["scenario"])
        response = self.client.get("/security/")
        self.assertNotContains(response, "<img src=x onerror=")
        self.assertContains(response, "&lt;img")

    def test_current_poll_failure_degrades_recent_retained_health(self) -> None:
        SecuritySyncState.objects.create(
            source=self.source,
            last_published_generation=self.source.generation,
            last_decision_sync_at=self.now,
            last_alert_sync_at=self.now,
            outcome="unavailable",
            health={
                "simulation": False,
                "engine": {"active": True},
                "bouncer": {"active": True},
                "configuration": {"qualified": True},
                "firewall": {"qualified": True},
            },
        )
        response = self.client.get("/security/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Degraded; last snapshot retained", response.content.decode())
        self.assertNotIn("Decisions current", response.content.decode())

    def test_mapped_host_search_normalizes_but_mapped_cidr_preserves_its_family(self) -> None:
        self.decision(1, "198.51.100.8")
        self.decision(2, "::ffff:c633:6408/125")
        host = self.client.get("/security/", {"address": "::ffff:c633:6408"})
        self.assertIn("decision-1", host.content.decode())
        self.assertNotIn("decision-2", host.content.decode())
        network = self.client.get("/security/", {"address": "::ffff:c633:6408/125"})
        self.assertIn("decision-2", network.content.decode())
        self.assertNotIn("decision-1", network.content.decode())

    def test_decision_origin_is_visible_and_filterable(self) -> None:
        native = self.decision(1, "198.51.100.8")
        manual = self.decision(2, "198.51.100.9")
        manual.origin = "cscli"
        manual.save(update_fields=["origin"])
        response = self.client.get("/security/", {"origin": "cscli"})
        self.assertEqual([row.pk for row in response.context["security_page"]], [manual.pk])
        self.assertContains(response, "cscli")
        self.assertNotContains(response, native.scenario)
