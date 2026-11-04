"""Staff actions persist audited intent; all host work remains in background tasks."""

from __future__ import annotations

from dataclasses import asdict
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import Client, TestCase, override_settings

from apps.security.action_forms import CoverageForm
from apps.security.addresses import address_bounds
from apps.security.models import SecurityActionRequest, SecurityActionTarget, SecurityAllowlist, SecurityDecision
from apps.users.models import User
from tests.security.action_fixtures import ActionFixture


@override_settings(PRAHO_CROWDSEC_ACTIONS_ENABLED=True)
class SecurityActionViewTests(ActionFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.client.force_login(self.admin)

    def ban(self) -> dict[str, object]:
        return {
            "idempotency_key": str(uuid4()),
            "sources": [str(self.source.pk)],
            "address": "198.51.100.8",
            "duration_seconds": "14400",
            "reason": "Confirmed administrative attack",
        }

    def test_ban_post_records_once_and_never_calls_a_host(self) -> None:
        payload = self.ban()
        with patch("apps.security.action_transport.call", side_effect=AssertionError("Host I/O during request")):
            first = self.client.post("/security/actions/ban/", payload)
            self.assertEqual(first.status_code, 302)
            self.assertEqual(self.client.post("/security/actions/ban/", payload).status_code, 302)
            detail = self.client.get(first.url)
            self.assertEqual(detail.status_code, 200)
            self.assertContains(detail, "198.51.100.8")
        self.assertEqual(SecurityActionRequest.objects.count(), 1)
        target = SecurityActionTarget.objects.get()
        self.assertIsNone(target.dispatched_at)
        self.assertEqual(target.expires_at, target.action.created_at + timedelta(minutes=5))

    def test_support_and_managers_can_revoke_but_cannot_ban(self) -> None:
        decision = SecurityDecision.objects.create(
            source=self.source,
            remote_id=1,
            source_created_at=self.now,
            expires_at=self.now + timedelta(minutes=5),
            scenario="crowdsecurity/ssh-bf",
            type="ban",
            scope="ip",
            value="198.51.100.8",
            origin="crowdsec",
            **asdict(address_bounds("ip", "198.51.100.8")),
        )
        for role in ("support", "manager"):
            with self.subTest(role=role):
                user = User.objects.create_user(email=f"action-ui-{role}@example.test", staff_role=role, is_staff=True)
                self.client.force_login(user)
                self.assertEqual(self.client.get("/security/actions/ban/").status_code, 403)
                self.assertEqual(self.client.post("/security/actions/ban/", self.ban()).status_code, 403)
                response = self.client.post(
                    f"/security/decisions/{decision.pk}/revoke/",
                    {"reason": "Verified customer address", "idempotency_key": str(uuid4())},
                )
                self.assertEqual(response.status_code, 302)
                self.assertEqual(self.client.get(response.url).status_code, 200)
        self.assertEqual(SecurityActionRequest.objects.filter(kind="revoke").count(), 2)

    def test_billing_cannot_read_results_or_issue_any_action(self) -> None:
        action = self.issue()
        user = User.objects.create_user(email="action-ui-billing@example.test", staff_role="billing", is_staff=True)
        self.client.force_login(user)
        for url in (
            f"/security/actions/{action.pk}/",
            "/security/actions/ban/",
            f"/security/sources/{self.source.pk}/allowlist/",
            f"/security/sources/{self.source.pk}/coverage/",
        ):
            self.assertEqual(self.client.get(url).status_code, 403)

    def test_csrf_and_required_reason_prevent_mutation(self) -> None:
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        self.assertEqual(client.post("/security/actions/ban/", self.ban()).status_code, 403)
        payload = self.ban()
        payload["reason"] = ""
        self.assertEqual(self.client.post("/security/actions/ban/", payload).status_code, 400)
        self.assertFalse(SecurityActionRequest.objects.exists())

    def test_complete_allowlist_is_persisted_with_pending_target_result(self) -> None:
        response = self.client.post(
            f"/security/sources/{self.source.pk}/allowlist/",
            {
                "cidrs": "198.51.100.0/24\n2001:db8::/64",
                "reason": "Protect approved customer networks",
                "idempotency_key": str(uuid4()),
                "expected_revision": "0",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(SecurityAllowlist.objects.get(source=self.source).cidrs, ["198.51.100.0/24", "2001:db8::/64"])
        self.assertContains(self.client.get(response.url), "Pending")

    def test_unknown_results_are_explicit_and_detail_rendering_is_read_only(self) -> None:
        action = self.issue()
        SecurityActionTarget.objects.filter(action=action).update(
            state="unknown", evidence={"evidence": "mutation_uncertain"}
        )
        action.status = "unknown"
        action.save(update_fields=["status"])
        with patch("apps.security.action_transport.call", side_effect=AssertionError("RPC during result rendering")):
            response = self.client.get(f"/security/actions/{action.pk}/")
        self.assertContains(response, "Unknown")
        self.assertContains(response, "may have applied")

    def test_unqualified_coverage_proof_is_rejected(self) -> None:
        response = self.client.post(
            f"/security/sources/{self.source.pk}/coverage/",
            {
                "scenarios": ["crowdsecurity/http-cve-2021-41773"],
                "evidence_digest": "e" * 64,
                "native_evidence": '{"schema":1}',
                "reason": "Review incomplete evidence",
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_target_rejection_explains_protected_network_overlap(self) -> None:
        action = self.issue()
        SecurityActionTarget.objects.filter(action=action).update(
            state="rejected", evidence={"evidence": "protected_overlap"}
        )
        response = self.client.get(f"/security/actions/{action.pk}/")
        self.assertContains(response, "Overlaps an inventory protected network")

    def test_stale_allowlist_form_cannot_remove_a_newer_approved_network(self) -> None:
        url = f"/security/sources/{self.source.pk}/allowlist/"
        first = {
            "cidrs": "198.51.100.0/24",
            "reason": "First reviewed list",
            "idempotency_key": str(uuid4()),
            "expected_revision": "0",
        }
        self.assertEqual(self.client.post(url, first).status_code, 302)
        stale = {**first, "cidrs": "2001:db8::/64", "reason": "Older review tab", "idempotency_key": str(uuid4())}
        self.assertEqual(self.client.post(url, stale).status_code, 400)
        self.assertEqual(SecurityAllowlist.objects.get(source=self.source).cidrs, ["198.51.100.0/24"])
        self.assertEqual(self.client.post(url, first).status_code, 302)

    def test_action_history_filters_unknown_results_and_never_calls_a_host(self) -> None:
        unknown, pending = self.issue(), self.issue()
        SecurityActionRequest.objects.filter(pk=unknown.pk).update(status="unknown")
        with patch("apps.security.action_transport.call", side_effect=AssertionError("RPC during history rendering")):
            response = self.client.get("/security/actions/", {"state": "unknown"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f"/security/actions/{unknown.pk}/")
        self.assertNotContains(response, f"/security/actions/{pending.pk}/")
        self.assertEqual(self.client.get("/security/actions/", {"state": "unrecognized"}).status_code, 400)

    def test_coverage_form_refuses_duplicate_json_proof_facts(self) -> None:
        form = CoverageForm(
            {
                "reason": "Review contradictory proof",
                "scenarios": ["crowdsecurity/http-cve-2021-41773"],
                "evidence_digest": "e" * 64,
                "native_evidence": '{"schema":1,"schema":1}',
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("native_evidence", form.errors)
