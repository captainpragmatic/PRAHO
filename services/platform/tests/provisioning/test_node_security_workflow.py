"""Security reviews are explicit operator actions, bound to live transport evidence."""

import base64
import json
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from django.core.exceptions import ValidationError
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from apps.common.types import Ok
from apps.infrastructure.ansible_service import AnsibleResult
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_security import connection_identity, record_inspection
from apps.provisioning.virtualmin_security_execution import claim_hardening
from apps.provisioning.virtualmin_security_models import NodeSecurityExecution
from apps.provisioning.virtualmin_security_tasks import collect_inspection, review_node_security
from apps.users.models import User
from tests.provisioning.test_node_security_policy import node_policy_evidence


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class SecurityWorkflowTests(TestCase):
    def setUp(self):
        self.server = VirtualminServer.objects.create(hostname="review.example.test", api_username="root")
        self.operator = User.objects.create_superuser(email="security@example.test", password="test-password")
        self.url = reverse("provisioning:node_security", args=[self.server.pk])
        self.evidence = {
            "schema": 1,
            "identity": connection_identity(self.server),
            "versions": {"webmin": "2.670", "virtualmin": "8.3.0"},
            "listeners": ["tcp 0.0.0.0:25"],
            "principals": [{"name": "root", "access": "all"}],
            "services": ["postfix"],
            "firewall": ["allow tcp 25", *node_policy_evidence()["firewall"]],
            "proposed_changes": ["Stop public mail after evacuation"],
        }
        self.client.force_login(self.operator)

    def test_get_does_not_inspect_or_harden(self):
        with patch("apps.provisioning.virtualmin_security_views.async_task") as queue:
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Inspect current policy")
        queue.assert_not_called()

    def test_queued_task_redirect_preserves_one_encoded_task_identifier(self):
        identifier = "task/id?part=one&mode=two"
        with patch("apps.provisioning.virtualmin_security_views.async_task", return_value=identifier):
            response = self.client.post(self.url, {"action": "inspect"})
        self.assertEqual(response.status_code, 302)
        location = urlsplit(response["Location"])
        self.assertEqual(location.path, self.url)
        self.assertEqual(parse_qs(location.query), {"task": [identifier]})

    def test_invalid_action_and_denied_decision_are_plain_text_errors(self):
        response = self.client.post(self.url, {"action": "<strong>invalid</strong>"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response["Content-Type"], "text/plain; charset=utf-8")
        self.assertEqual(response.content.decode(), "Invalid security action.")
        self.operator.is_superuser = False
        self.operator.save(update_fields=["is_superuser"])
        denied = self.client.post(self.url, {"action": "acknowledge"})
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied["Content-Type"], "text/plain; charset=utf-8")
        self.assertEqual(denied.content.decode(), "Deployment permission is required.")

    def unsafe_network(self):
        evidence = self.evidence
        index = evidence["firewall"].index("PRAHO_IPV4_NAT_END") - 1
        evidence["firewall"].insert(
            index,
            "-A PREROUTING -i eth0 -d 198.51.100.9/32 -p tcp --dport 2525 -j DNAT --to-destination 10.177.0.2:8080",
        )
        return evidence

    def test_unsafe_network_refuses_before_claim_or_enrollment_and_source_acknowledgment_still_works(self):
        evidence = self.unsafe_network()
        review = record_inspection(self.server, evidence)
        with (
            patch("apps.provisioning.virtualmin_security_tasks.collect_inspection", return_value=evidence),
            patch("apps.provisioning.virtualmin_security_tasks.apply_hardening") as apply,
        ):
            result = review_node_security(
                str(self.server.pk), str(self.operator.pk), "apply", str(review.pk), "Accept service evacuation"
            )
        self.assertEqual(result["outcome"], "needs_review")
        self.assertIn("2525", result["message"])
        self.assertFalse(NodeSecurityExecution.objects.exists())
        self.server.refresh_from_db()
        self.assertIsNone(self.server.security_operation)
        self.assertEqual(self.server.api_username, "root")
        apply.assert_not_called()
        with patch("apps.provisioning.virtualmin_security_tasks.collect_inspection", return_value=evidence):
            acknowledged = review_node_security(
                str(self.server.pk),
                str(self.operator.pk),
                "acknowledge",
                str(review.pk),
                "Retain Docker forwarding for source service",
            )
        self.assertEqual(acknowledged["outcome"], "acknowledged_source_only")

    def test_get_explains_network_preparation_without_offering_conversion_or_blocking_acknowledgment(self):
        record_inspection(self.server, self.unsafe_network())
        response = self.client.get(self.url)
        self.assertContains(response, "Prepare network ingress before hardening")
        self.assertContains(response, "198.51.100.9")
        self.assertContains(response, "Keep as migration source")
        self.assertNotContains(response, "Apply reviewed hardening")

    def test_stale_verification_is_not_presented_as_current_policy(self):
        VirtualminServer.objects.filter(pk=self.server.pk).update(security_state="verified_web")
        response = self.client.get(self.url)
        self.assertContains(response, "Verification needs renewal")
        self.assertTrue(response.context["verification_stale"])

    def test_previous_input_only_policy_version_cannot_remain_destination_capable(self):
        from apps.provisioning.virtualmin_node_capability import destination_refusal  # noqa: PLC0415
        from apps.provisioning.virtualmin_security import _evidence_digest  # noqa: PLC0415
        from apps.provisioning.virtualmin_security_models import NodeSecurityReview  # noqa: PLC0415

        old = dict(self.evidence)
        old["firewall"] = old["firewall"][: old["firewall"].index("PRAHO_NETWORK_V2")]
        review = NodeSecurityReview.objects.create(
            server=self.server,
            server_uuid=self.server.pk,
            policy_version="virtualmin-web-only-v1",
            identity=connection_identity(self.server),
            digest=_evidence_digest(old),
            evidence=old,
        )
        VirtualminServer.objects.filter(pk=self.server.pk).update(
            security_state="verified_web",
            verified_security_review=review,
            current_security_review=review,
            legacy_security_admission=True,
        )
        self.server.refresh_from_db()
        self.assertIsNotNone(destination_refusal(self.server))
        response = self.client.get(self.url)
        self.assertContains(response, "Inspect again for current NAT, forwarding and topology evidence")
        self.assertNotContains(response, "Apply reviewed hardening")
        # Inspecting a once-verified rollout node must not revive grandfathered admission.
        record_inspection(self.server, self.evidence)
        self.assertIsNotNone(destination_refusal(self.server))

    def test_existing_node_admission_is_explained_separately_from_verification(self):
        VirtualminServer.objects.filter(pk=self.server.pk).update(legacy_security_admission=True)
        response = self.client.get(self.url)
        self.assertTrue(response.context["legacy_admitted"])
        self.assertContains(response, "Existing destination placement remains enabled during qualification.")

    def test_inspect_only_queues_the_read_only_action(self):
        with patch("apps.provisioning.virtualmin_security_views.async_task", return_value="task-id") as queue:
            response = self.client.post(self.url, {"action": "inspect"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(queue.call_args.args[3], "inspect")
        self.assertEqual(queue.call_args.args[1], str(self.server.pk))

    def test_explicit_acknowledgment_and_reason_are_required(self):
        with patch("apps.provisioning.virtualmin_security_views.async_task") as queue:
            response = self.client.post(self.url, {"action": "acknowledge", "reason": "preserve mail"})
        self.assertEqual(response.status_code, 400)
        queue.assert_not_called()

    def test_csrf_is_required(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        self.assertEqual(client.post(self.url, {"action": "inspect"}).status_code, 403)

    def test_apply_requires_explicit_impact_acceptance(self):
        with patch("apps.provisioning.virtualmin_security_views.async_task") as queue:
            response = self.client.post(self.url, {"action": "apply", "reason": "Services evacuated"})
        self.assertEqual(response.status_code, 400)
        queue.assert_not_called()

    def test_apply_queues_the_review_and_acceptance_for_worker_reinspection(self):
        review = record_inspection(self.server, self.evidence)
        with patch("apps.provisioning.virtualmin_security_views.async_task", return_value="task-id") as queue:
            response = self.client.post(
                self.url,
                {
                    "action": "apply",
                    "review_id": str(review.pk),
                    "reason": "Mail and DNS evacuated; accept interruption",
                    "acknowledged": "on",
                },
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(queue.call_args.args[3:5], ("apply", str(review.pk)))
        self.assertEqual(queue.call_args.kwargs["timeout"], 4200)

    def test_failed_apply_keeps_a_durable_exclusion_and_cannot_replay(self):
        review = record_inspection(self.server, self.evidence)
        with (
            patch("apps.provisioning.virtualmin_security_tasks.collect_inspection", return_value=self.evidence),
            patch(
                "apps.provisioning.virtualmin_security_tasks.apply_hardening",
                side_effect=ValidationError("Unknown remote outcome"),
            ) as apply,
        ):
            first = review_node_security(
                str(self.server.pk), str(self.operator.pk), "apply", str(review.pk), "Accept reviewed impact"
            )
            second = review_node_security(str(self.server.pk), str(self.operator.pk), "apply", str(review.pk), "Retry")
        self.assertEqual((first["outcome"], second["outcome"]), ("needs_review", "needs_review"))
        apply.assert_called_once()
        run = NodeSecurityExecution.objects.get()
        self.server.refresh_from_db()
        self.assertEqual(run.status, "needs_review")
        self.assertEqual(self.server.security_operation, run.pk)

    def test_verification_never_replays_or_reconciles_an_active_worker(self):
        review = record_inspection(self.server, self.evidence)
        claim_hardening(review, self.evidence, self.operator, "Accept reviewed interruption")
        with (
            patch("apps.provisioning.virtualmin_security_tasks.collect_inspection", return_value=self.evidence),
            patch("apps.provisioning.virtualmin_security_tasks.apply_hardening") as apply,
        ):
            result = review_node_security(
                str(self.server.pk), str(self.operator.pk), "verify", reason="Commands stopped"
            )
        self.assertEqual(result["outcome"], "needs_review")
        apply.assert_not_called()

    def test_verification_requires_confirmation_that_remote_work_stopped(self):
        with patch("apps.provisioning.virtualmin_security_views.async_task") as queue:
            response = self.client.post(self.url, {"action": "verify", "reason": "Inspected"})
        self.assertEqual(response.status_code, 400)
        queue.assert_not_called()

    def test_worker_records_observation_without_service_changes(self):
        with patch("apps.provisioning.virtualmin_security_tasks.collect_inspection", return_value=self.evidence):
            result = review_node_security(str(self.server.pk), str(self.operator.pk), "inspect")
        self.server.refresh_from_db()
        self.assertEqual(result["outcome"], "inspected")
        self.assertEqual(self.server.api_username, "root")
        self.assertEqual(self.server.security_state, "unreviewed")
        self.assertEqual(self.server.current_security_review.evidence["services"], ["postfix"])

    def test_worker_reinspects_before_acknowledgment(self):
        with patch("apps.provisioning.virtualmin_security_tasks.collect_inspection", return_value=self.evidence):
            result = review_node_security(str(self.server.pk), str(self.operator.pk), "inspect")
        changed = {**self.evidence, "listeners": ["tcp 0.0.0.0:25", "tcp 0.0.0.0:110"]}
        with patch("apps.provisioning.virtualmin_security_tasks.collect_inspection", return_value=changed):
            result = review_node_security(
                str(self.server.pk), str(self.operator.pk), "acknowledge", result["review_id"], "Keep mail"
            )
        self.assertEqual(result["outcome"], "needs_review")
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_state, "unreviewed")

    def test_collector_binds_the_actual_administrative_networks(self):
        encoded = base64.b64encode(json.dumps(self.evidence).encode()).decode()
        response = AnsibleResult(True, "virtualmin_security_read.yml", "PRAHO_SECURITY_INSPECTION=" + encoded, "", 0)
        with (
            patch("apps.provisioning.virtualmin_security_tasks.AnsibleService") as transport,
            patch(
                "apps.provisioning.virtualmin_security_tasks.node_admin_allowed_cidrs", return_value=["192.0.2.1/32"]
            ),
        ):
            transport.return_value.run_server_playbook.return_value = Ok(response)
            evidence = collect_inspection(self.server)
        self.assertIn("Administrative networks: 192.0.2.1/32", evidence["proposed_changes"])
        self.assertFalse([line for line in evidence["proposed_changes"] if line.startswith("Warning:")])

    def test_collector_warns_when_platform_egress_is_outside_the_administrative_networks(self):
        encoded = base64.b64encode(json.dumps(self.evidence).encode()).decode()
        response = AnsibleResult(True, "virtualmin_security_read.yml", "PRAHO_SECURITY_INSPECTION=" + encoded, "", 0)
        with (
            patch("apps.provisioning.virtualmin_security_tasks.AnsibleService") as transport,
            patch(
                "apps.provisioning.virtualmin_security_tasks.node_admin_allowed_cidrs", return_value=["192.0.2.1/32"]
            ),
            patch(
                "apps.provisioning.virtualmin_security_tasks.uncovered_platform_egress",
                return_value=["2a01:4f9:c015:4d96::1"],
            ),
        ):
            transport.return_value.run_server_playbook.return_value = Ok(response)
            evidence = collect_inspection(self.server)
        proposals = evidence["proposed_changes"]
        networks = proposals.index("Administrative networks: 192.0.2.1/32")
        self.assertEqual(
            proposals[networks + 1],
            "Warning: Platform source addresses outside the administrative networks: 2a01:4f9:c015:4d96::1. "
            "The node firewall will drop Platform's connections from them.",
        )

    def test_collector_refuses_multiple_envelopes(self):
        response = AnsibleResult(
            True, "virtualmin_security_read.yml", "PRAHO_SECURITY_INSPECTION=e30= PRAHO_SECURITY_INSPECTION=e30=", "", 0
        )
        with patch("apps.provisioning.virtualmin_security_tasks.AnsibleService") as transport:
            transport.return_value.run_server_playbook.return_value = Ok(response)
            with self.assertRaises(ValidationError):
                collect_inspection(self.server)
