"""Staff maintenance forms use real permissions, CSRF and the audited public services."""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import patch

from django.test import Client, SimpleTestCase, TestCase
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import override, trans_real
from freezegun import freeze_time

from apps.common.types import Ok
from apps.infrastructure.node_maintenance_execution import claim_direct_operation
from apps.infrastructure.node_maintenance_forms import (
    NodeMaintenancePolicyForm,
    NodeMaintenanceReconcileForm,
    NodeMaintenanceWindowForm,
)
from apps.infrastructure.node_maintenance_models import (
    NodeMaintenanceExecution,
    NodeMaintenancePolicy,
    NodeMaintenanceWindow,
)
from apps.infrastructure.provider_config import ProviderCommandResult
from apps.users.models import User
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture


@contextmanager
def hostile_catalog_messages(messages: dict[str, str]) -> Iterator[None]:
    """Change only the translation catalog boundary; request/business authority stays real."""
    with override("en"):
        catalog = trans_real._active.value
        original = catalog.gettext
        with patch.object(catalog, "gettext", side_effect=lambda message: messages.get(message, original(message))):
            yield


class NodeMaintenanceModeFormTests(SimpleTestCase):
    def test_declared_form_labels_are_localized_instead_of_implicit_english_names(self):
        with override("ro"):
            self.assertEqual(str(NodeMaintenancePolicyForm().fields["weekdays"].label), "Zilele permise ale săptămânii")
            window_form = NodeMaintenanceWindowForm()
            self.assertEqual(str(window_form.fields["kind"].label), "Tipul mentenanței")
            self.assertEqual(str(window_form.fields["execution_mode"].label), "Modul de execuție")
            direct_form = NodeMaintenanceReconcileForm()
            self.assertEqual(
                str(direct_form.fields["commands_stopped"].label),
                "Confirm că nu mai rulează comenzi pentru această operațiune înregistrată.",
            )
            self.assertEqual(str(direct_form.fields["outcome"].choices[0][1]), "Rezultat verificat")

    def body(self, kind, mode, downtime=True):
        return {
            "kind": kind,
            "execution_mode": mode,
            "starts_at": "2026-11-02T12:00:00Z",
            "ends_at": "2026-11-02T12:30:00Z",
            "expects_downtime": "on" if downtime else "",
            "customer_note": "Planned customer impact.",
        }

    def test_a_notice_kind_cannot_be_borrowed_for_another_automated_action(self):
        for kind, mode in (("reboot", "security"), ("panel_update", "reboot"), ("panel_update", "security")):
            with self.subTest(kind=kind, mode=mode):
                form = NodeMaintenanceWindowForm(self.body(kind, mode))
                self.assertFalse(form.is_valid())
                self.assertIn("execution_mode", form.errors)

    def test_provider_restart_cannot_claim_that_no_downtime_is_expected(self):
        form = NodeMaintenanceWindowForm(self.body("reboot", "reboot", downtime=False))
        self.assertFalse(form.is_valid())
        self.assertIn("expects_downtime", form.errors)

    def test_supported_pairs_and_operator_managed_impact_remain_available(self):
        for kind, mode, downtime in (
            ("reboot", "manual", False),
            ("panel_update", "manual", False),
            ("reboot", "reboot", True),
        ):
            with self.subTest(kind=kind, mode=mode, downtime=downtime):
                form = NodeMaintenanceWindowForm(self.body(kind, mode, downtime))
                self.assertTrue(form.is_valid(), form.errors)


class NodeMaintenanceDirectViewsTests(MaintenanceAdmissionFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.actor)

    def operation(self, *, bound=True, issue=True):
        deployment = _create_deployment("completed", external_node_id="recorded-direct-resource")
        if bound:
            deployment.virtualmin_server = self.node
            deployment.save(update_fields=["virtualmin_server"])
        if issue:
            with patch(
                "apps.infrastructure.deployment_service.run_provider_command",
                return_value=Ok(ProviderCommandResult(True, "", "", 0, "fixture")),
            ):
                result = _make_service().reboot_node(deployment, {}, user=self.actor)
            self.assertTrue(result.is_ok(), result)
        else:
            self.assertTrue(claim_direct_operation(deployment, "reboot").is_ok())
        return deployment, NodeMaintenanceExecution.objects.get(deployment=deployment)

    def reconcile_url(self, execution):
        return reverse("infrastructure:maintenance_execution_reconcile", args=[execution.pk])

    def body(self, **changes):
        return {
            "expected_phase": "awaiting_recovery",
            "outcome": "verified",
            "reason": "Checked the actual recorded target.",
            "commands_stopped": "on",
            "resource_confirmed": "on",
            **changes,
        }

    def test_node_review_shows_readonly_target_and_consent_without_exposing_a_claim_token(self):
        _, execution = self.operation()
        page = self.client.get(reverse("infrastructure:maintenance_policy", args=[self.node.pk]))
        self.assertContains(page, "Review pending node operations")
        self.assertContains(page, "recorded-direct-resource")
        self.assertContains(page, self.reconcile_url(execution))
        self.assertContains(page, "commands_stopped")
        self.assertContains(page, "resource_confirmed")
        self.assertNotContains(page, str(execution.token))
        self.assertNotContains(page, 'name="provider_resource_id"')

    def test_unbound_deployment_still_exposes_its_existing_direct_operation_review(self):
        deployment, execution = self.operation(bound=False)
        page = self.client.get(reverse("infrastructure:deployment_detail", args=[deployment.pk]))
        self.assertContains(page, "Review pending node operations")
        self.assertContains(page, self.reconcile_url(execution))
        self.assertNotContains(page, str(execution.token))

    def test_actual_operator_reconciliation_finishes_only_the_existing_row_without_provider_io(self):
        deployment, execution = self.operation()
        with patch("apps.infrastructure.deployment_service.run_provider_command") as provider:
            response = self.client.post(self.reconcile_url(execution), self.body())
        self.assertRedirects(
            response, reverse("infrastructure:deployment_detail", args=[deployment.pk]), fetch_redirect_response=False
        )
        self.assertEqual(NodeMaintenanceExecution.objects.get(pk=execution.pk).phase, "verified")
        self.assertEqual(NodeMaintenanceExecution.objects.count(), 1)
        provider.assert_not_called()

    def test_stale_phase_and_missing_independent_attestation_do_not_release_the_owner(self):
        _, execution = self.operation()
        for changes in ({"expected_phase": "issued"}, {"commands_stopped": ""}, {"resource_confirmed": ""}):
            with self.subTest(changes=changes):
                response = self.client.post(self.reconcile_url(execution), self.body(**changes))
                self.assertEqual(response.status_code, 400)
                self.assertEqual(NodeMaintenanceExecution.objects.get(pk=execution.pk).phase, "awaiting_recovery")

    def test_changed_resource_cannot_be_accepted_by_posting_a_replacement_identity(self):
        deployment, execution = self.operation(bound=False)
        deployment.external_node_id = "different-resource"
        deployment.save(update_fields=["external_node_id"])
        response = self.client.post(self.reconcile_url(execution), self.body(provider_resource_id="different-resource"))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(NodeMaintenanceExecution.objects.get(pk=execution.pk).phase, "awaiting_recovery")

    def test_real_reconciliation_refusals_remain_plain_text_with_hostile_catalog_content(self):
        deployment, execution = self.operation(bound=False)
        hostile = '<img src=x onerror="window.catalogBoundary=1">'
        for changed_resource in (False, True):
            with self.subTest(changed_resource=changed_resource):
                if changed_resource:
                    deployment.external_node_id = "changed-after-review"
                    deployment.save(update_fields=["external_node_id"])
                message = (
                    "The recorded resource binding changed. Do not release this hold without manual review."
                    if changed_resource
                    else "This execution changed. Reload and review its current phase."
                )
                body = self.body(expected_phase="awaiting_recovery" if changed_resource else "issued")
                with hostile_catalog_messages({message: hostile}):
                    response = self.client.post(self.reconcile_url(execution), body)
                self.assertEqual(response.status_code, 400)
                self.assertIn(hostile, response.content.decode())
                self.assertEqual(NodeMaintenanceExecution.objects.get(pk=execution.pk).phase, "awaiting_recovery")
                self.assertEqual(response.headers["Content-Type"].split(";", 1)[0], "text/plain")
                self.assertEqual(response.charset.casefold(), "utf-8")

    def test_active_administrators_and_managers_can_record_a_checked_failure(self):
        for role in ("admin", "manager"):
            with self.subTest(role=role):
                _, execution = self.operation(bound=False)
                actor = User.objects.create_user(email=f"direct-{role}@example.test", staff_role=role, is_staff=True)
                self.client.force_login(actor)
                response = self.client.post(self.reconcile_url(execution), self.body(outcome="failed"))
                self.assertEqual(response.status_code, 302)
                self.assertEqual(NodeMaintenanceExecution.objects.get(pk=execution.pk).phase, "failed")

    def test_customer_and_inactive_staff_cannot_release_an_execution(self):
        _, execution = self.operation(bound=False)
        for actor in (
            User.objects.create_user(email="direct-customer@example.test"),
            User.objects.create_user(
                email="direct-inactive@example.test", staff_role="admin", is_staff=True, is_active=False
            ),
        ):
            with self.subTest(actor=actor.email):
                self.client.force_login(actor)
                self.assertIn(self.client.post(self.reconcile_url(execution), self.body()).status_code, (302, 403))
                self.assertEqual(NodeMaintenanceExecution.objects.get(pk=execution.pk).phase, "awaiting_recovery")

    def test_claimed_operation_can_only_be_recorded_as_not_run(self):
        _, execution = self.operation(issue=False)
        response = self.client.post(self.reconcile_url(execution), self.body(expected_phase="claimed"))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(NodeMaintenanceExecution.objects.get(pk=execution.pk).phase, "claimed")
        response = self.client.post(
            self.reconcile_url(execution), self.body(expected_phase="claimed", outcome="failed")
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(NodeMaintenanceExecution.objects.get(pk=execution.pk).phase, "failed")

    def test_support_reads_pending_identity_but_cannot_reconcile(self):
        deployment, execution = self.operation(bound=False)
        support = User.objects.create_user(
            email="direct-review-support@example.test", staff_role="support", is_staff=True
        )
        self.client.force_login(support)
        page = self.client.get(reverse("infrastructure:deployment_detail", args=[deployment.pk]))
        self.assertContains(page, "Review pending node operations")
        self.assertContains(page, "recorded-direct-resource")
        self.assertNotContains(page, 'name="commands_stopped"')
        self.assertEqual(self.client.post(self.reconcile_url(execution), self.body()).status_code, 403)

    def test_real_csrf_is_required_and_actual_form_token_can_finish_the_exact_operation(self):
        deployment, execution = self.operation(bound=False)
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.actor)
        path = self.reconcile_url(execution)
        self.assertEqual(client.post(path, self.body()).status_code, 403)
        self.assertEqual(client.get(reverse("infrastructure:deployment_detail", args=[deployment.pk])).status_code, 200)
        response = client.post(path, self.body(csrfmiddlewaretoken=client.cookies["csrftoken"].value))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(NodeMaintenanceExecution.objects.get(pk=execution.pk).phase, "verified")


class NodeMaintenanceViewsTests(MaintenanceAdmissionFixture, TestCase):
    def setUp(self) -> None:
        clock = freeze_time("2026-11-02 12:00:00+00:00")
        self.clock = clock.start()
        self.addCleanup(clock.stop)
        super().setUp()
        self.actor.profile.preferred_language = "en"
        self.actor.profile.save(update_fields=["preferred_language"])
        self.client.force_login(self.actor)
        self.policy_url = reverse("infrastructure:maintenance_policy", args=[self.node.pk])
        self.create_url = reverse("infrastructure:maintenance_create", args=[self.node.pk])

    def policy_body(self, **changes):
        return {
            "timezone": "UTC",
            "weekdays": [str(day) for day in range(7)],
            "starts_time": "00:00",
            "ends_time": "23:59",
            "max_defer_minutes": "30",
            "revision": "1",
            **changes,
        }

    def action_url(self, window, action):
        return reverse("infrastructure:maintenance_action", args=[window.pk, action])

    def test_action_refusals_remain_plain_text_with_hostile_catalog_content(self):
        window = self.window()
        hostile = '<img src=x onerror="window.catalogBoundary=1">'
        cases = (
            ("cancel", {"confirmation": ""}, "Review and confirm the maintenance impact before continuing."),
            ("unsupported", {}, "Choose a supported maintenance action."),
            ("cancel", {"revision": "2"}, "This window changed. Reload and review the current revision."),
        )
        for action, changes, message in cases:
            with self.subTest(action=action, changes=changes):
                body = {"revision": "1", "reason": "Request error contract", "confirmation": "on", **changes}
                with hostile_catalog_messages({message: hostile}):
                    response = self.client.post(self.action_url(window, action), body)
                self.assertEqual(response.status_code, 400)
                self.assertIn(hostile, response.content.decode())
                self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "scheduled")
                self.assertEqual(response.headers["Content-Type"].split(";", 1)[0], "text/plain")
                self.assertEqual(response.charset.casefold(), "utf-8")

    def test_stale_policy_revision_cannot_overwrite_a_newer_operator_decision(self):
        first = self.client.post(self.policy_url, self.policy_body())
        self.assertEqual(first.status_code, 302)
        self.assertEqual(NodeMaintenancePolicy.objects.get(node=self.node).revision, 2)

        stale = self.client.post(self.policy_url, self.policy_body(timezone="Europe/Bucharest"))

        self.assertEqual(stale.status_code, 200)
        policy = NodeMaintenancePolicy.objects.get(node=self.node)
        self.assertEqual(policy.revision, 2)
        self.assertEqual(policy.timezone, "UTC")
        self.assertContains(stale, "policy changed")

    def test_first_policy_post_preserves_the_existing_public_create_contract(self):
        NodeMaintenancePolicy.objects.filter(node=self.node).delete()
        body = self.policy_body()
        body.pop("revision")
        response = self.client.post(self.policy_url, body)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(NodeMaintenancePolicy.objects.get(node=self.node).revision, 1)

    def test_existing_policy_update_requires_the_reviewed_revision(self):
        body = self.policy_body()
        body.pop("revision")
        response = self.client.post(self.policy_url, body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(NodeMaintenancePolicy.objects.get(node=self.node).revision, 1)

    def test_browser_cannot_schedule_using_a_policy_preview_superseded_by_another_operator(self):
        frame = self.client.get(self.create_url)
        self.assertEqual(frame.context["form"].initial["policy_revision"], 1)
        update = self.client.post(self.policy_url, self.policy_body(max_defer_minutes="45"))
        self.assertEqual(update.status_code, 302)
        response = self.client.post(
            self.create_url,
            {
                "kind": "panel_update",
                "execution_mode": "manual",
                "policy_revision": "1",
                "starts_at": "2026-11-02T12:10:00Z",
                "ends_at": "2026-11-02T12:40:00Z",
                "expects_downtime": "on",
                "customer_note": "Reviewed against the earlier policy.",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(NodeMaintenanceWindow.objects.exists())
        self.assertContains(response, "policy changed")

    def test_preview_counts_tracked_accounts_and_distinct_customers_without_native_io(self):
        self.account_on_node("another-maintenance.example.test")
        with patch("apps.provisioning.virtualmin_gateway.VirtualminGateway.list_domains_with_owners") as native:
            response = self.client.get(self.create_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Tracked hosting accounts: 2")
        self.assertContains(response, "Affected customers: 1")
        self.assertEqual(response.context["maintenance_account_count"], 2)
        self.assertEqual(response.context["maintenance_customer_count"], 1)
        native.assert_not_called()
        self.assertFalse(NodeMaintenanceWindow.objects.exists())

    def test_preview_names_tracked_child_domains_without_counting_them_as_customers(self):
        self.account.domains = [self.account.domain, "named-child.example.test", "<unsafe-child.example.test>"]
        self.account.save(update_fields=["domains"])
        page = self.client.get(self.create_url)
        self.assertContains(page, "named-child.example.test")
        self.assertContains(page, "&lt;unsafe-child.example.test&gt;")
        self.assertNotContains(page, "<unsafe-child.example.test>")
        self.assertEqual(page.context["maintenance_account_count"], 1)
        self.assertEqual(page.context["maintenance_customer_count"], 1)

    def test_native_named_subservers_do_not_inflate_the_node_card_account_or_customer_preview(self):
        self.account_on_node("another-maintenance.example.test")
        rows = [
            {"domain": self.account.domain, "username": "parent", "type": "Top-level server"},
            {"domain": "another-maintenance.example.test", "username": "another", "type": "Top-level server"},
            {
                "domain": "named-child.example.test",
                "username": "parent",
                "type": "Sub-server",
                "parent_domain": self.account.domain,
            },
            {
                "domain": "account-name.hosting.example.test",
                "username": "parent",
                "type": "Sub-server",
                "parent_domain": self.account.domain,
            },
        ]
        with patch(
            "apps.provisioning.virtualmin_gateway.VirtualminGateway.list_domains_with_owners", return_value=Ok(rows)
        ):
            response = self.client.get(reverse("provisioning:virtualmin_server_detail", args=[self.node.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.policy_url)
        self.assertEqual(response.context["maintenance_account_count"], 2)
        self.assertEqual(response.context["maintenance_customer_count"], 1)
        self.assertContains(response, self.policy_url)
        self.assertContains(response, "Server maintenance")

    def test_managed_deployment_detail_exposes_the_same_bound_node_maintenance_review(self):
        deployment = _create_deployment("completed")
        deployment.virtualmin_server = self.node
        deployment.save(update_fields=["virtualmin_server"])
        page = self.client.get(reverse("infrastructure:deployment_detail", args=[deployment.pk]))
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, self.policy_url)
        self.assertContains(page, "Server maintenance")
        self.assertEqual(page.context["maintenance_node"], self.node)
        self.assertEqual(page.context["maintenance_customer_count"], 1)

    def test_staff_window_times_use_viewer_zone_and_customer_note_is_plain_text(self):
        self.actor.profile.timezone = "America/New_York"
        self.actor.profile.save(update_fields=["timezone"])
        before = timezone.get_current_timezone_name()
        note = '<img src=x onerror="alert(1)">'
        response = self.client.post(
            self.create_url,
            {
                "kind": "panel_update",
                "execution_mode": "manual",
                "starts_at": (timezone.now() + timedelta(minutes=10)).isoformat(),
                "ends_at": (timezone.now() + timedelta(minutes=40)).isoformat(),
                "expects_downtime": "on",
                "expected_downtime_minutes": "5",
                "customer_note": note,
            },
        )
        self.assertEqual(response.status_code, 302)
        page = self.client.get(self.policy_url)
        self.assertContains(page, "America/New_York")
        self.assertContains(page, "07:10")
        self.assertContains(page, "&lt;img")
        self.assertNotContains(page, note)
        self.assertEqual(timezone.get_current_timezone_name(), before)

    def test_support_can_read_but_has_no_maintenance_mutation_form(self):
        support = User.objects.create_user(
            email="maintenance-support@example.test", staff_role="support", is_staff=True
        )
        self.client.force_login(support)
        response = self.client.get(self.policy_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Only administrators and managers can change maintenance")
        self.assertContains(response, "Monday")
        policy = NodeMaintenancePolicy.objects.get(node=self.node)
        self.assertContains(response, policy.ends_time.strftime("%H:%M"))
        self.assertNotContains(response, 'id="maintenance-policy-form"')
        self.assertEqual(self.client.post(self.policy_url, self.policy_body()).status_code, 403)
        self.assertEqual(NodeMaintenancePolicy.objects.get(node=self.node).revision, 1)

    def test_romanian_operator_sees_localized_policy_and_consequences(self):
        self.actor.profile.preferred_language = "ro"
        self.actor.profile.save(update_fields=["preferred_language"])
        page = self.client.get(self.policy_url)
        self.assertContains(page, "Mentenanța serverului")
        self.assertContains(page, "Luni")
        self.assertContains(page, "Amânarea maximă a începerii")
        self.assertNotContains(page, "Set how late work may begin")
        window = self.window()
        page = self.client.get(self.policy_url)
        self.assertContains(page, "anularea retrage lucrările neîncepute")
        self.assertContains(page, self.action_url(window, "cancel"))

    def test_active_admin_and_manager_can_update_a_reviewed_policy(self):
        for role in ("admin", "manager"):
            with self.subTest(role=role):
                actor = User.objects.create_user(
                    email=f"maintenance-{role}@example.test", staff_role=role, is_staff=True
                )
                self.client.force_login(actor)
                revision = NodeMaintenancePolicy.objects.get(node=self.node).revision
                response = self.client.post(self.policy_url, self.policy_body(revision=str(revision)))
                self.assertEqual(response.status_code, 302)
                policy = NodeMaintenancePolicy.objects.get(node=self.node)
                self.assertEqual(policy.updated_by_id, actor.pk)
                self.assertEqual(policy.revision, revision + 1)

    def test_customer_and_inactive_operator_cannot_mutate_policy(self):
        for actor in (
            User.objects.create_user(email="maintenance-customer@example.test"),
            User.objects.create_user(
                email="maintenance-inactive@example.test", staff_role="admin", is_staff=True, is_active=False
            ),
        ):
            with self.subTest(actor=actor.email):
                self.client.force_login(actor)
                response = self.client.post(self.policy_url, self.policy_body())
                self.assertIn(response.status_code, (302, 403))
                self.assertEqual(NodeMaintenancePolicy.objects.get(node=self.node).revision, 1)

    def test_csrf_middleware_protects_the_real_policy_post_and_accepts_its_real_form_token(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.actor)
        self.assertEqual(client.post(self.policy_url, self.policy_body()).status_code, 403)
        self.assertEqual(client.get(self.policy_url).status_code, 200)
        body = self.policy_body(csrfmiddlewaretoken=client.cookies["csrftoken"].value)
        self.assertEqual(client.post(self.policy_url, body).status_code, 302)
        self.assertEqual(NodeMaintenancePolicy.objects.get(node=self.node).revision, 2)

    def test_applicable_window_blocks_policy_changes(self):
        self.window(future=True)
        response = self.client.post(self.policy_url, self.policy_body())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(NodeMaintenancePolicy.objects.get(node=self.node).revision, 1)

    def test_start_and_finish_forms_are_rendered_with_distinct_explicit_attestation(self):
        window = self.window()
        page = self.client.get(self.policy_url)
        self.assertContains(page, self.action_url(window, "start"))
        self.assertContains(page, 'name="confirmation"')
        started = self.client.post(
            self.action_url(window, "start"),
            {
                "revision": "1",
                "reason": "Ready to begin approved work",
                "confirmation": "on",
            },
        )
        self.assertEqual(started.status_code, 302)
        page = self.client.get(self.policy_url)
        self.assertContains(page, self.action_url(window, "finish"))
        self.assertContains(page, 'name="attestation"')
        self.assertContains(page, "remote commands have stopped")
        self.assertNotContains(page, self.action_url(window, "cancel"))

    def test_finish_requires_readiness_attestation_and_records_operator_outcome(self):
        window = self.start(self.window())
        body = {
            "revision": "1",
            "reason": "Work verified",
            "confirmation": "on",
            "outcome": "completed",
            "public_outcome": "Hosting is ready.",
        }
        self.assertEqual(self.client.post(self.action_url(window, "finish"), body).status_code, 400)
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "running")
        body["attestation"] = "on"
        self.assertEqual(self.client.post(self.action_url(window, "finish"), body).status_code, 302)
        completed = NodeMaintenanceWindow.objects.get(pk=window.pk)
        self.assertEqual(completed.status, "completed")
        self.assertEqual(completed.completion_source, "operator")

    def test_move_and_cancel_forms_keep_expected_revision_and_reason(self):
        window = self.window()
        response = self.client.post(
            self.action_url(window, "move"),
            {
                "revision": "1",
                "reason": "Replace the announced time",
                "confirmation": "on",
                "starts_at": (window.starts_at + timedelta(minutes=10)).isoformat(),
                "ends_at": (window.ends_at + timedelta(minutes=10)).isoformat(),
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).revision, 2)
        self.assertEqual(
            self.client.post(
                self.action_url(window, "cancel"),
                {
                    "revision": "1",
                    "reason": "Withdraw stale decision",
                    "confirmation": "on",
                },
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                self.action_url(window, "cancel"),
                {
                    "revision": "2",
                    "reason": "Work is no longer required",
                    "confirmation": "on",
                },
            ).status_code,
            302,
        )
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "cancelled")
