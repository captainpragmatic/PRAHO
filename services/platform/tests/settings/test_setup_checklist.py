"""Fresh installations get actionable configuration guidance, not dead ends."""

import json
import re
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from apps.common.status_observations import Observation, claim_check, finish_check
from apps.common.system_status import node_input_identity
from apps.common.types import Ok
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.settings.setup_checklist import evaluate_setup
from tests.factories.core_factories import create_admin_user, create_staff_user


class SetupChecklistPagesTests(TestCase):
    def test_django_admin_does_not_evaluate_application_setup(self) -> None:
        from types import SimpleNamespace  # noqa: PLC0415

        from django.test import RequestFactory  # noqa: PLC0415

        from apps.common.context_processors import setup_attention  # noqa: PLC0415

        request = RequestFactory().get("/admin/")
        request.user = self.admin
        request.resolver_match = SimpleNamespace(namespaces=["admin"])
        with patch("apps.settings.setup_checklist.get_setup_report") as report:
            self.assertEqual(setup_attention(request), {})
        report.assert_not_called()

    def setUp(self) -> None:
        self.admin = create_admin_user(username="setup_admin")
        self.client.force_login(self.admin)

    def test_setup_page_explains_requirements_and_links_to_canonical_settings(self) -> None:
        response = self.client.get("/settings/setup/")
        self.assertContains(response, "Setup checklist")
        self.assertContains(response, "Required")
        self.assertContains(response, "/settings/company/?return_to=setup#setting-company.legal_name")
        self.assertContains(response, "Optional")
        self.assertContains(response, "favicon")

    def test_setup_is_admin_only(self) -> None:
        self.client.force_login(create_staff_user(username="setup_support", staff_role="support"))
        response = self.client.get("/settings/setup/")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(b"S3", response.content)

    def test_existing_settings_pages_show_setup_reminder_and_exact_anchors(self) -> None:
        response = self.client.get("/settings/company/")
        self.assertContains(response, "Setup checklist")
        self.assertContains(response, 'id="setting-company.legal_name"')

    @patch("apps.infrastructure.views.SettingsService.get_setting", side_effect=lambda key, default=None: default)
    def test_missing_dns_shows_prerequisites_before_a_deployment_is_created(self, _setting) -> None:
        response = self.client.get("/infrastructure/deployments/create/")
        self.assertContains(response, "Before you deploy")
        self.assertContains(response, "/settings/node-deployment/?return_to=node-deploy#setting-node_deployment.dns_default_zone")

    @patch("apps.infrastructure.views.SettingsService.get_setting", side_effect=lambda key, default=None: default)
    def test_blocked_node_creation_preserves_choices_and_never_credentials(self, _setting) -> None:
        self.client.post("/infrastructure/deployments/create/", {"environment": "staging", "display_name": "My staging node", "api_token": "private-token"})
        draft = self.client.session["node_deployment_draft"]
        self.assertEqual(draft["values"]["environment"], "staging")
        self.assertEqual(draft["values"]["display_name"], "My staging node")
        self.assertNotIn("private-token", str(draft))

    def test_system_status_has_details_without_running_probes_on_get(self) -> None:
        with patch("apps.common.system_status.check_all_subsystems") as probes:
            response = self.client.get("/system-status/")
        self.assertContains(response, "System Status")
        self.assertContains(response, "Last")
        probes.assert_not_called()

    def test_manual_status_refresh_queues_one_check_instead_of_calling_providers(self) -> None:
        cache.clear()
        with patch("django_q.tasks.async_task", return_value="queued") as queue, patch("apps.common.system_status.check_all_subsystems") as probes:
            response = self.client.post("/dashboard/system-status/refresh/")
        self.assertContains(response, "queued")
        queue.assert_called_once()
        probes.assert_not_called()

    def test_node_dns_test_verifies_zone_access_without_creating_records(self) -> None:
        configured = {"node_deployment.dns_cloudflare_api_token": "fixture-token", "node_deployment.dns_cloudflare_zone_id": "a" * 32, "node_deployment.dns_default_zone": "nodes.example.test"}
        with patch("apps.settings.services.SettingsService.get_setting", side_effect=lambda key, default=None: configured.get(key, default)), patch("apps.infrastructure.dns_gateway.CloudflareDnsGateway.get_zone_name", return_value=Ok("example.test")) as lookup, patch("apps.infrastructure.dns_gateway.CloudflareDnsGateway.reconcile_records") as mutate:
            response = self.client.post("/settings/test/node-deployment/")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])
        lookup.assert_called_once_with("a" * 32)
        mutate.assert_not_called()

    def test_node_configuration_invalidates_setup_only_after_commit(self) -> None:
        with patch("apps.settings.setup_checklist.clear_setup_cache") as invalidate:
            with self.captureOnCommitCallbacks(execute=True):
                VirtualminServer.objects.create(name="Imported server", hostname="node.example.test", api_username="root", encrypted_api_password=b"")
                invalidate.assert_not_called()
            invalidate.assert_called_once()

    def test_node_status_refresh_queues_only_that_node_and_never_runs_a_probe_in_request(self) -> None:
        node = VirtualminServer.objects.create(name="Detailed node", hostname="details.example.test", api_username="root", encrypted_api_password=b"")
        with patch("django_q.tasks.async_task", return_value="queued") as queue, patch("apps.provisioning.virtualmin_service.VirtualminServerManagementService.health_check_server") as probe:
            response = self.client.post(f"/system-status/nodes/{node.pk}/refresh/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, f"/system-status/?node={node.pk}")
        self.assertEqual(queue.call_args.args, ("apps.provisioning.virtualmin_tasks.refresh_virtualmin_node_status", str(node.pk)))
        probe.assert_not_called()

    def test_imported_backup_transport_is_an_explicit_setup_requirement(self) -> None:
        VirtualminServer.objects.create(name="Imported", hostname="imported.example.test", api_username="root", encrypted_api_password=b"")
        items = {item.key: item for section in evaluate_setup().sections for item in section.items}
        self.assertIn("backup_transport", items)
        self.assertFalse(items["backup_transport"].configured)
        self.assertIn("private key", items["backup_transport"].description)

    def test_edited_node_credentials_are_unknown_before_the_next_background_check(self) -> None:
        node = VirtualminServer.objects.create(name="Configured node", hostname="configured.example.test", api_username="root", encrypted_api_password=b"")
        identity = node_input_identity(node)
        claim = claim_check("virtualmin", node_id=node.pk, identity=identity)
        assert claim is not None
        self.assertTrue(finish_check(claim, identity=identity, observation=Observation("green", "connected")))
        before = self.client.get(f"/system-status/?node={node.pk}")
        self.assertEqual(before.context["rows"][0]["level"], "green")
        node.api_username = "replacement"
        node.save(update_fields=["api_username"])
        after = self.client.get(f"/system-status/?node={node.pk}")
        self.assertEqual(after.context["rows"][0]["level"], "unknown")

    def test_returned_node_form_seeds_staging_instead_of_defaulting_to_production(self) -> None:
        session = self.client.session
        session["node_deployment_draft"] = {"created_at": timezone.now().timestamp(), "values": {
            "environment": "stg", "node_type": "sha", "provider": "17", "region": "19", "node_size": "23",
            "display_name": "My staging box", "backup_enabled": False,
        }}
        session.save()
        with patch("apps.infrastructure.views.deployment_configuration_issues", return_value=[]), patch("apps.infrastructure.views.SettingsService.get_setting", side_effect=lambda key, default=None: "nodes.example.test" if key == "node_deployment.dns_default_zone" else default):
            response = self.client.get("/infrastructure/deployments/create/")
        self.assertContains(response, 'id="deployment-form-data"')
        match = re.search(r'<script id="deployment-form-data" type="application/json">(.*?)</script>', response.content.decode(), re.S)
        self.assertIsNotNone(match)
        state = json.loads(match.group(1))
        self.assertEqual(state["environment"], "stg")
        self.assertEqual((state["provider"], state["region"], state["node_size"]), ("17", "19", "23"))
        self.assertContains(response, 'value="My staging box"')
        backup = re.search(r'<input[^>]*name="backup_enabled"[^>]*>', response.content.decode())
        self.assertIsNotNone(backup)
        self.assertNotIn("checked", backup.group(0))
