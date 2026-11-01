"""The preview uses the current enrolled connection and rejects ambiguous or changed native evidence."""

import base64
import json
from types import SimpleNamespace
from unittest.mock import patch

from django.core.exceptions import ValidationError

from apps.common.types import Ok
from apps.provisioning.component_migration_inspection import collect_source_components
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_security import connection_identity
from tests.provisioning.test_component_migration_reviews import ComponentReviewTestBase


class ComponentInspectionTransportTests(ComponentReviewTestBase):
    def setUp(self):
        super().setUp()
        self.selection = {key: self.facts["source"][key] for key in ("domain_id", "domain", "owner")}
        self.selection.update(
            {"paths": [{"relative": "public_html", "purpose": "application"}], "databases": ["customer_web"]}
        )

    def result(self):
        encoded = base64.b64encode(json.dumps(self.facts).encode()).decode()
        return Ok(SimpleNamespace(success=True, stdout="PRAHO_COMPONENT_INSPECTION=" + encoded))

    @patch("apps.provisioning.component_migration_inspection.AnsibleService")
    def test_current_identity_is_owned_by_transport_and_exact_native_scope_is_returned(self, runner):
        runner.return_value.run_server_playbook.return_value = self.result()
        selected = {**self.selection, "server_uuid": "forged", "connection_identity": "forged"}
        manifest = collect_source_components(self.server, selected)
        self.assertEqual(manifest.as_json(), self.facts)
        call = runner.return_value.run_server_playbook.call_args
        self.assertEqual(call.args[:2], (self.server, "virtualmin_component.yml"))
        request = call.args[2]["component_request"]
        self.assertEqual(request["server_uuid"], str(self.server.pk))
        self.assertEqual(request["connection_identity"], connection_identity(self.server))
        self.assertEqual(call.args[2]["component_action"], "inspect")

    @patch("apps.provisioning.component_migration_inspection.AnsibleService")
    def test_connection_change_during_inspection_requires_another_preview(self, runner):
        def drift(*_args, **_kwargs):
            result = self.result()
            changed = VirtualminServer.objects.get(pk=self.server.pk)
            changed.hostname = "changed-source.example.test"
            changed.save(update_fields=["hostname", "updated_at"])
            return result

        runner.return_value.run_server_playbook.side_effect = drift
        with self.assertRaisesRegex(ValidationError, "changed"):
            collect_source_components(self.server, self.selection)

    @patch("apps.provisioning.component_migration_inspection.AnsibleService")
    def test_duplicate_evidence_or_different_native_domain_cannot_create_a_review(self, runner):
        response = self.result()
        response.unwrap().stdout += "\n" + response.unwrap().stdout
        runner.return_value.run_server_playbook.return_value = response
        with self.assertRaises(ValidationError):
            collect_source_components(self.server, self.selection)
        self.facts["source"]["domain_id"] = "999999"
        runner.return_value.run_server_playbook.return_value = self.result()
        with self.assertRaisesRegex(ValidationError, "changed"):
            collect_source_components(self.server, self.selection)
