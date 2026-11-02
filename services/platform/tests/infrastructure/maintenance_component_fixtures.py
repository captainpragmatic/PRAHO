"""Public component admission fixture; only remote observations are substituted."""

import base64
import json
import secrets
from datetime import time
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import requests
from django.utils import timezone

from apps.common.credential_vault import CredentialData, get_credential_vault
from apps.common.types import Ok
from apps.infrastructure.ansible_service import AnsibleResult
from apps.infrastructure.node_maintenance_models import NodeMaintenancePolicy
from apps.infrastructure.registration_service import NodeRegistrationService
from apps.provisioning.component_migration_service import (
    approve_component_review,
    record_component_review,
    start_component_migration,
)
from apps.provisioning.virtualmin_gateway import VirtualminGateway
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_node_capability import destination_refusal
from apps.provisioning.virtualmin_security import acknowledge_source, connection_identity, record_inspection
from apps.settings.services import SettingsService
from tests.infrastructure.maintenance_security_fixtures import MaintenanceSecurityFixture
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment
from tests.mocks.virtualmin_mock import MockVirtualminGateway
from tests.provisioning.test_component_migration_manifest import component_manifest
from tests.provisioning.test_node_security_policy import OPERATOR_KEY


class MaintenanceComponentFixture(MaintenanceSecurityFixture):
    def setUp(self) -> None:
        super().setUp()
        private_key = Path(self.spool.name) / "source-key"
        private_key.write_text("Fixture key; SSH is an external observation boundary.\n")
        private_key.chmod(0o600)
        self.enterContext(self.settings(VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH=str(private_key)))
        for key, value in (
            ("provisioning.migration_enabled", True),
            ("provisioning.migration_spool_dir", self.spool.name),
            ("dns.account_hostnames_enabled", False),
        ):
            self.assertTrue(SettingsService.update_setting(key, value).is_ok())
        self.node.ipv4_address = "192.0.2.10"
        self.node.imported_ssh_host_keys = OPERATOR_KEY
        self.node.last_health_check = timezone.now()
        self.node.save(update_fields=["ipv4_address", "imported_ssh_host_keys", "last_health_check"])
        stored_source = get_credential_vault().store_credential(
            CredentialData(
                service_type="virtualmin",
                service_identifier=self.node.hostname,
                username=self.node.api_username,
                password=secrets.token_urlsafe(24),
            )
        )
        self.assertTrue(stored_source.is_ok(), stored_source)
        evidence = self.inspect(self.node)
        source_review = record_inspection(self.node, evidence)
        acknowledge_source(source_review, evidence, self.actor, "Retain source mail, DNS and authentication backups")
        self.node.refresh_from_db()
        self.target = VirtualminServer.objects.create(
            name="Component destination",
            hostname="component-destination.example.test",
            status="disabled",
            api_username="praho-api",
            ipv4_address="192.0.2.20",
            last_health_check=timezone.now(),
        )
        deployment = _create_deployment("completed", external_node_id="component-destination-fixture")
        deployment.virtualmin_server = self.target
        deployment.ssh_host_keys = OPERATOR_KEY
        deployment.save(update_fields=["virtualmin_server", "ssh_host_keys"])
        self.deployment = deployment
        stored = get_credential_vault().store_credential(
            CredentialData(
                service_type="virtualmin",
                service_identifier=self.target.hostname,
                username="praho-api",
                password=secrets.token_urlsafe(24),
            )
        )
        self.assertTrue(stored.is_ok(), stored)
        self._prepare_native_admission()

    def _prepare_native_admission(self) -> None:
        self.native_source = MockVirtualminGateway(self.node.hostname)
        self.native_target = MockVirtualminGateway(self.target.hostname)
        self.native = {self.node.hostname: self.native_source, self.target.hostname: self.native_target}

        def http(gateway: VirtualminGateway, params: dict[str, object], **kwargs: object) -> requests.Response:
            result = self.native[gateway.server.hostname].call(
                str(params["program"]), {key: value for key, value in params.items() if key not in {"program", "json"}}
            )
            self.assertTrue(result.is_ok(), result)
            response = requests.Response()
            response.status_code = 200
            response._content = result.unwrap().raw_response.encode()
            response.raw = BytesIO(response._content)
            response._content_consumed = True
            response.headers["Content-Type"] = "application/json"
            return response

        self.http = self.enterContext(
            patch(
                "apps.provisioning.virtualmin_gateway.VirtualminGateway._execute_http_request",
                autospec=True,
                side_effect=http,
            )
        )
        # Activation keeps its real parser, evidence verifier, current identity and CAS.
        target_evidence = self.inspect(self.target)
        encoded = base64.b64encode(json.dumps(target_evidence).encode()).decode()
        with patch(
            "apps.infrastructure.ansible_service.AnsibleService.run_server_playbook",
            return_value=Ok(
                AnsibleResult(True, "virtualmin_security_read.yml", "PRAHO_SECURITY_INSPECTION=" + encoded, "", 0)
            ),
        ):
            activated = NodeRegistrationService().verify_and_activate(self.target)
        self.assertTrue(activated.is_ok(), activated)
        self.target.refresh_from_db()
        self.assertIsNone(destination_refusal(self.target))
        NodeMaintenancePolicy.objects.create(
            node=self.target,
            timezone="UTC",
            weekdays=list(range(7)),
            starts_time=time(0),
            ends_time=time(23, 59),
            max_defer_minutes=30,
        )
        self.facts = component_manifest()
        self.facts["source"].update(
            server_uuid=str(self.node.pk),
            connection_identity=connection_identity(self.node),
            domain=self.account.domain,
            owner=self.account.virtualmin_username,
            home="/home/" + self.account.virtualmin_username,
        )
        self.facts["routing"]["website_names"] = [self.account.domain, "www." + self.account.domain]
        native = self.native_source.seed_domain(
            self.account.domain,
            username=self.account.virtualmin_username,
            domain_id=self.facts["source"]["domain_id"],
        )
        native.features = ["unix", "dir", "web", "ssl", "logrotate", "mysql", "mail", "dns"]
        review = record_component_review(self.account, self.target, self.facts, self.actor)
        self.approval = approve_component_review(
            review,
            self.facts,
            self.actor,
            "Move selected website and database; retain mail and DNS",
            "Operations retains independent source mail and DNS backups",
        )

    def component_start(self) -> VirtualminMigration:
        return start_component_migration(self.approval, self.facts, self.actor, enqueue=False)
