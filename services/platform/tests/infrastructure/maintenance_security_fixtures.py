"""Plain fixtures using public security inspection and decision producers."""

import base64
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from apps.common.types import Ok
from apps.infrastructure.ansible_service import AnsibleResult
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_security import connection_identity, record_inspection
from apps.provisioning.virtualmin_security_execution import claim_hardening
from apps.provisioning.virtualmin_security_models import NodeSecurityExecution
from apps.provisioning.virtualmin_security_tasks import collect_inspection
from apps.settings.services import SettingsService
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture
from tests.provisioning.test_node_security_policy import ADMIN_NETWORKS, OPERATOR_KEY, node_policy_evidence


class MaintenanceSecurityFixture(MaintenanceAdmissionFixture):
    def setUp(self) -> None:
        super().setUp()
        self.spool = TemporaryDirectory()
        self.addCleanup(self.spool.cleanup)
        key = Path(self.spool.name) / "operator.pub"
        key.write_text(OPERATOR_KEY + "\n")
        key.chmod(0o600)
        self.enterContext(self.settings(PRAHO_SSH_OPERATOR_PUBLIC_KEYS_FILE=str(key)))
        self.assertTrue(
            SettingsService.update_setting("infrastructure.node_admin_allowed_cidrs", ADMIN_NETWORKS).is_ok()
        )
        self.evidence = self.inspect(self.node)
        self.review = record_inspection(self.node, self.evidence)

    def inspect(self, node: VirtualminServer) -> dict[str, object]:
        packet = node_policy_evidence()
        packet["identity"] = connection_identity(node)
        packet["proposed_changes"] = ["Restrict root"]
        encoded = base64.b64encode(json.dumps(packet).encode()).decode()
        with patch(
            "apps.infrastructure.ansible_service.AnsibleService.run_server_playbook",
            return_value=Ok(
                AnsibleResult(True, "virtualmin_security_read.yml", "PRAHO_SECURITY_INSPECTION=" + encoded, "", 0)
            ),
        ) as transport:
            evidence = collect_inspection(node)
        transport.assert_called_once()
        return evidence

    def harden(self) -> NodeSecurityExecution:
        return claim_hardening(
            self.review, self.evidence, self.actor, "Mail and DNS evacuated; accept the reviewed access changes"
        )
