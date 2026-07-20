"""Retriability must survive infrastructure orchestration boundaries."""

from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from apps.common.types import Err, Retriability
from apps.infrastructure.deployment_service import NodeDeploymentService


class NodeDeploymentRetriabilityTests(SimpleTestCase):
    def test_stop_node_preserves_provider_retriability(self) -> None:
        service = NodeDeploymentService.__new__(NodeDeploymentService)
        deployment = MagicMock()
        deployment.status = "completed"
        deployment.hostname = "node.example.com"
        deployment.provider.provider_type = "hetzner"
        deployment.external_node_id = "node-1"
        provider_result = Err("provider rate limited", retriability=Retriability.RETRIABLE)

        with (
            patch("apps.infrastructure.deployment_service.run_provider_command", return_value=provider_result),
            patch("apps.infrastructure.models.NodeDeploymentLog.objects.create"),
            patch.object(NodeDeploymentService, "_mark_failed"),
            patch("apps.infrastructure.deployment_service.InfrastructureAuditService"),
        ):
            result = service.stop_node(deployment, {"api_token": "token"})

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)
