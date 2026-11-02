"""Retriability must survive infrastructure orchestration boundaries."""

from unittest.mock import patch

from django.test import TestCase

from apps.common.types import Err, Retriability
from apps.infrastructure.deployment_service import NodeDeploymentService
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment


class NodeDeploymentRetriabilityTests(TestCase):
    def test_stop_node_preserves_provider_retriability(self) -> None:
        service = NodeDeploymentService()
        deployment = _create_deployment("completed", external_node_id="retriability-native-fixture")
        provider_result = Err("provider rate limited", retriability=Retriability.RETRIABLE)

        with (
            patch("apps.infrastructure.deployment_service.run_provider_command", return_value=provider_result),
        ):
            result = service.stop_node(deployment, {"api_token": "token"})

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)
