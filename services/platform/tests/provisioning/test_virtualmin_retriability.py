"""
Retriability annotations on the Virtualmin connection-test paths.

test_connection wraps an inner call() Result — its Err must PROPAGATE the
inner retriability, not blanket-assert RETRIABLE (a validation error is
permanent; forcing RETRIABLE invites a retry loop the moment a consumer
wires up retries). Unexpected exceptions carry no signal, so they must
stay UNKNOWN — the fail-closed default the tri-state design mandates.
"""

from unittest.mock import patch

from django.test import SimpleTestCase

from apps.common.types import Err, Retriability
from apps.provisioning.virtualmin_gateway import (
    VirtualminAPIError,
    VirtualminConfig,
    VirtualminGateway,
)
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminProvisioningService


def _gateway() -> VirtualminGateway:
    server = VirtualminServer(hostname="test.example.com")
    return VirtualminGateway(VirtualminConfig(server=server))


class GatewayTestConnectionRetriabilityTests(SimpleTestCase):
    def test_failed_call_propagates_inner_retriability(self) -> None:
        """An inner Err with UNKNOWN retriability must not be upgraded to RETRIABLE."""
        gateway = _gateway()
        inner = Err(VirtualminAPIError("Validation error: bad program"))

        with patch.object(gateway, "call", return_value=inner):
            result = gateway.test_connection()

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)

    def test_failed_call_keeps_explicit_retriable_signal(self) -> None:
        gateway = _gateway()
        inner = Err(VirtualminAPIError("Server unreachable"), retriability=Retriability.RETRIABLE)

        with patch.object(gateway, "call", return_value=inner):
            result = gateway.test_connection()

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)

    def test_unexpected_exception_is_unknown(self) -> None:
        gateway = _gateway()

        with patch.object(gateway, "call", side_effect=RuntimeError("boom")):
            result = gateway.test_connection()

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)


class ServiceTestServerConnectionRetriabilityTests(SimpleTestCase):
    def test_gateway_setup_failure_is_unknown(self) -> None:
        """_get_gateway failures (no server, credential errors) are not transient."""
        service = VirtualminProvisioningService()

        with patch.object(service, "_get_gateway", side_effect=RuntimeError("No server specified")):
            result = service.test_server_connection(VirtualminServer(hostname="x.example.com"))

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)
