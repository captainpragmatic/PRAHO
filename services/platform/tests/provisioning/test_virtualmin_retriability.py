"""
Retriability annotations on the Virtualmin connection-test paths.

test_connection wraps an inner call() Result — its Err must PROPAGATE the
inner retriability, not blanket-assert RETRIABLE (a validation error is
permanent; forcing RETRIABLE invites a retry loop the moment a consumer
wires up retries). Unexpected exceptions carry no signal, so they must
stay UNKNOWN — the fail-closed default the tri-state design mandates.
"""

from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from apps.common.types import Err, Retriability
from apps.provisioning.virtualmin_gateway import (
    VirtualminAPIError,
    VirtualminConfig,
    VirtualminGateway,
)
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_service import (
    VirtualminAccountCreationData,
    VirtualminProvisioningService,
    VirtualminServerManagementService,
)


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

    def test_get_server_info_preserves_inner_retriability(self) -> None:
        gateway = _gateway()
        inner = Err(VirtualminAPIError("rate limited"), retriability=Retriability.RETRIABLE)

        with patch.object(gateway, "call", return_value=inner):
            result = gateway.get_server_info()

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)

    def test_list_domains_preserves_inner_retriability(self) -> None:
        gateway = _gateway()
        inner = Err(VirtualminAPIError("bad request"), retriability=Retriability.NOT_RETRIABLE)

        with patch.object(gateway, "call", return_value=inner):
            result = gateway.list_domains()

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.NOT_RETRIABLE)


class ServiceTestServerConnectionRetriabilityTests(SimpleTestCase):
    def test_gateway_setup_failure_is_unknown(self) -> None:
        """_get_gateway failures (no server, credential errors) are not transient."""
        service = VirtualminProvisioningService()

        with patch.object(service, "_get_gateway", side_effect=RuntimeError("No server specified")):
            result = service.test_server_connection(VirtualminServer(hostname="x.example.com"))

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)

    def test_sync_account_preserves_gateway_retriability(self) -> None:
        service = VirtualminProvisioningService()
        account = MagicMock()
        gateway = MagicMock()
        gateway.get_domain_state.return_value = Err("bad credentials", retriability=Retriability.NOT_RETRIABLE)

        with patch.object(service, "_get_gateway", return_value=gateway):
            result = service.sync_account_from_virtualmin(account)

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.NOT_RETRIABLE)


    def test_failed_creation_preserves_inner_retriability(self) -> None:
        service = VirtualminProvisioningService()
        customer = MagicMock(id=42)
        creation_data = VirtualminAccountCreationData(
            service=MagicMock(id=7, customer=customer),
            domain="retry.example.com",
            username="retryuser",
            password="StrongPassword123!",
            server=MagicMock(),
        )
        account = MagicMock(id=11)
        job = MagicMock()
        inner = Err("connect timeout", retriability=Retriability.RETRIABLE)

        with (
            patch("apps.provisioning.virtualmin_service.transaction.atomic"),
            patch("apps.provisioning.virtualmin_service.VirtualminAccount") as account_cls,
            patch("apps.provisioning.virtualmin_service.VirtualminProvisioningJob") as job_cls,
            patch.object(service, "_execute_domain_creation", return_value=inner),
        ):
            account_cls.objects.filter.return_value.first.return_value = None
            account_cls.return_value = account
            job_cls.return_value = job

            result = service.create_virtualmin_account(creation_data)

        assert isinstance(result, Err)
        self.assertEqual(result.unwrap_err(), "connect timeout")
        self.assertEqual(result.retriability, Retriability.RETRIABLE)

    def test_server_statistics_preserves_gateway_retriability(self) -> None:
        server = MagicMock()
        server.hostname = "stats.example.com"
        gateway = MagicMock()
        gateway.get_server_info.return_value = Err("rate limited", retriability=Retriability.RETRIABLE)

        with patch("apps.provisioning.virtualmin_service.VirtualminProvisioningService") as service_cls:
            service_cls.return_value._get_gateway.return_value = gateway
            result = VirtualminServerManagementService().update_server_statistics(server)

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)

    def test_domain_conflict_check_fails_closed_with_gateway_retriability(self) -> None:
        service = VirtualminProvisioningService()
        account = MagicMock()
        account.domain = "example.com"
        account.virtualmin_username = "owner"
        gateway = MagicMock()
        gateway.list_domains_with_owners.return_value = Err("cannot inspect domains", retriability=Retriability.RETRIABLE)

        result = service._check_domain_conflicts(account, gateway)

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)

    def test_template_check_fails_closed_with_gateway_retriability(self) -> None:
        service = VirtualminProvisioningService()
        account = MagicMock()
        account.template_name = "Default"
        gateway = MagicMock()
        gateway.list_templates.return_value = Err("bad ACL", retriability=Retriability.NOT_RETRIABLE)

        result = service._check_template_availability(account, gateway)

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.NOT_RETRIABLE)
