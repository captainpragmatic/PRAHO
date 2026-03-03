"""
Tests for VirtualminDisasterRecoveryService audit fixes.

Covers:
- C1: VirtualminGateway must receive VirtualminConfig, not VirtualminServer
- M15: Truthy quota checks skip zero values (zero means unlimited)
- Quota restoration edge cases (disk-only, bandwidth-only, both, none)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.types import Ok
from apps.provisioning.virtualmin_disaster_recovery import VirtualminDisasterRecoveryService
from apps.provisioning.virtualmin_gateway import VirtualminConfig


class RestoreQuotasGatewayConstructorTests(TestCase):
    """C1: _restore_quotas must pass VirtualminConfig to VirtualminGateway, not VirtualminServer."""

    def setUp(self) -> None:
        self.service = VirtualminDisasterRecoveryService()
        self.mock_server = MagicMock()
        self.mock_server.hostname = "test.example.com"

    @patch("apps.provisioning.virtualmin_disaster_recovery.VirtualminGateway")
    @patch("apps.provisioning.virtualmin_disaster_recovery.VirtualminConfig")
    def test_restore_quotas_uses_virtualmin_config_not_server(
        self, mock_config_cls: MagicMock, mock_gateway_cls: MagicMock
    ) -> None:
        """VirtualminGateway must be constructed with VirtualminConfig(server=server)."""
        mock_config_instance = MagicMock(spec=VirtualminConfig)
        mock_config_cls.return_value = mock_config_instance
        mock_gateway = MagicMock()
        mock_gateway.call.return_value = Ok({"status": "success"})
        mock_gateway_cls.return_value = mock_gateway

        self.service._restore_quotas(self.mock_server, "example.com", 500, 1000)

        # Config must be created with server=
        mock_config_cls.assert_called_once_with(server=self.mock_server)
        # Gateway must receive the config object, not the server directly
        mock_gateway_cls.assert_called_once_with(mock_config_instance)


class RestoreQuotasParameterTests(TestCase):
    """Test that _restore_quotas sends correct parameters for various quota combinations."""

    def setUp(self) -> None:
        self.service = VirtualminDisasterRecoveryService()
        self.mock_server = MagicMock()
        self.mock_server.hostname = "test.example.com"

    @patch("apps.provisioning.virtualmin_disaster_recovery.VirtualminGateway")
    @patch("apps.provisioning.virtualmin_disaster_recovery.VirtualminConfig")
    def _call_restore_quotas(
        self,
        disk: int | None,
        bw: int | None,
        mock_config_cls: MagicMock,
        mock_gateway_cls: MagicMock,
    ) -> dict[str, str]:
        """Helper: call _restore_quotas and return the params dict passed to gateway.call."""
        mock_gateway = MagicMock()
        mock_gateway.call.return_value = Ok({"status": "success"})
        mock_gateway_cls.return_value = mock_gateway
        mock_config_cls.return_value = MagicMock(spec=VirtualminConfig)

        self.service._restore_quotas(self.mock_server, "example.com", disk, bw)

        mock_gateway.call.assert_called_once()
        _program, params = mock_gateway.call.call_args[0]
        return params

    def test_restore_quotas_both_quotas(self) -> None:
        """Both disk and bandwidth quotas should be included in params."""
        params = self._call_restore_quotas(500, 1000)
        self.assertEqual(params["domain"], "example.com")
        self.assertEqual(params["quota"], "500")
        self.assertEqual(params["bw"], "1000")

    def test_restore_quotas_disk_only(self) -> None:
        """Only disk quota set; bandwidth should be absent."""
        params = self._call_restore_quotas(500, None)
        self.assertEqual(params["quota"], "500")
        self.assertNotIn("bw", params)

    def test_restore_quotas_bandwidth_only(self) -> None:
        """Only bandwidth quota set; disk should be absent."""
        params = self._call_restore_quotas(None, 1000)
        self.assertNotIn("quota", params)
        self.assertEqual(params["bw"], "1000")

    def test_restore_quotas_correct_program(self) -> None:
        """_restore_quotas must call the 'modify-domain' Virtualmin program."""
        with (
            patch("apps.provisioning.virtualmin_disaster_recovery.VirtualminConfig"),
            patch("apps.provisioning.virtualmin_disaster_recovery.VirtualminGateway") as mock_gw_cls,
        ):
            mock_gw = MagicMock()
            mock_gw.call.return_value = Ok({"status": "success"})
            mock_gw_cls.return_value = mock_gw

            self.service._restore_quotas(self.mock_server, "example.com", 100, 200)

            program, _params = mock_gw.call.call_args[0]
            self.assertEqual(program, "modify-domain")


class RestoreQuotasZeroValueTests(TestCase):
    """M15: Zero quotas mean 'unlimited' and must not be skipped by truthy checks."""

    def setUp(self) -> None:
        self.service = VirtualminDisasterRecoveryService()
        self.mock_server = MagicMock()
        self.mock_server.hostname = "test.example.com"

    @patch("apps.provisioning.virtualmin_disaster_recovery.VirtualminGateway")
    @patch("apps.provisioning.virtualmin_disaster_recovery.VirtualminConfig")
    def test_restore_quotas_zero_quota_means_unlimited(
        self, mock_config_cls: MagicMock, mock_gateway_cls: MagicMock
    ) -> None:
        """Zero disk/bandwidth values must be sent (not skipped), as 0 means unlimited."""
        mock_gateway = MagicMock()
        mock_gateway.call.return_value = Ok({"status": "success"})
        mock_gateway_cls.return_value = mock_gateway
        mock_config_cls.return_value = MagicMock(spec=VirtualminConfig)

        self.service._restore_quotas(self.mock_server, "example.com", 0, 0)

        mock_gateway.call.assert_called_once()
        _program, params = mock_gateway.call.call_args[0]
        self.assertEqual(params["quota"], "0")
        self.assertEqual(params["bw"], "0")

    @patch("apps.provisioning.virtualmin_disaster_recovery.VirtualminGateway")
    @patch("apps.provisioning.virtualmin_disaster_recovery.VirtualminConfig")
    def test_restore_quotas_none_quota_skipped(
        self, mock_config_cls: MagicMock, mock_gateway_cls: MagicMock
    ) -> None:
        """None quota values must be omitted from params (no quota to restore)."""
        mock_gateway = MagicMock()
        mock_gateway.call.return_value = Ok({"status": "success"})
        mock_gateway_cls.return_value = mock_gateway
        mock_config_cls.return_value = MagicMock(spec=VirtualminConfig)

        self.service._restore_quotas(self.mock_server, "example.com", None, None)

        mock_gateway.call.assert_called_once()
        _program, params = mock_gateway.call.call_args[0]
        self.assertNotIn("quota", params)
        self.assertNotIn("bw", params)
