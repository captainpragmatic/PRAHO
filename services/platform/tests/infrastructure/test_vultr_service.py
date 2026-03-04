"""
Tests for VultrService — CloudProviderGateway implementation using Vultr REST API v2.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests as req_lib

from django.test import TestCase

from apps.infrastructure.cloud_gateway import (
    FirewallRule,
    ServerCreateRequest,
)
from apps.infrastructure.vultr_service import VultrService

_PATCH_TARGET = "apps.infrastructure.vultr_service.safe_request"


def _mock_response(json_data=None, status_code=200):
    """Create a mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.raise_for_status.return_value = None
    return resp


class VultrServiceCreateServerTest(TestCase):
    def setUp(self):
        self.svc = VultrService(token="test-token")

    def test_create_server_success(self):
        """Server creation returns ServerCreateResult on success."""
        create_resp = _mock_response({"instance": {"id": "inst-123", "status": "pending"}})
        active_resp = _mock_response({
            "instance": {"id": "inst-123", "status": "active", "power_status": "running",
                         "main_ip": "1.2.3.4", "v6_main_ip": "::1"}
        })

        req = ServerCreateRequest(
            name="test-server", server_type="vc2-1c-1gb", location="ewr",
            ssh_keys=[], image="ubuntu-22-04-x64",
        )
        with patch(_PATCH_TARGET, side_effect=[create_resp, active_resp]):
            result = self.svc.create_server(req)
        assert result.is_ok()
        val = result.unwrap()
        assert val.server_id == "inst-123"
        assert val.ipv4_address == "1.2.3.4"

    def test_create_server_idempotent(self):
        """If instance with correlation_id exists, return it without creating."""
        list_resp = _mock_response({
            "instances": [{"id": "existing-1", "label": "corr-42", "main_ip": "5.6.7.8", "v6_main_ip": ""}]
        })

        req = ServerCreateRequest(
            name="test", server_type="vc2-1c-1gb", location="ewr",
            ssh_keys=[], labels={"praho-deployment": "corr-42"},
        )
        with patch(_PATCH_TARGET, return_value=list_resp):
            result = self.svc.create_server(req)
        assert result.is_ok()
        assert result.unwrap().server_id == "existing-1"

    def test_create_server_poll_timeout(self):
        """Polling timeout returns error."""
        create_resp = _mock_response({"instance": {"id": "inst-slow"}})
        pending_resp = _mock_response({
            "instance": {"id": "inst-slow", "status": "pending", "power_status": "stopped"}
        })

        with patch(_PATCH_TARGET, side_effect=[create_resp] + [pending_resp] * 100), \
             patch("apps.infrastructure.vultr_service._get_vultr_poll_timeout", return_value=0), \
             patch("apps.infrastructure.vultr_service.VULTR_POLL_INTERVAL", 0.001):
            req = ServerCreateRequest(name="slow", server_type="vc2-1c-1gb", location="ewr", ssh_keys=[])
            result = self.svc.create_server(req)

        assert result.is_err()
        assert "did not become active" in result.unwrap_err()


class VultrServiceDeleteServerTest(TestCase):
    def setUp(self):
        self.svc = VultrService(token="test-token")

    def test_delete_server_success(self):
        with patch(_PATCH_TARGET, return_value=_mock_response()):
            result = self.svc.delete_server("inst-123")
        assert result.is_ok()
        assert result.unwrap() is True

    def test_delete_server_failure(self):
        with patch(_PATCH_TARGET, side_effect=Exception("API error")):
            result = self.svc.delete_server("inst-bad")
        assert result.is_err()


class VultrServiceGetServerTest(TestCase):
    def setUp(self):
        self.svc = VultrService(token="test-token")

    def test_get_server_success(self):
        resp = _mock_response({
            "instance": {
                "id": "inst-1", "label": "my-server", "status": "active",
                "main_ip": "1.2.3.4", "v6_main_ip": "", "plan": "vc2-1c-1gb",
                "region": "ewr", "tags": ["env=prod"],
            }
        })
        with patch(_PATCH_TARGET, return_value=resp):
            result = self.svc.get_server("inst-1")
        assert result.is_ok()
        info = result.unwrap()
        assert info.server_id == "inst-1"
        assert info.labels == {"env": "prod"}

    def test_get_server_not_found(self):
        http_error = req_lib.HTTPError(response=MagicMock(status_code=404))
        with patch(_PATCH_TARGET, side_effect=http_error):
            result = self.svc.get_server("missing")
        assert result.is_ok()
        assert result.unwrap() is None


class VultrServicePowerOpsTest(TestCase):
    """C8: Power ops call _wait_for_status which polls get_server. Mocks must provide valid instance data."""

    def setUp(self):
        self.svc = VultrService(token="test-token")

    def _mock_power_sequence(self, action_status: str = "running"):
        """Return POST (action) + GET (poll) responses for power operations."""
        post_resp = _mock_response()  # POST to start/halt/reboot returns 204-like
        poll_resp = _mock_response({
            "instance": {
                "id": "inst-1", "label": "test", "status": "active",
                "power_status": action_status, "main_ip": "1.2.3.4",
                "v6_main_ip": "", "plan": "vc2-1c-1gb", "region": "ewr", "tags": [],
            }
        })
        return [post_resp, poll_resp]

    def test_power_on(self):
        with patch(_PATCH_TARGET, side_effect=self._mock_power_sequence("running")), \
             patch("apps.infrastructure.vultr_service._get_vultr_poll_timeout", return_value=1), \
             patch("apps.infrastructure.vultr_service.VULTR_POLL_INTERVAL", 0.01):
            result = self.svc.power_on("inst-1")
        assert result.is_ok()

    def test_power_off(self):
        post_resp = _mock_response()
        poll_resp = _mock_response({
            "instance": {
                "id": "inst-1", "label": "test", "status": "stopped",
                "power_status": "stopped", "main_ip": "1.2.3.4",
                "v6_main_ip": "", "plan": "vc2-1c-1gb", "region": "ewr", "tags": [],
            }
        })
        with patch(_PATCH_TARGET, side_effect=[post_resp, poll_resp]), \
             patch("apps.infrastructure.vultr_service._get_vultr_poll_timeout", return_value=1), \
             patch("apps.infrastructure.vultr_service.VULTR_POLL_INTERVAL", 0.01):
            result = self.svc.power_off("inst-1")
        assert result.is_ok()

    def test_reboot(self):
        with patch(_PATCH_TARGET, side_effect=self._mock_power_sequence("running")), \
             patch("apps.infrastructure.vultr_service._get_vultr_poll_timeout", return_value=1), \
             patch("apps.infrastructure.vultr_service.VULTR_POLL_INTERVAL", 0.01):
            result = self.svc.reboot("inst-1")
        assert result.is_ok()

    def test_resize(self):
        patch_resp = _mock_response()
        poll_resp = _mock_response({
            "instance": {
                "id": "inst-1", "label": "test", "status": "active",
                "power_status": "running", "main_ip": "1.2.3.4",
                "v6_main_ip": "", "plan": "vc2-2c-4gb", "region": "ewr", "tags": [],
            }
        })
        with patch(_PATCH_TARGET, side_effect=[patch_resp, poll_resp]), \
             patch("apps.infrastructure.vultr_service._get_vultr_poll_timeout", return_value=1), \
             patch("apps.infrastructure.vultr_service.VULTR_POLL_INTERVAL", 0.01):
            result = self.svc.resize("inst-1", "vc2-2c-4gb")
        assert result.is_ok()


class VultrServiceSSHKeyTest(TestCase):
    def setUp(self):
        self.svc = VultrService(token="test-token")

    def test_upload_ssh_key_new(self):
        list_resp = _mock_response({"ssh_keys": []})
        create_resp = _mock_response({"ssh_key": {"id": "key-1", "name": "mykey", "fingerprint": "aa:bb"}})
        with patch(_PATCH_TARGET, side_effect=[list_resp, create_resp]):
            result = self.svc.upload_ssh_key("mykey", "ssh-rsa AAAA...")
        assert result.is_ok()
        assert result.unwrap().key_id == "key-1"

    def test_upload_ssh_key_existing_same(self):
        list_resp = _mock_response({
            "ssh_keys": [{"id": "key-1", "name": "mykey", "ssh_key": "ssh-rsa AAAA...", "fingerprint": "aa:bb"}]
        })
        with patch(_PATCH_TARGET, return_value=list_resp):
            result = self.svc.upload_ssh_key("mykey", "ssh-rsa AAAA...")
        assert result.is_ok()

    def test_delete_ssh_key(self):
        list_resp = _mock_response({"ssh_keys": [{"id": "key-1", "name": "mykey"}]})
        del_resp = _mock_response()
        with patch(_PATCH_TARGET, side_effect=[list_resp, del_resp]):
            result = self.svc.delete_ssh_key("mykey")
        assert result.is_ok()


class VultrServiceFirewallTest(TestCase):
    def setUp(self):
        self.svc = VultrService(token="test-token")

    def test_create_firewall(self):
        create_resp = _mock_response({"firewall_group": {"id": "fw-1"}})
        rule_resp = _mock_response()
        rules = [FirewallRule(protocol="tcp", port="22", description="SSH")]
        with patch(_PATCH_TARGET, side_effect=[create_resp, rule_resp, rule_resp]):
            result = self.svc.create_firewall("test-fw", rules)
        assert result.is_ok()
        assert result.unwrap() == "fw-1"

    def test_delete_firewall(self):
        with patch(_PATCH_TARGET, return_value=_mock_response()):
            result = self.svc.delete_firewall("fw-1")
        assert result.is_ok()


class VultrServiceCatalogTest(TestCase):
    def setUp(self):
        self.svc = VultrService(token="test-token")

    def test_get_locations(self):
        resp = _mock_response({
            "regions": [{"id": "ewr", "city": "New Jersey", "country": "US"}]
        })
        with patch(_PATCH_TARGET, return_value=resp):
            result = self.svc.get_locations()
        assert result.is_ok()
        locs = result.unwrap()
        assert len(locs) == 1
        assert locs[0].name == "ewr"

    def test_get_server_types(self):
        resp = _mock_response({
            "plans": [{"id": "vc2-1c-1gb", "vcpu_count": 1, "ram": 1024, "disk": 25}]
        })
        with patch(_PATCH_TARGET, return_value=resp):
            result = self.svc.get_server_types()
        assert result.is_ok()
        types = result.unwrap()
        assert len(types) == 1
        assert types[0].vcpus == 1
        assert types[0].memory_gb == 1.0


class VultrServiceEmptyImageTest(TestCase):
    """M10: create_server with empty/None image must return Err, not os_id:0."""

    def test_create_server_with_empty_image_rejects(self):
        svc = VultrService(token="test-token")

        req = ServerCreateRequest(
            name="test", server_type="vc2-1c-1gb", location="ewr",
            ssh_keys=[], image="",
        )
        result = svc.create_server(req)
        assert result.is_err()
        assert "Image required" in result.unwrap_err()

    def test_create_server_with_valid_image_succeeds(self):
        svc = VultrService(token="test-token")

        create_resp = _mock_response({"instance": {"id": "inst-1", "status": "pending"}})
        active_resp = _mock_response({
            "instance": {"id": "inst-1", "status": "active", "power_status": "running",
                         "main_ip": "1.2.3.4", "v6_main_ip": ""}
        })

        req = ServerCreateRequest(
            name="test", server_type="vc2-1c-1gb", location="ewr",
            ssh_keys=[], image="ubuntu-22-04-x64",
        )
        with patch(_PATCH_TARGET, side_effect=[create_resp, active_resp]):
            result = svc.create_server(req)
        assert result.is_ok()


class VultrServiceDeleteFirewall404Test(TestCase):
    """H11: delete_firewall returns Ok(True) on 404 (already gone)."""

    def test_delete_firewall_404_returns_ok(self):
        svc = VultrService(token="test-token")
        http_error = req_lib.HTTPError(response=MagicMock(status_code=404))
        with patch(_PATCH_TARGET, side_effect=http_error):
            result = svc.delete_firewall("fw-gone")
        assert result.is_ok()
        assert result.unwrap() is True

    def test_delete_firewall_500_returns_err(self):
        svc = VultrService(token="test-token")
        http_error = req_lib.HTTPError(response=MagicMock(status_code=500))
        with patch(_PATCH_TARGET, side_effect=http_error):
            result = svc.delete_firewall("fw-bad")
        assert result.is_err()


class VultrServiceDeleteServerAlreadyGoneTest(TestCase):
    """delete_server returns Ok(True) on 404."""

    def test_delete_server_404_returns_ok(self):
        svc = VultrService(token="test-token")
        http_error = req_lib.HTTPError(response=MagicMock(status_code=404))
        with patch(_PATCH_TARGET, side_effect=http_error):
            result = svc.delete_server("inst-gone")
        assert result.is_ok()
        assert result.unwrap() is True


class VultrServiceStatusNormalizationTest(TestCase):
    """Vultr normalizes status values via normalize_server_status."""

    def test_active_normalized_to_running(self):
        svc = VultrService(token="test-token")
        resp = _mock_response({
            "instance": {
                "id": "inst-1", "label": "test", "status": "active",
                "main_ip": "1.2.3.4", "v6_main_ip": "", "plan": "vc2-1c-1gb",
                "region": "ewr", "tags": [],
            }
        })
        with patch(_PATCH_TARGET, return_value=resp):
            result = svc.get_server("inst-1")
        assert result.is_ok()
        info = result.unwrap()
        assert info is not None
        assert info.status == "running"  # 'active' → 'running'
