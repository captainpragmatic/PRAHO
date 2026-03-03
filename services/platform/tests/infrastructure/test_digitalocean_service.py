"""
Tests for DigitalOcean Cloud Service (pydo SDK wrapper).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.infrastructure.cloud_gateway import FirewallRule, ServerCreateRequest
from apps.infrastructure.digitalocean_service import DigitalOceanService


def _make_service() -> tuple[DigitalOceanService, MagicMock]:
    """Create a DigitalOceanService with a mocked pydo Client."""
    with patch("apps.infrastructure.digitalocean_service.Client") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        svc = DigitalOceanService(token="test-token")
    return svc, mock_client


def _droplet_dict(
    droplet_id: int = 12345,
    name: str = "test-server",
    status: str = "active",
    ipv4: str = "1.2.3.4",
) -> dict:
    return {
        "id": droplet_id,
        "name": name,
        "status": status,
        "size_slug": "s-1vcpu-1gb",
        "region": {"slug": "nyc1"},
        "tags": ["praho-deployment:abc123"],
        "networks": {
            "v4": [{"type": "public", "ip_address": ipv4}],
            "v6": [{"type": "public", "ip_address": "2001:db8::1"}],
        },
    }


class TestDigitalOceanServiceCreateServer(TestCase):
    def test_create_server_success(self) -> None:
        svc, client = _make_service()
        client.droplets.list.return_value = {"droplets": []}
        client.ssh_keys.list.return_value = {"ssh_keys": []}
        client.droplets.create.return_value = {
            "droplet": {"id": 99},
            "links": {"actions": [{"id": 1001}]},
        }
        client.actions.get.return_value = {"action": {"status": "completed"}}
        client.droplets.get.return_value = {"droplet": _droplet_dict(droplet_id=99)}

        req = ServerCreateRequest(
            name="web1", server_type="s-1vcpu-1gb", location="nyc1",
            ssh_keys=[], image="ubuntu-22-04-x64", labels={},
        )
        result = svc.create_server(req)

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap().server_id, "99")
        self.assertEqual(result.unwrap().ipv4_address, "1.2.3.4")

    def test_create_server_idempotent(self) -> None:
        svc, client = _make_service()
        client.droplets.list.return_value = {"droplets": [_droplet_dict()]}

        req = ServerCreateRequest(
            name="web1", server_type="s-1vcpu-1gb", location="nyc1",
            ssh_keys=[], image="ubuntu-22-04-x64",
            labels={"praho-deployment": "abc123"},
        )
        result = svc.create_server(req)

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap().server_id, "12345")
        client.droplets.create.assert_not_called()

    def test_create_server_failure(self) -> None:
        svc, client = _make_service()
        client.droplets.list.return_value = {"droplets": []}
        client.ssh_keys.list.return_value = {"ssh_keys": []}
        client.droplets.create.side_effect = RuntimeError("API error")

        req = ServerCreateRequest(
            name="web1", server_type="s-1vcpu-1gb", location="nyc1",
            ssh_keys=[], image="ubuntu-22-04-x64", labels={},
        )
        result = svc.create_server(req)

        self.assertTrue(result.is_err())
        self.assertIn("API error", result.unwrap_err())


class TestDigitalOceanServiceDeleteServer(TestCase):
    def test_delete_server_success(self) -> None:
        svc, client = _make_service()
        client.droplets.destroy.return_value = None
        result = svc.delete_server("12345")
        self.assertTrue(result.is_ok())
        client.droplets.destroy.assert_called_once_with(droplet_id=12345)

    def test_delete_server_not_found(self) -> None:
        svc, client = _make_service()
        client.droplets.destroy.side_effect = RuntimeError("404 not found")
        result = svc.delete_server("12345")
        self.assertTrue(result.is_ok())


class TestDigitalOceanServiceGetServer(TestCase):
    def test_get_server_exists(self) -> None:
        svc, client = _make_service()
        client.droplets.get.return_value = {"droplet": _droplet_dict()}
        result = svc.get_server("12345")
        self.assertTrue(result.is_ok())
        info = result.unwrap()
        self.assertIsNotNone(info)
        self.assertEqual(info.server_id, "12345")
        self.assertEqual(info.ipv4_address, "1.2.3.4")

    def test_get_server_not_found(self) -> None:
        svc, client = _make_service()
        client.droplets.get.side_effect = RuntimeError("not found")
        result = svc.get_server("99999")
        self.assertTrue(result.is_ok())
        self.assertIsNone(result.unwrap())


class TestDigitalOceanServicePowerActions(TestCase):
    def test_power_on(self) -> None:
        svc, client = _make_service()
        client.droplet_actions.post.return_value = {"action": {"id": 100, "status": "in-progress"}}
        client.actions.get.return_value = {"action": {"status": "completed"}}
        result = svc.power_on("12345")
        self.assertTrue(result.is_ok())

    def test_power_off(self) -> None:
        svc, client = _make_service()
        client.droplet_actions.post.return_value = {"action": {"id": 101, "status": "in-progress"}}
        client.actions.get.return_value = {"action": {"status": "completed"}}
        result = svc.power_off("12345")
        self.assertTrue(result.is_ok())

    def test_reboot(self) -> None:
        svc, client = _make_service()
        client.droplet_actions.post.return_value = {"action": {"id": 102, "status": "in-progress"}}
        client.actions.get.return_value = {"action": {"status": "completed"}}
        result = svc.reboot("12345")
        self.assertTrue(result.is_ok())

    def test_resize(self) -> None:
        svc, client = _make_service()
        client.droplet_actions.post.return_value = {"action": {"id": 103, "status": "in-progress"}}
        client.actions.get.return_value = {"action": {"status": "completed"}}
        result = svc.resize("12345", "s-2vcpu-2gb")
        self.assertTrue(result.is_ok())


class TestDigitalOceanServiceSSHKeys(TestCase):
    def test_upload_ssh_key(self) -> None:
        svc, client = _make_service()
        client.ssh_keys.list.return_value = {"ssh_keys": []}
        client.ssh_keys.create.return_value = {
            "ssh_key": {"id": 55, "name": "mykey", "fingerprint": "ab:cd:ef"},
        }
        result = svc.upload_ssh_key("mykey", "ssh-rsa AAAA...")
        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap().key_id, "55")

    def test_delete_ssh_key(self) -> None:
        svc, client = _make_service()
        client.ssh_keys.list.return_value = {"ssh_keys": [{"id": 55, "name": "mykey"}]}
        client.ssh_keys.delete.return_value = None
        result = svc.delete_ssh_key("mykey")
        self.assertTrue(result.is_ok())


class TestDigitalOceanServiceFirewalls(TestCase):
    def test_create_firewall(self) -> None:
        svc, client = _make_service()
        client.firewalls.create.return_value = {"firewall": {"id": "fw-uuid-123"}}
        rules = [FirewallRule(protocol="tcp", port="22")]
        result = svc.create_firewall("web-fw", rules)
        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), "fw-uuid-123")

    def test_delete_firewall(self) -> None:
        svc, client = _make_service()
        client.firewalls.delete.return_value = None
        result = svc.delete_firewall("fw-uuid-123")
        self.assertTrue(result.is_ok())


class TestDigitalOceanServiceCatalog(TestCase):
    def test_get_locations(self) -> None:
        svc, client = _make_service()
        client.regions.list.return_value = {
            "regions": [
                {"slug": "nyc1", "name": "New York 1", "available": True},
                {"slug": "fra1", "name": "Frankfurt 1", "available": True},
                {"slug": "old1", "name": "Retired", "available": False},
            ],
        }
        result = svc.get_locations()
        self.assertTrue(result.is_ok())
        locs = result.unwrap()
        self.assertEqual(len(locs), 2)
        self.assertEqual(locs[0].name, "nyc1")

    def test_get_server_types(self) -> None:
        svc, client = _make_service()
        client.sizes.list.return_value = {
            "sizes": [
                {"slug": "s-1vcpu-1gb", "vcpus": 1, "memory": 1024, "disk": 25, "available": True},
                {"slug": "s-2vcpu-2gb", "vcpus": 2, "memory": 2048, "disk": 50, "available": True},
            ],
        }
        result = svc.get_server_types()
        self.assertTrue(result.is_ok())
        types = result.unwrap()
        self.assertEqual(len(types), 2)
        self.assertEqual(types[0].vcpus, 1)
        self.assertAlmostEqual(types[0].memory_gb, 1.0)


class TestDigitalOceanServicePollingTimeout(TestCase):
    @patch("apps.infrastructure.digitalocean_service.time")
    def test_polling_timeout(self, mock_time: MagicMock) -> None:
        svc, client = _make_service()
        # Simulate time passing beyond timeout
        mock_time.monotonic.side_effect = [0, 0, 301]
        mock_time.sleep = MagicMock()
        client.actions.get.return_value = {"action": {"status": "in-progress"}}

        with self.assertRaises(TimeoutError):
            svc._wait_for_action(999)


class TestDigitalOceanCountryCode(TestCase):
    """H13: Country code must be valid ISO 3166-1, not slug prefix."""

    def test_country_code_is_valid_iso(self) -> None:
        """'nyc1' → 'US', not 'NYC'."""
        svc, client = _make_service()
        client.regions.list.return_value = {
            "regions": [
                {"slug": "nyc1", "name": "New York 1", "available": True},
                {"slug": "lon1", "name": "London 1", "available": True},
                {"slug": "ams3", "name": "Amsterdam 3", "available": True},
                {"slug": "sgp1", "name": "Singapore 1", "available": True},
                {"slug": "fra1", "name": "Frankfurt 1", "available": True},
                {"slug": "blr1", "name": "Bangalore 1", "available": True},
                {"slug": "sfo3", "name": "San Francisco 3", "available": True},
                {"slug": "tor1", "name": "Toronto 1", "available": True},
                {"slug": "syd1", "name": "Sydney 1", "available": True},
            ],
        }
        result = svc.get_locations()
        self.assertTrue(result.is_ok())
        locs = result.unwrap()

        # Build a map slug → country for verification
        country_map = {loc.name: loc.country for loc in locs}
        self.assertEqual(country_map["nyc1"], "US")
        self.assertEqual(country_map["lon1"], "GB")
        self.assertEqual(country_map["ams3"], "NL")
        self.assertEqual(country_map["sgp1"], "SG")
        self.assertEqual(country_map["fra1"], "DE")
        self.assertEqual(country_map["blr1"], "IN")
        self.assertEqual(country_map["sfo3"], "US")
        self.assertEqual(country_map["tor1"], "CA")
        self.assertEqual(country_map["syd1"], "AU")

        # Verify none are 3-char slug prefixes
        for loc in locs:
            self.assertEqual(len(loc.country), 2, f"Country code for {loc.name} should be 2 chars, got '{loc.country}'")


class TestDigitalOceanSSHKeyWarning(TestCase):
    """M11: _resolve_ssh_key_ids should warn on missing keys."""

    def test_resolve_ssh_key_ids_warns_on_missing(self) -> None:
        svc, client = _make_service()
        # Return no keys — all lookups will fail
        client.ssh_keys.list.return_value = {"ssh_keys": []}

        with self.assertLogs("apps.infrastructure.digitalocean_service", level="WARNING") as cm:
            ids = svc._resolve_ssh_key_ids(["missing-key", "also-missing"])

        self.assertEqual(ids, [])
        # Should have 2 warnings
        self.assertEqual(len(cm.output), 2)
        self.assertIn("missing-key", cm.output[0])
        self.assertIn("also-missing", cm.output[1])

    def test_resolve_ssh_key_ids_found_keys_no_warning(self) -> None:
        svc, client = _make_service()
        client.ssh_keys.list.return_value = {
            "ssh_keys": [{"id": 1, "name": "my-key"}],
        }

        # No warnings should be emitted for found keys
        ids = svc._resolve_ssh_key_ids(["my-key"])
        self.assertEqual(ids, [1])


class TestDigitalOceanDeleteFirewallIdempotent(TestCase):
    """delete_firewall returns Ok(True) if already gone (404)."""

    def test_delete_firewall_404_returns_ok(self) -> None:
        svc, client = _make_service()
        client.firewalls.delete.side_effect = RuntimeError("404 not found")
        result = svc.delete_firewall("fw-gone")
        self.assertTrue(result.is_ok())


class TestDigitalOceanStatusNormalization(TestCase):
    """DigitalOcean normalizes droplet status to canonical values."""

    def test_active_normalized_to_running(self) -> None:
        svc, client = _make_service()
        client.droplets.get.return_value = {"droplet": _droplet_dict(status="active")}
        result = svc.get_server("12345")
        self.assertTrue(result.is_ok())
        info = result.unwrap()
        self.assertIsNotNone(info)
        self.assertEqual(info.status, "running")  # 'active' → 'running'
