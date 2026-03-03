"""
Tests for hcloud_service.py

Tests the HcloudService wrapper around the hcloud Python SDK.
All hcloud.Client interactions are mocked — no real API calls.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase

from apps.infrastructure.hcloud_service import HcloudResult, HcloudServerInfo, HcloudService


def _make_mock_server(  # noqa: PLR0913
    server_id: int = 42,
    name: str = "test-server",
    status: str = "running",
    ipv4: str = "1.2.3.4",
    ipv6: str = "2001:db8::1",
    server_type_name: str = "cpx21",
    location_name: str = "fsn1",
    labels: dict[str, str] | None = None,
) -> mock.Mock:
    """Build a mock hcloud Server domain object."""
    server = mock.Mock()
    server.id = server_id
    server.name = name
    server.status = status
    server.public_net.ipv4.ip = ipv4
    server.public_net.ipv6.ip = ipv6
    server.server_type.name = server_type_name
    server.location.name = location_name
    server.labels = labels or {}
    return server


def _make_service() -> tuple[HcloudService, mock.Mock]:
    """Create an HcloudService with a mocked Client."""
    with mock.patch("apps.infrastructure.hcloud_service.Client") as mock_client_cls:
        client_instance = mock.Mock()
        mock_client_cls.return_value = client_instance
        svc = HcloudService(token="fake-token")
    return svc, client_instance


class TestCreateServer(TestCase):
    """Tests for HcloudService.create_server()."""

    def test_create_server_success(self):
        """Successful server creation returns Ok with populated HcloudResult."""
        svc, client = _make_service()
        server = _make_mock_server()
        action = mock.Mock()

        response = mock.Mock()
        response.server = server
        response.action = action
        response.root_password = "secret123"
        client.servers.create.return_value = response

        result = svc.create_server(
            name="prd-sha-het-de-fsn1-001",
            server_type="cpx21",
            location="fsn1",
            ssh_keys=["my-key"],
            labels={"env": "prd"},
        )

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertIsInstance(data, HcloudResult)
        self.assertTrue(data.success)
        self.assertEqual(data.server_id, "42")
        self.assertEqual(data.ipv4_address, "1.2.3.4")
        self.assertEqual(data.ipv6_address, "2001:db8::1")
        self.assertEqual(data.root_password, "secret123")
        action.wait_until_finished.assert_called_once()

    def test_create_server_error(self):
        """API exception returns Err with descriptive message."""
        svc, client = _make_service()
        client.servers.create.side_effect = Exception("API rate limit exceeded")

        result = svc.create_server(
            name="test", server_type="cpx21", location="fsn1", ssh_keys=["k"]
        )

        self.assertTrue(result.is_err())
        self.assertIn("Server creation failed", result.unwrap_err())
        self.assertIn("API rate limit exceeded", result.unwrap_err())

    def test_create_server_timeout(self):
        """Timeout during action.wait_until_finished returns Err."""
        svc, client = _make_service()
        server = _make_mock_server()
        action = mock.Mock()
        action.wait_until_finished.side_effect = Exception("Action timed out after 300s")

        response = mock.Mock()
        response.server = server
        response.action = action
        response.root_password = ""
        client.servers.create.return_value = response

        result = svc.create_server(
            name="test", server_type="cpx21", location="fsn1", ssh_keys=[]
        )

        self.assertTrue(result.is_err())
        self.assertIn("timed out", result.unwrap_err())

    def test_create_server_no_public_net(self):
        """Server with no public_net still returns Ok with empty IPs."""
        svc, client = _make_service()
        server = mock.Mock()
        server.id = 99
        server.public_net = None

        action = mock.Mock()
        response = mock.Mock()
        response.server = server
        response.action = action
        response.root_password = None
        client.servers.create.return_value = response

        result = svc.create_server(
            name="test", server_type="cpx21", location="fsn1", ssh_keys=[]
        )

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data.ipv4_address, "")
        self.assertEqual(data.ipv6_address, "")
        self.assertEqual(data.root_password, "")


class TestDeleteServer(TestCase):
    """Tests for HcloudService.delete_server()."""

    def test_delete_server_success(self):
        """Successful deletion returns Ok."""
        svc, client = _make_service()
        server = _make_mock_server()
        client.servers.get_by_id.return_value = server
        action = mock.Mock()
        client.servers.delete.return_value = action

        result = svc.delete_server(42)

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertTrue(data.success)
        self.assertEqual(data.server_id, "42")
        action.wait_until_finished.assert_called_once()

    def test_delete_server_not_found(self):
        """Deleting a nonexistent server returns Err."""
        svc, client = _make_service()
        client.servers.get_by_id.side_effect = Exception("Server not found")

        result = svc.delete_server(999)

        self.assertTrue(result.is_err())
        self.assertIn("Server deletion failed", result.unwrap_err())


class TestGetServer(TestCase):
    """Tests for HcloudService.get_server()."""

    def test_get_server_success(self):
        """Successful get returns Ok with HcloudServerInfo."""
        svc, client = _make_service()
        server = _make_mock_server(server_id=10, name="web1", status="running")
        client.servers.get_by_id.return_value = server

        result = svc.get_server(10)

        self.assertTrue(result.is_ok())
        info = result.unwrap()
        self.assertIsInstance(info, HcloudServerInfo)
        self.assertEqual(info.server_id, 10)
        self.assertEqual(info.name, "web1")
        self.assertEqual(info.status, "running")
        self.assertEqual(info.ipv4_address, "1.2.3.4")
        self.assertEqual(info.server_type, "cpx21")
        self.assertEqual(info.location, "fsn1")

    def test_get_server_not_found(self):
        """Getting a nonexistent server returns Err."""
        svc, client = _make_service()
        client.servers.get_by_id.side_effect = Exception("not found")

        result = svc.get_server(999)

        self.assertTrue(result.is_err())
        self.assertIn("Failed to get server 999", result.unwrap_err())


class TestPowerOperations(TestCase):
    """Tests for power_on, power_off, and reboot."""

    def setUp(self):
        self.svc, self.client = _make_service()
        self.server = _make_mock_server()
        self.client.servers.get_by_id.return_value = self.server
        self.action = mock.Mock()

    def test_power_on_success(self):
        self.client.servers.power_on.return_value = self.action

        result = self.svc.power_on(42)

        self.assertTrue(result.is_ok())
        self.assertTrue(result.unwrap())
        self.action.wait_until_finished.assert_called_once()

    def test_power_on_error(self):
        self.client.servers.power_on.side_effect = Exception("already on")

        result = self.svc.power_on(42)

        self.assertTrue(result.is_err())
        self.assertIn("Power on failed", result.unwrap_err())

    def test_power_off_success(self):
        self.client.servers.power_off.return_value = self.action

        result = self.svc.power_off(42)

        self.assertTrue(result.is_ok())
        self.assertTrue(result.unwrap())

    def test_power_off_error(self):
        self.client.servers.power_off.side_effect = Exception("timeout")

        result = self.svc.power_off(42)

        self.assertTrue(result.is_err())
        self.assertIn("Power off failed", result.unwrap_err())

    def test_reboot_success(self):
        self.client.servers.reboot.return_value = self.action

        result = self.svc.reboot(42)

        self.assertTrue(result.is_ok())
        self.assertTrue(result.unwrap())

    def test_reboot_error(self):
        self.client.servers.reboot.side_effect = Exception("server locked")

        result = self.svc.reboot(42)

        self.assertTrue(result.is_err())
        self.assertIn("Reboot failed", result.unwrap_err())


class TestGetLocations(TestCase):
    """Tests for HcloudService.get_locations()."""

    def test_get_locations_returns_list(self):
        svc, client = _make_service()
        loc1 = mock.Mock(name="fsn1")
        loc2 = mock.Mock(name="nbg1")
        client.locations.get_all.return_value = [loc1, loc2]

        result = svc.get_locations()

        self.assertTrue(result.is_ok())
        self.assertEqual(len(result.unwrap()), 2)

    def test_get_locations_error(self):
        svc, client = _make_service()
        client.locations.get_all.side_effect = Exception("unauthorized")

        result = svc.get_locations()

        self.assertTrue(result.is_err())
        self.assertIn("Failed to get locations", result.unwrap_err())


class TestGetServerTypes(TestCase):
    """Tests for HcloudService.get_server_types()."""

    def test_get_server_types_returns_list(self):
        svc, client = _make_service()
        st1 = mock.Mock()
        st2 = mock.Mock()
        client.server_types.get_all.return_value = [st1, st2]

        result = svc.get_server_types()

        self.assertTrue(result.is_ok())
        self.assertEqual(len(result.unwrap()), 2)

    def test_get_server_types_error(self):
        svc, client = _make_service()
        client.server_types.get_all.side_effect = Exception("connection error")

        result = svc.get_server_types()

        self.assertTrue(result.is_err())
        self.assertIn("Failed to get server types", result.unwrap_err())


class TestUploadSshKey(TestCase):
    """Tests for HcloudService.upload_ssh_key()."""

    def test_upload_new_key(self):
        """New key is created when no existing key found."""
        svc, client = _make_service()
        client.ssh_keys.get_by_name.return_value = None
        new_key = mock.Mock()
        client.ssh_keys.create.return_value = new_key

        result = svc.upload_ssh_key("deploy-key", "ssh-ed25519 AAAA...")

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), new_key)
        client.ssh_keys.create.assert_called_once_with(
            name="deploy-key", public_key="ssh-ed25519 AAAA..."
        )

    def test_upload_duplicate_key_returns_existing(self):
        """Existing key is returned without creating a new one."""
        svc, client = _make_service()
        existing_key = mock.Mock()
        client.ssh_keys.get_by_name.return_value = existing_key

        result = svc.upload_ssh_key("deploy-key", "ssh-ed25519 AAAA...")

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), existing_key)
        client.ssh_keys.create.assert_not_called()

    def test_upload_ssh_key_error(self):
        """API error returns Err."""
        svc, client = _make_service()
        client.ssh_keys.get_by_name.side_effect = Exception("forbidden")

        result = svc.upload_ssh_key("key", "ssh-rsa AAAA...")

        self.assertTrue(result.is_err())
        self.assertIn("SSH key upload failed", result.unwrap_err())
