"""
Tests for CloudProviderGateway ABC, factory, and HcloudService implementation.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.infrastructure.cloud_gateway import (
    CloudProviderGateway,
    FirewallRule,
    LocationInfo,
    SSHKeyResult,
    ServerCreateRequest,
    ServerCreateResult,
    ServerInfo,
    ServerTypeInfo,
    STANDARD_FIREWALL_RULES,
    _PROVIDER_REGISTRY,
    get_cloud_gateway,
    get_registered_providers,
    normalize_server_status,
    register_cloud_gateway,
)


class TestCloudProviderGatewayABC(TestCase):
    """Test the ABC cannot be instantiated directly."""

    def test_cannot_instantiate_abc(self):
        with self.assertRaises(TypeError):
            CloudProviderGateway()  # type: ignore[abstract]

    def test_server_create_request_defaults(self):
        req = ServerCreateRequest(name="test", server_type="cpx21", location="fsn1", ssh_keys=["key1"])
        self.assertEqual(req.image, "ubuntu-22.04")
        self.assertEqual(req.labels, {})
        self.assertEqual(req.firewall_ids, [])

    def test_server_create_result_fields(self):
        result = ServerCreateResult(server_id="123", ipv4_address="1.2.3.4")
        self.assertEqual(result.server_id, "123")
        self.assertEqual(result.ipv6_address, "")

    def test_server_info_fields(self):
        info = ServerInfo(server_id="456", name="test-server", status="running", ipv4_address="5.6.7.8")
        self.assertEqual(info.server_type, "")
        self.assertEqual(info.labels, {})

    def test_ssh_key_result_fields(self):
        key = SSHKeyResult(key_id="789", name="my-key")
        self.assertEqual(key.fingerprint, "")

    def test_firewall_rule_defaults(self):
        rule = FirewallRule(port="22")
        self.assertEqual(rule.direction, "in")
        self.assertEqual(rule.protocol, "tcp")
        self.assertIn("0.0.0.0/0", rule.source_ips)
        self.assertIn("::/0", rule.source_ips)

    def test_location_info_fields(self):
        loc = LocationInfo(name="fsn1", country="DE", city="Falkenstein")
        self.assertEqual(loc.description, "")

    def test_server_type_info_fields(self):
        st = ServerTypeInfo(name="cpx21", vcpus=3, memory_gb=4.0, disk_gb=80)
        self.assertEqual(st.description, "")


class TestStandardFirewallRules(TestCase):
    """Test the standard firewall rule set."""

    def test_has_ssh_rule(self):
        ports = [r.port for r in STANDARD_FIREWALL_RULES]
        self.assertIn("22", ports)

    def test_has_http_rule(self):
        ports = [r.port for r in STANDARD_FIREWALL_RULES]
        self.assertIn("80", ports)

    def test_has_https_rule(self):
        ports = [r.port for r in STANDARD_FIREWALL_RULES]
        self.assertIn("443", ports)

    def test_has_webmin_rule(self):
        ports = [r.port for r in STANDARD_FIREWALL_RULES]
        self.assertIn("10000", ports)

    def test_all_rules_are_tcp_inbound(self):
        for rule in STANDARD_FIREWALL_RULES:
            self.assertEqual(rule.direction, "in")
            self.assertEqual(rule.protocol, "tcp")


class TestGatewayFactory(TestCase):
    """Test the provider registry and factory."""

    def test_hetzner_is_registered(self):
        # Importing hcloud_service registers it
        from apps.infrastructure.hcloud_service import HcloudService  # noqa: F401, PLC0415

        self.assertIn("hetzner", get_registered_providers())

    def test_get_cloud_gateway_hetzner(self):
        from apps.infrastructure.hcloud_service import HcloudService  # noqa: PLC0415

        with patch.object(HcloudService, "__init__", lambda self, **kw: setattr(self, "client", MagicMock())):
            gw = get_cloud_gateway("hetzner", token="test-token")
            self.assertIsInstance(gw, CloudProviderGateway)
            self.assertIsInstance(gw, HcloudService)

    def test_get_cloud_gateway_unknown_raises(self):
        with self.assertRaises(ValueError) as ctx:
            get_cloud_gateway("nonexistent_provider", token="xxx")
        self.assertIn("nonexistent_provider", str(ctx.exception))

    def test_register_custom_provider(self):
        class DummyGateway(CloudProviderGateway):
            def __init__(self, token: str, **kwargs):
                pass

            def create_server(self, request):
                pass

            def delete_server(self, server_id):
                pass

            def get_server(self, server_id):
                pass

            def power_on(self, server_id):
                pass

            def power_off(self, server_id):
                pass

            def reboot(self, server_id):
                pass

            def resize(self, server_id, server_type):
                pass

            def upload_ssh_key(self, name, public_key):
                pass

            def delete_ssh_key(self, name):
                pass

            def create_firewall(self, name, rules, labels=None):
                pass

            def delete_firewall(self, firewall_id):
                pass

            def get_locations(self):
                pass

            def get_server_types(self):
                pass

            def create_snapshot(self, server_id, name):
                pass

            def restore_snapshot(self, server_id, snapshot_id):
                pass

            def list_snapshots(self, server_id):
                pass

            def delete_snapshot(self, snapshot_id):
                pass

        register_cloud_gateway("test_dummy", DummyGateway)
        self.addCleanup(lambda: _PROVIDER_REGISTRY.pop("test_dummy", None))
        self.assertIn("test_dummy", get_registered_providers())
        gw = get_cloud_gateway("test_dummy", token="xxx")
        self.assertIsInstance(gw, DummyGateway)

    def test_get_registered_providers_returns_sorted(self):
        providers = get_registered_providers()
        self.assertEqual(providers, sorted(providers))

    def test_register_overwrites_existing(self):
        """Re-registering a provider replaces the previous gateway class."""

        class GatewayV1(CloudProviderGateway):
            def __init__(self, token: str, **kwargs):
                pass

            def create_server(self, request):
                pass

            def delete_server(self, server_id):
                pass

            def get_server(self, server_id):
                pass

            def power_on(self, server_id):
                pass

            def power_off(self, server_id):
                pass

            def reboot(self, server_id):
                pass

            def resize(self, server_id, server_type):
                pass

            def upload_ssh_key(self, name, public_key):
                pass

            def delete_ssh_key(self, name):
                pass

            def create_firewall(self, name, rules, labels=None):
                pass

            def delete_firewall(self, firewall_id):
                pass

            def get_locations(self):
                pass

            def get_server_types(self):
                pass

            def create_snapshot(self, server_id, name):
                pass

            def restore_snapshot(self, server_id, snapshot_id):
                pass

            def list_snapshots(self, server_id):
                pass

            def delete_snapshot(self, snapshot_id):
                pass

        class GatewayV2(GatewayV1):
            pass

        register_cloud_gateway("test_overwrite", GatewayV1)
        self.addCleanup(lambda: _PROVIDER_REGISTRY.pop("test_overwrite", None))
        self.assertIs(_PROVIDER_REGISTRY["test_overwrite"], GatewayV1)

        register_cloud_gateway("test_overwrite", GatewayV2)
        self.assertIs(_PROVIDER_REGISTRY["test_overwrite"], GatewayV2)

    def test_digitalocean_is_registered(self):
        """DigitalOcean gateway is registered when its module is imported."""
        from apps.infrastructure.digitalocean_service import DigitalOceanService  # noqa: F401, PLC0415

        self.assertIn("digitalocean", get_registered_providers())

    def test_vultr_is_registered(self):
        """Vultr gateway is registered when its module is imported."""
        from apps.infrastructure.vultr_service import VultrService  # noqa: F401, PLC0415

        self.assertIn("vultr", get_registered_providers())

    def test_aws_is_registered(self):
        """AWS gateway is registered when its module is imported."""
        from apps.infrastructure.aws_service import AWSService  # noqa: F401, PLC0415

        self.assertIn("aws", get_registered_providers())


class TestNormalizeServerStatus(TestCase):
    """Tests for normalize_server_status function (M13 finding)."""

    def test_normalize_server_status_known_mappings(self):
        """Known provider statuses map to canonical values."""
        self.assertEqual(normalize_server_status("active"), "running")
        self.assertEqual(normalize_server_status("new"), "initializing")
        self.assertEqual(normalize_server_status("pending"), "initializing")
        self.assertEqual(normalize_server_status("shutting-down"), "stopping")
        self.assertEqual(normalize_server_status("terminated"), "off")
        self.assertEqual(normalize_server_status("stopped"), "off")
        self.assertEqual(normalize_server_status("stopping"), "stopping")
        self.assertEqual(normalize_server_status("archive"), "off")

    def test_normalize_server_status_passthrough_unknown(self):
        """Unknown statuses pass through unchanged."""
        self.assertEqual(normalize_server_status("running"), "running")
        self.assertEqual(normalize_server_status("custom-status"), "custom-status")
        self.assertEqual(normalize_server_status("rebuilding"), "rebuilding")

    def test_normalize_server_status_empty_string(self):
        """Empty string passes through unchanged."""
        self.assertEqual(normalize_server_status(""), "")


class TestFirewallRuleSourceIps(TestCase):
    """Test that FirewallRule default source_ips are not shared across instances."""

    def test_firewall_rule_source_ips_not_shared(self):
        """Each FirewallRule gets its own source_ips list (not shared mutable default)."""
        rule1 = FirewallRule(port="22")
        rule2 = FirewallRule(port="80")
        rule1.source_ips.append("10.0.0.0/8")
        # rule2's source_ips should NOT be affected
        self.assertNotIn("10.0.0.0/8", rule2.source_ips)
        self.assertEqual(len(rule2.source_ips), 2)
