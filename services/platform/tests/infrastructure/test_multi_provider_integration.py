"""
Multi-provider integration tests.

Verifies the gateway factory, provider config registry, and sync registry
all agree on which providers are available.
"""

from __future__ import annotations

import json

from django.test import TestCase

from apps.infrastructure.cloud_gateway import (
    CloudProviderGateway,
    get_cloud_gateway,
    get_registered_providers,
)
from apps.infrastructure.provider_config import (
    PROVIDER_CONFIG,
    get_registered_sync_providers,
)

# Import provider modules to trigger gateway + sync function registration
import apps.infrastructure.hcloud_service  # noqa: F401
import apps.infrastructure.digitalocean_service  # noqa: F401
import apps.infrastructure.vultr_service  # noqa: F401
import apps.infrastructure.aws_service  # side-effect: registers sync fn
import apps.infrastructure.provider_sync  # noqa: F401

# AWS expects JSON credentials
AWS_TEST_TOKEN = json.dumps({
    "access_key_id": "test",
    "secret_access_key": "test",
    "region": "us-east-1",
})


def _get_test_token(provider_type: str) -> str:
    """Get a test token appropriate for the provider."""
    if provider_type == "aws":
        return AWS_TEST_TOKEN
    return "test-token"


class TestGatewayFactory(TestCase):
    """Tests for the cloud gateway factory."""

    def test_gateway_factory_returns_correct_provider_hetzner(self):
        """Hetzner gateway is returned for 'hetzner'."""
        gw = get_cloud_gateway("hetzner", token=_get_test_token("hetzner"))
        self.assertIsInstance(gw, CloudProviderGateway)
        self.assertIn("Hcloud", type(gw).__name__)

    def test_gateway_factory_returns_correct_provider_digitalocean(self):
        """DigitalOcean gateway is returned for 'digitalocean'."""
        gw = get_cloud_gateway("digitalocean", token=_get_test_token("digitalocean"))
        self.assertIsInstance(gw, CloudProviderGateway)
        self.assertIn("DigitalOcean", type(gw).__name__)

    def test_gateway_factory_returns_correct_provider_vultr(self):
        """Vultr gateway is returned for 'vultr'."""
        gw = get_cloud_gateway("vultr", token=_get_test_token("vultr"))
        self.assertIsInstance(gw, CloudProviderGateway)
        self.assertIn("Vultr", type(gw).__name__)

    def test_gateway_factory_returns_correct_provider_aws(self):
        """AWS gateway is returned for 'aws'."""
        gw = get_cloud_gateway("aws", token=_get_test_token("aws"))
        self.assertIsInstance(gw, CloudProviderGateway)
        self.assertIn("AWS", type(gw).__name__)

    def test_gateway_factory_unknown_provider_raises(self):
        """ValueError for unknown provider type."""
        with self.assertRaises(ValueError) as ctx:
            get_cloud_gateway("unknown", token="test")
        self.assertIn("unknown", str(ctx.exception).lower())

    def test_all_providers_implement_all_methods(self):
        """No abstract method raises NotImplementedError after instantiation."""
        abstract_methods = [
            m for m in dir(CloudProviderGateway)
            if getattr(getattr(CloudProviderGateway, m, None), "__isabstractmethod__", False)
        ]
        for provider_type in get_registered_providers():
            gw = get_cloud_gateway(provider_type, token=_get_test_token(provider_type))
            for method_name in abstract_methods:
                method = getattr(gw, method_name, None)
                self.assertIsNotNone(
                    method,
                    f"{provider_type} missing method: {method_name}",
                )
                # Verify the method is callable (not abstract)
                self.assertTrue(
                    callable(method),
                    f"{provider_type}.{method_name} is not callable",
                )


class TestRegistryConsistency(TestCase):
    """Verify all registries are consistent."""

    def test_provider_config_has_all_registered_providers(self):
        """PROVIDER_CONFIG keys should include all gateway-registered providers."""
        gateway_providers = set(get_registered_providers())
        config_providers = set(PROVIDER_CONFIG.keys())
        missing = gateway_providers - config_providers
        self.assertEqual(
            missing,
            set(),
            f"Gateway providers missing from PROVIDER_CONFIG: {missing}",
        )

    def test_sync_registry_has_all_providers(self):
        """Sync function registry should cover all gateway-registered providers."""
        gateway_providers = set(get_registered_providers())
        sync_providers = get_registered_sync_providers()
        missing = gateway_providers - sync_providers
        self.assertEqual(
            missing,
            set(),
            f"Gateway providers missing from sync registry: {missing}",
        )
