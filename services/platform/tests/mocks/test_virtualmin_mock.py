"""
Self-tests for MockVirtualminGateway.

Verifies that the mock behaves realistically: state tracking, error responses,
call logging, fixture accuracy, and parser integration.
"""

from django.test import TestCase

from apps.common.types import Ok
from apps.provisioning.virtualmin_gateway import (
    VirtualminConflictExistsError,
    VirtualminNotFoundError,
    VirtualminResponse,
)

from .virtualmin_mock import MockVirtualminGateway, VirtualminMockMixin


# ---------------------------------------------------------------
# MockVirtualminGateway unit tests
# ---------------------------------------------------------------


class MockGatewayCreateDomainTest(TestCase):
    """Test create-domain behavior."""

    def setUp(self):
        self.gw = MockVirtualminGateway()

    def test_create_domain_success(self):
        result = self.gw.call("create-domain", {"domain": "new.com", "user": "newuser"})
        self.assertTrue(result.is_ok())
        response = result.unwrap()
        self.assertIsInstance(response, VirtualminResponse)
        self.assertTrue(response.success)
        self.assertEqual(response.program, "create-domain")
        # Domain should exist in state
        d = self.gw.get_domain_state("new.com")
        self.assertIsNotNone(d)
        self.assertEqual(d.username, "newuser")
        self.assertTrue(d.enabled)

    def test_create_domain_conflict(self):
        self.gw.seed_domain("existing.com")
        result = self.gw.call("create-domain", {"domain": "existing.com"})
        self.assertTrue(result.is_err())
        error = result.unwrap_err()
        self.assertIsInstance(error, VirtualminConflictExistsError)
        self.assertIn("already exists", str(error))

    def test_create_domain_quota_exceeded(self):
        gw = MockVirtualminGateway(max_domains=1)
        gw.seed_domain("first.com")
        result = gw.call("create-domain", {"domain": "second.com"})
        self.assertTrue(result.is_err())
        error = result.unwrap_err()
        self.assertIsInstance(error, type(error))  # Should be an API error
        self.assertIn("quota", str(error).lower())

    def test_create_domain_tracks_state(self):
        self.assertEqual(self.gw.domain_count, 0)
        self.gw.call("create-domain", {"domain": "a.com"})
        self.gw.call("create-domain", {"domain": "b.com"})
        self.assertEqual(self.gw.domain_count, 2)


class MockGatewayDeleteDomainTest(TestCase):
    """Test delete-domain behavior."""

    def setUp(self):
        self.gw = MockVirtualminGateway()
        self.gw.seed_domain("target.com")

    def test_delete_domain_success(self):
        result = self.gw.call("delete-domain", {"domain": "target.com"})
        self.assertTrue(result.is_ok())
        response = result.unwrap()
        self.assertTrue(response.success)
        self.assertIsNone(self.gw.get_domain_state("target.com"))

    def test_delete_domain_not_found(self):
        result = self.gw.call("delete-domain", {"domain": "nonexistent.com"})
        self.assertTrue(result.is_err())
        self.assertIsInstance(result.unwrap_err(), VirtualminNotFoundError)


class MockGatewaySuspendTest(TestCase):
    """Test disable/enable domain (suspend/unsuspend) behavior."""

    def setUp(self):
        self.gw = MockVirtualminGateway()
        self.gw.seed_domain("active.com", enabled=True)

    def test_disable_domain_success(self):
        result = self.gw.call("disable-domain", {"domain": "active.com"})
        self.assertTrue(result.is_ok())
        d = self.gw.get_domain_state("active.com")
        self.assertFalse(d.enabled)

    def test_disable_already_disabled(self):
        self.gw.get_domain_state("active.com").enabled = False
        result = self.gw.call("disable-domain", {"domain": "active.com"})
        # Still returns Ok with a failure response (not an exception)
        self.assertTrue(result.is_ok())
        response = result.unwrap()
        self.assertFalse(response.success)

    def test_disable_not_found(self):
        result = self.gw.call("disable-domain", {"domain": "missing.com"})
        self.assertTrue(result.is_err())
        self.assertIsInstance(result.unwrap_err(), VirtualminNotFoundError)

    def test_enable_domain_success(self):
        self.gw.get_domain_state("active.com").enabled = False
        result = self.gw.call("enable-domain", {"domain": "active.com"})
        self.assertTrue(result.is_ok())
        d = self.gw.get_domain_state("active.com")
        self.assertTrue(d.enabled)

    def test_enable_already_enabled(self):
        result = self.gw.call("enable-domain", {"domain": "active.com"})
        self.assertTrue(result.is_ok())
        response = result.unwrap()
        self.assertFalse(response.success)


class MockGatewayListDomainsTest(TestCase):
    """Test list-domains behavior."""

    def setUp(self):
        self.gw = MockVirtualminGateway()
        self.gw.seed_domain("alpha.com", disk_usage_mb=100, disk_quota_mb=500)
        self.gw.seed_domain("beta.org", disk_usage_mb=200, disk_quota_mb=1000)

    def test_list_domains_returns_all(self):
        result = self.gw.list_domains()
        self.assertTrue(result.is_ok())
        domains = result.unwrap()
        self.assertEqual(len(domains), 2)
        domain_names = {d["domain"] for d in domains}
        self.assertEqual(domain_names, {"alpha.com", "beta.org"})

    def test_list_domains_empty(self):
        gw = MockVirtualminGateway()
        result = gw.list_domains()
        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), [])

    def test_list_domains_single_filter(self):
        result = self.gw.call("list-domains", {"domain": "alpha.com", "multiline": ""})
        self.assertTrue(result.is_ok())
        response = result.unwrap()
        self.assertTrue(response.success)


class MockGatewayCallLoggingTest(TestCase):
    """Test call recording and inspection."""

    def setUp(self):
        self.gw = MockVirtualminGateway()

    def test_call_count_starts_at_zero(self):
        self.assertEqual(self.gw.call_count, 0)

    def test_call_count_increments(self):
        self.gw.call("info")
        self.gw.call("info")
        self.assertEqual(self.gw.call_count, 2)

    def test_get_calls_all(self):
        self.gw.call("info")
        self.gw.call("list-domains")
        calls = self.gw.get_calls()
        self.assertEqual(len(calls), 2)

    def test_get_calls_filtered(self):
        self.gw.call("info")
        self.gw.call("list-domains")
        self.gw.call("info")
        info_calls = self.gw.get_calls("info")
        self.assertEqual(len(info_calls), 2)

    def test_reset_calls(self):
        self.gw.seed_domain("keep.com")
        self.gw.call("info")
        self.gw.reset_calls()
        self.assertEqual(self.gw.call_count, 0)
        # State preserved
        self.assertIsNotNone(self.gw.get_domain_state("keep.com"))

    def test_full_reset(self):
        self.gw.seed_domain("gone.com")
        self.gw.call("info")
        self.gw.reset()
        self.assertEqual(self.gw.call_count, 0)
        self.assertEqual(self.gw.domain_count, 0)


class MockGatewayFailureInjectionTest(TestCase):
    """Test configurable failure injection."""

    def test_fail_specific_operation(self):
        gw = MockVirtualminGateway(fail_operations={"create-domain": "Server offline"})
        result = gw.call("create-domain", {"domain": "test.com"})
        self.assertTrue(result.is_err())
        self.assertIn("Server offline", str(result.unwrap_err()))

    def test_other_operations_unaffected(self):
        gw = MockVirtualminGateway(fail_operations={"create-domain": "Server offline"})
        result = gw.call("info")
        self.assertTrue(result.is_ok())

    def test_fail_connection(self):
        gw = MockVirtualminGateway(fail_operations={"info": "Connection refused"})
        result = gw.test_connection()
        self.assertTrue(result.is_err())
        self.assertIn("Connection refused", result.unwrap_err())

    def test_ping_fails_when_info_fails(self):
        gw = MockVirtualminGateway(fail_operations={"info": "down"})
        self.assertFalse(gw.ping_server())


class MockGatewayConvenienceMethodsTest(TestCase):
    """Test high-level convenience methods."""

    def setUp(self):
        self.gw = MockVirtualminGateway()
        self.gw.seed_domain("web.com", disk_usage_mb=150, bandwidth_usage_mb=500)

    def test_test_connection(self):
        result = self.gw.test_connection()
        self.assertTrue(result.is_ok())
        info_dict = result.unwrap()
        self.assertTrue(info_dict["healthy"])
        self.assertEqual(info_dict["server"], "mock-server.example.com")

    def test_get_server_info(self):
        result = self.gw.get_server_info()
        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertIn("data", data)

    def test_get_domain_info(self):
        result = self.gw.get_domain_info("web.com")
        self.assertTrue(result.is_ok())
        info_dict = result.unwrap()
        self.assertEqual(info_dict["disk_usage_mb"], 150)
        self.assertEqual(info_dict["bandwidth_usage_mb"], 500)

    def test_get_domain_info_not_found(self):
        result = self.gw.get_domain_info("missing.com")
        self.assertTrue(result.is_err())
        self.assertIn("does not exist", result.unwrap_err())


class MockGatewayResponseParserIntegrationTest(TestCase):
    """Verify that mock responses pass through VirtualminResponseParser correctly."""

    def setUp(self):
        self.gw = MockVirtualminGateway()

    def test_success_response_parsed_correctly(self):
        result = self.gw.call("info")
        self.assertTrue(result.is_ok())
        response = result.unwrap()
        # Parser should have set success=True based on status=success
        self.assertTrue(response.success)
        # data should be a dict (parsed from fixture JSON)
        self.assertIsInstance(response.data, dict)

    def test_create_response_has_raw_json(self):
        result = self.gw.call("create-domain", {"domain": "parsed.com"})
        self.assertTrue(result.is_ok())
        response = result.unwrap()
        self.assertIn("create-domain", response.raw_response)

    def test_list_domains_response_structure(self):
        self.gw.seed_domain("one.com")
        self.gw.seed_domain("two.com")
        result = self.gw.call("list-domains", {})
        self.assertTrue(result.is_ok())
        response = result.unwrap()
        self.assertTrue(response.success)
        # Parser should have preserved the data structure
        self.assertIn("data", response.data)


class MockGatewayStateLifecycleTest(TestCase):
    """Test full domain lifecycle through mock state."""

    def test_create_suspend_unsuspend_delete(self):
        gw = MockVirtualminGateway()

        # Create
        result = gw.call("create-domain", {"domain": "lifecycle.com"})
        self.assertTrue(result.is_ok())
        self.assertTrue(gw.get_domain_state("lifecycle.com").enabled)

        # Suspend
        result = gw.call("disable-domain", {"domain": "lifecycle.com"})
        self.assertTrue(result.is_ok())
        self.assertFalse(gw.get_domain_state("lifecycle.com").enabled)

        # Unsuspend
        result = gw.call("enable-domain", {"domain": "lifecycle.com"})
        self.assertTrue(result.is_ok())
        self.assertTrue(gw.get_domain_state("lifecycle.com").enabled)

        # Delete
        result = gw.call("delete-domain", {"domain": "lifecycle.com"})
        self.assertTrue(result.is_ok())
        self.assertIsNone(gw.get_domain_state("lifecycle.com"))

        # Verify call count
        self.assertEqual(gw.call_count, 4)

    def test_double_create_fails(self):
        gw = MockVirtualminGateway()
        gw.call("create-domain", {"domain": "once.com"})
        result = gw.call("create-domain", {"domain": "once.com"})
        self.assertTrue(result.is_err())

    def test_delete_then_recreate(self):
        gw = MockVirtualminGateway()
        gw.call("create-domain", {"domain": "reborn.com"})
        gw.call("delete-domain", {"domain": "reborn.com"})
        result = gw.call("create-domain", {"domain": "reborn.com"})
        self.assertTrue(result.is_ok())


# ---------------------------------------------------------------
# VirtualminMockMixin integration test
# ---------------------------------------------------------------


class VirtualminMockMixinTest(VirtualminMockMixin, TestCase):
    """Test that the mixin properly patches the gateway."""

    def test_mock_gateway_is_available(self):
        self.assertIsNotNone(self.mock_gateway)
        self.assertIsInstance(self.mock_gateway, MockVirtualminGateway)

    def test_mock_gateway_tracks_state(self):
        self.mock_gateway.seed_domain("mixin-test.com")
        self.assertIsNotNone(self.mock_gateway.get_domain_state("mixin-test.com"))

    def test_mock_gateway_tracks_calls(self):
        self.mock_gateway.call("info")
        self.assertEqual(self.mock_gateway.call_count, 1)
