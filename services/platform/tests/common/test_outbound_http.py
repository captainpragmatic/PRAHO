"""Tests for outbound HTTP security helper — policy and validation."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import requests
from django.test import TestCase, override_settings

from apps.common.outbound_http import (
    DANGEROUS_PORTS,
    INTERNAL_SERVICE,
    STRICT_EXTERNAL,
    TRUSTED_PROVIDER,
    OutboundPolicy,
    OutboundSecurityError,
    PinnedIPAdapter,
    ResolvedTarget,
    _build_internal_service_policy,
    _is_dangerous_ip,
    _log_dns_fallback,
    get_internal_service_policy,
    validate_and_resolve,
)

# A public IP for mocking DNS resolution
MOCK_PUBLIC_IP = "93.184.216.34"


def _mock_getaddrinfo_public(host, port, family=0, type_=0, *args, **kwargs):
    """Mock DNS that returns a single public IP."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (MOCK_PUBLIC_IP, port or 443))]


def _mock_getaddrinfo_private(host, port, family=0, type_=0, *args, **kwargs):
    """Mock DNS that returns a private IP."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port or 443))]


def _mock_getaddrinfo_loopback(host, port, family=0, type_=0, *args, **kwargs):
    """Mock DNS that returns loopback."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port or 443))]


def _mock_getaddrinfo_fail(host, port, family=0, type_=0, *args, **kwargs):
    raise socket.gaierror("DNS resolution failed")


def _mock_getaddrinfo_ipv6_loopback(host, port, family=0, type_=0, *args, **kwargs):
    return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port or 443, 0, 0))]


def _mock_getaddrinfo_link_local(host, port, family=0, type_=0, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port or 443))]


class TestOutboundPolicy(TestCase):
    """Task 0.1: OutboundPolicy frozen dataclass creation and defaults."""

    def test_strict_external_defaults(self):
        p = STRICT_EXTERNAL
        self.assertEqual(p.name, "strict_external")
        self.assertTrue(p.require_https)
        self.assertFalse(p.allow_redirects)
        self.assertEqual(p.max_redirects, 0)
        self.assertEqual(p.timeout_seconds, 30.0)
        self.assertEqual(p.connect_timeout_seconds, 10.0)
        self.assertEqual(p.allowed_schemes, frozenset({"https"}))
        self.assertIsNone(p.allowed_ports)
        self.assertEqual(p.blocked_ports, DANGEROUS_PORTS)
        self.assertIsNone(p.allowed_domains)
        self.assertTrue(p.verify_tls)
        self.assertEqual(p.max_retries, 0)
        self.assertTrue(p.check_dns)

    def test_trusted_provider_overrides(self):
        p = TRUSTED_PROVIDER
        self.assertEqual(p.timeout_seconds, 60.0)
        self.assertEqual(p.max_retries, 3)

    def test_internal_service_allows_http(self):
        p = INTERNAL_SERVICE
        self.assertFalse(p.require_https)
        self.assertIn("http", p.allowed_schemes)
        self.assertIn("https", p.allowed_schemes)

    def test_policy_is_frozen(self):
        with self.assertRaises(AttributeError):
            STRICT_EXTERNAL.name = "hacked"  # intentionally testing frozen dataclass

    def test_custom_policy_creation(self):
        p = OutboundPolicy(
            name="test",
            allowed_domains=frozenset({"example.com"}),
            allowed_ports=frozenset({443, 8443}),
        )
        self.assertEqual(p.allowed_domains, frozenset({"example.com"}))
        self.assertEqual(p.allowed_ports, frozenset({443, 8443}))


class TestOutboundSecurityError(TestCase):
    def test_error_has_message(self):
        err = OutboundSecurityError("blocked")
        self.assertEqual(str(err), "blocked")

    def test_error_is_exception(self):
        self.assertTrue(issubclass(OutboundSecurityError, Exception))


class TestDangerousPorts(TestCase):
    def test_contains_critical_ports(self):
        for port in (22, 23, 25, 53, 3306, 5432, 6379):
            self.assertIn(port, DANGEROUS_PORTS)

    def test_does_not_contain_http_ports(self):
        self.assertNotIn(80, DANGEROUS_PORTS)
        self.assertNotIn(443, DANGEROUS_PORTS)
        self.assertNotIn(8080, DANGEROUS_PORTS)


class TestValidateAndResolve(TestCase):
    """Task 0.1: validate_and_resolve() — scheme, port, domain, IP, DNS."""

    # --- Valid URLs ---

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    def test_valid_https_url(self):
        target = validate_and_resolve("https://example.com/path")
        self.assertEqual(target.scheme, "https")
        self.assertEqual(target.hostname, "example.com")
        self.assertEqual(target.port, 443)
        self.assertEqual(target.path, "/path")
        self.assertIn(MOCK_PUBLIC_IP, target.pinned_ips)

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    def test_valid_https_with_port(self):
        target = validate_and_resolve("https://example.com:8443/api")
        self.assertEqual(target.port, 8443)

    # --- Scheme enforcement ---

    def test_rejects_http_with_strict_policy(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("http://example.com")

    def test_allows_http_with_internal_policy(self):
        target = validate_and_resolve("http://localhost/path", policy=INTERNAL_SERVICE)
        self.assertEqual(target.scheme, "http")

    def test_rejects_ftp_scheme(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("ftp://example.com/file")

    def test_rejects_file_scheme(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("file:///etc/passwd")

    def test_rejects_missing_scheme(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("example.com/path")

    # --- Port blocklist ---

    def test_rejects_ssh_port(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://example.com:22/")

    def test_rejects_mysql_port(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://example.com:3306/")

    def test_rejects_redis_port(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://example.com:6379/")

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    def test_allows_custom_port_not_blocked(self):
        target = validate_and_resolve("https://example.com:9999/")
        self.assertEqual(target.port, 9999)

    def test_allowed_ports_whitelist(self):
        policy = OutboundPolicy(
            name="test",
            allowed_ports=frozenset({443}),
        )
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://example.com:8443/", policy=policy)

    # --- Private IP blocking ---

    def test_rejects_127_0_0_1(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://127.0.0.1/")

    def test_rejects_10_x(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://10.0.0.1/")

    def test_rejects_172_16_x(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://172.16.0.1/")

    def test_rejects_192_168_x(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://192.168.1.1/")

    def test_rejects_link_local_169_254(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://169.254.169.254/")

    def test_rejects_ipv6_loopback(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://[::1]/")

    def test_rejects_cgnat_address(self):
        """CGNAT range 100.64.0.0/10 must be blocked (not globally routable)."""
        self.assertTrue(_is_dangerous_ip("100.64.0.1"))

    def test_rejects_benchmarking_address(self):
        """Benchmarking range 198.18.0.0/15 must be blocked."""
        self.assertTrue(_is_dangerous_ip("198.18.0.1"))

    def test_unparseable_ip_fails_closed(self):
        """Unparseable IP strings must be treated as dangerous (fail-closed)."""
        self.assertTrue(_is_dangerous_ip("not-an-ip"))
        self.assertTrue(_is_dangerous_ip(""))

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    def test_allows_public_ip(self):
        target = validate_and_resolve(f"https://{MOCK_PUBLIC_IP}/")
        self.assertIn(MOCK_PUBLIC_IP, target.pinned_ips)

    # --- Query string preservation ---

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    def test_resolved_target_preserves_query_string(self):
        """Query string must survive URL parsing and appear in ResolvedTarget."""
        target = validate_and_resolve(f"https://{MOCK_PUBLIC_IP}/path?foo=bar&baz=1")
        self.assertEqual(target.query, "foo=bar&baz=1")

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    def test_resolved_target_empty_query(self):
        """URLs without query strings should have empty query field."""
        target = validate_and_resolve(f"https://{MOCK_PUBLIC_IP}/path")
        self.assertEqual(target.query, "")

    # --- DNS resolution blocking private IPs ---

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_private)
    def test_dns_resolving_to_private_ip_blocked(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://evil.example.com/")

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_loopback)
    def test_dns_resolving_to_loopback_blocked(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://evil.example.com/")

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_ipv6_loopback)
    def test_dns_resolving_to_ipv6_loopback_blocked(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://evil.example.com/")

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_link_local)
    def test_dns_resolving_to_link_local_blocked(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://evil.example.com/")

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_fail)
    def test_dns_failure_raises_error(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://nonexistent.example.com/")

    # --- IP encoding tricks ---

    def test_decimal_ip_127_0_0_1(self):
        """2130706433 = 127.0.0.1 in decimal."""
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://2130706433/")

    def test_hex_ip_127_0_0_1(self):
        """0x7f000001 = 127.0.0.1 in hex."""
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://0x7f000001/")

    def test_octal_ip_127_0_0_1(self):
        """0177.0.0.1 = 127.0.0.1 in octal."""
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://0177.0.0.1/")

    # --- IPv6 zone ID ---

    def test_rejects_ipv6_zone_id(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://[fe80::1%25eth0]/")

    # --- Embedded credentials ---

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    def test_rejects_embedded_credentials(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://user:pass@example.com/")

    # --- Domain allowlist ---

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    def test_domain_allowlist_exact_match(self):
        policy = OutboundPolicy(
            name="test",
            allowed_domains=frozenset({"api.example.com"}),
        )
        target = validate_and_resolve("https://api.example.com/v1", policy=policy)
        self.assertEqual(target.hostname, "api.example.com")

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    def test_domain_allowlist_subdomain(self):
        policy = OutboundPolicy(
            name="test",
            allowed_domains=frozenset({"example.com"}),
        )
        target = validate_and_resolve("https://api.example.com/v1", policy=policy)
        self.assertEqual(target.hostname, "api.example.com")

    def test_domain_allowlist_rejects_non_matching(self):
        policy = OutboundPolicy(
            name="test",
            allowed_domains=frozenset({"example.com"}),
        )
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://evil.com/", policy=policy)

    def test_domain_allowlist_prevents_suffix_trick(self):
        """evil-example.com should NOT match example.com."""
        policy = OutboundPolicy(
            name="test",
            allowed_domains=frozenset({"example.com"}),
        )
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://evil-example.com/", policy=policy)

    # --- Edge cases ---

    def test_rejects_empty_url(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("")

    def test_rejects_none_url(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve(None)  # intentionally testing None input

    def test_rejects_too_long_url(self):
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("https://example.com/" + "a" * 3000)

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    def test_returns_resolved_target_type(self):
        target = validate_and_resolve("https://example.com/")
        self.assertIsInstance(target, ResolvedTarget)
        self.assertEqual(target.original_url, "https://example.com/")

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    def test_default_port_https(self):
        target = validate_and_resolve("https://example.com/")
        self.assertEqual(target.port, 443)

    def test_default_port_http(self):
        target = validate_and_resolve("http://localhost/", policy=INTERNAL_SERVICE)
        self.assertEqual(target.port, 80)

    def test_skip_dns_when_check_dns_false(self):
        policy = OutboundPolicy(name="no_dns", check_dns=False)
        target = validate_and_resolve("https://example.com/", policy=policy)
        self.assertEqual(target.pinned_ips, [])


MOCK_PUBLIC_IP_2 = "104.16.132.229"


def _mock_getaddrinfo_fresh(host, port, family=0, type_=0, *args, **kwargs):
    """Mock DNS returning a *different* public IP (simulates IP rotation)."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (MOCK_PUBLIC_IP_2, port or 443))]


class TestDNSFallback(TestCase):
    """DNS fallback retries with a fresh IP on ConnectionError."""

    def test_fallback_retries_with_fresh_ip(self):
        adapter = PinnedIPAdapter(pinned_ip=MOCK_PUBLIC_IP, hostname="api.stripe.com", port=443)
        req = requests.PreparedRequest()
        req.prepare(method="GET", url="https://api.stripe.com/v1/charges")

        with (
            patch.object(
                type(adapter).__bases__[0],
                "send",
                side_effect=[requests.ConnectionError("stale IP"), MagicMock(status_code=200)],
            ),
            patch("apps.common.outbound_http._resolve_dns", return_value=[MOCK_PUBLIC_IP_2]),
            patch("apps.common.outbound_http._log_dns_fallback") as mock_log,
        ):
            resp = adapter.send(req)

        self.assertEqual(resp.status_code, 200)
        mock_log.assert_called_once_with("api.stripe.com", MOCK_PUBLIC_IP, MOCK_PUBLIC_IP_2)

    def test_fallback_reraises_when_same_ips(self):
        adapter = PinnedIPAdapter(pinned_ip=MOCK_PUBLIC_IP, hostname="api.stripe.com", port=443)
        req = requests.PreparedRequest()
        req.prepare(method="GET", url="https://api.stripe.com/v1/charges")

        with (
            patch.object(
                type(adapter).__bases__[0],
                "send",
                side_effect=requests.ConnectionError("stale IP"),
            ),
            patch("apps.common.outbound_http._resolve_dns", return_value=[MOCK_PUBLIC_IP]),
            self.assertRaises(requests.ConnectionError),
        ):
            adapter.send(req)

    def test_fallback_reraises_on_dns_failure(self):
        adapter = PinnedIPAdapter(pinned_ip=MOCK_PUBLIC_IP, hostname="api.stripe.com", port=443)
        req = requests.PreparedRequest()
        req.prepare(method="GET", url="https://api.stripe.com/v1/charges")

        with (
            patch.object(
                type(adapter).__bases__[0],
                "send",
                side_effect=requests.ConnectionError("stale IP"),
            ),
            patch("apps.common.outbound_http._resolve_dns", side_effect=OutboundSecurityError("DNS failed")),
            self.assertRaises(OutboundSecurityError),
        ):
            adapter.send(req)

    def test_log_dns_fallback_creates_audit_event(self):
        with patch("apps.audit.services.AuditService.log_simple_event") as mock_log:
            _log_dns_fallback("api.stripe.com", "1.2.3.4", "5.6.7.8")
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        self.assertEqual(call_kwargs["actor_type"], "system")
        self.assertIn("api.stripe.com", call_kwargs["description"])
        self.assertEqual(call_kwargs["metadata"]["old_ip"], "1.2.3.4")
        self.assertEqual(call_kwargs["metadata"]["new_ip"], "5.6.7.8")

    def test_log_dns_fallback_swallows_exceptions(self):
        """Audit failure must never block real requests."""
        with patch("apps.audit.services.AuditService.log_simple_event", side_effect=RuntimeError("DB down")):
            # Should not raise
            _log_dns_fallback("api.stripe.com", "1.2.3.4", "5.6.7.8")


class TestInternalServicePolicy(TestCase):
    """Environment-aware INTERNAL_SERVICE policy from settings."""

    def setUp(self):
        # Clear lru_cache between tests
        _build_internal_service_policy.cache_clear()

    def tearDown(self):
        _build_internal_service_policy.cache_clear()

    @override_settings(INTERNAL_SERVICE_ALLOWED_DOMAINS=["localhost", "testserver"])
    def test_reads_allowed_domains_from_settings(self):
        policy = get_internal_service_policy()
        self.assertEqual(policy.allowed_domains, frozenset({"localhost", "testserver"}))
        self.assertFalse(policy.require_https)
        self.assertFalse(policy.check_dns)

    @override_settings(INTERNAL_SERVICE_ALLOWED_DOMAINS=[])
    def test_empty_domains_means_unrestricted(self):
        policy = get_internal_service_policy()
        self.assertIsNone(policy.allowed_domains)

    @override_settings(INTERNAL_SERVICE_ALLOWED_DOMAINS=["localhost"])
    def test_rejects_domains_not_in_allowlist(self):
        policy = get_internal_service_policy()
        with self.assertRaises(OutboundSecurityError):
            validate_and_resolve("http://evil.com/api", policy=policy)

    @override_settings(INTERNAL_SERVICE_ALLOWED_DOMAINS=["localhost"])
    def test_allows_domains_in_allowlist(self):
        policy = get_internal_service_policy()
        target = validate_and_resolve("http://localhost/api", policy=policy)
        self.assertEqual(target.hostname, "localhost")
        self.assertEqual(target.pinned_ips, [])  # check_dns=False
