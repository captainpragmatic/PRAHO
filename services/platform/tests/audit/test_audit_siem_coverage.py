"""
Comprehensive tests for SIEM integration modules.

Covers:
- apps/audit/siem.py: Formatters, transports, hash chain, SIEMService
- apps/audit/siem_integration.py: SIEMIntegrationService, providers, export
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.audit.siem import (
    CEFFormatter,
    HashChainManager,
    JSONFormatter,
    LEEFFormatter,
    OCSFFormatter,
    SIEMConfig,
    SIEMFormat,
    SIEMLogEntry,
    SIEMLogFormatter,
    SIEMService,
    SIEMSeverity,
    SIEMTransport,
    SyslogFormatter,
    get_siem_config,
    get_siem_service,
    log_to_siem,
)
from apps.audit.siem_integration import (
    SIEMConfig as IntegrationSIEMConfig,
)
from apps.audit.siem_integration import (
    SIEMEvent,
    SIEMIntegrationService,
    SIEMProvider,
    get_siem_config_from_settings,
)
from apps.audit.siem_integration import (
    SIEMSeverity as IntegrationSIEMSeverity,
)

# =============================================================================
# HELPERS
# =============================================================================


def _make_log_entry(**overrides: object) -> SIEMLogEntry:
    """Create a SIEMLogEntry with sensible defaults."""
    defaults = {
        "event_id": str(uuid.uuid4()),
        "timestamp": timezone.now(),
        "action": "login_success",
        "category": "authentication",
        "severity": "low",
        "user_id": "user-123",
        "user_email": "test@example.com",
        "actor_type": "user",
        "source_ip": "192.168.1.1",
        "user_agent": "TestAgent/1.0",
        "request_id": "req-abc",
        "session_id": "sess-xyz",
        "target_type": "user",
        "target_id": "target-1",
        "description": "User logged in",
        "metadata": {"key": "value"},
        "is_sensitive": False,
        "requires_review": False,
        "compliance_frameworks": ["ISO27001-A.9"],
        "previous_hash": "",
        "entry_hash": "",
        "sequence_number": 0,
    }
    defaults.update(overrides)
    return SIEMLogEntry(**defaults)


def _make_siem_config(**overrides: object) -> SIEMConfig:
    defaults = {
        "enabled": True,
        "format": SIEMFormat.JSON,
        "protocol": "tcp",
        "host": "localhost",
        "port": 514,
        "use_tls": False,
        "buffer_size": 10,
        "batch_size": 5,
        "flush_interval": 1,
        "max_retries": 1,
        "retry_delay": 0,
        "enable_hash_chain": True,
    }
    defaults.update(overrides)
    return SIEMConfig(**defaults)


def _make_audit_event_mock(**overrides: object) -> Mock:
    """Create a mock AuditEvent."""
    mock = Mock(spec=AuditEvent)
    mock.id = overrides.get("id", uuid.uuid4())
    mock.timestamp = overrides.get("timestamp", timezone.now())
    mock.action = overrides.get("action", "login_success")
    mock.category = overrides.get("category", "authentication")
    mock.severity = overrides.get("severity", "low")
    mock.user_id = overrides.get("user_id", 1)
    mock.user = overrides.get("user", Mock(email="test@example.com"))
    mock.actor_type = overrides.get("actor_type", "user")
    mock.ip_address = overrides.get("ip_address", "10.0.0.1")
    mock.user_agent = overrides.get("user_agent", "TestAgent/1.0")
    mock.request_id = overrides.get("request_id", "req-123")
    mock.session_key = overrides.get("session_key", "sess-abc")
    mock.content_type = overrides.get("content_type", Mock(model="user"))
    mock.object_id = overrides.get("object_id", "obj-1")
    mock.old_values = overrides.get("old_values", {})
    mock.new_values = overrides.get("new_values", {"status": "active"})
    mock.description = overrides.get("description", "Test event")
    mock.metadata = overrides.get("metadata", {})
    mock.is_sensitive = overrides.get("is_sensitive", False)
    mock.requires_review = overrides.get("requires_review", False)
    return mock


# =============================================================================
# siem.py — Enums and Config
# =============================================================================


class TestSIEMFormat(TestCase):
    def test_all_formats(self):
        assert SIEMFormat.CEF == "cef"
        assert SIEMFormat.LEEF == "leef"
        assert SIEMFormat.JSON == "json"
        assert SIEMFormat.SYSLOG == "syslog"
        assert SIEMFormat.OCSF == "ocsf"

    def test_siem_severity_values(self):
        assert SIEMSeverity.UNKNOWN == 0
        assert SIEMSeverity.LOW == 1
        assert SIEMSeverity.MEDIUM == 4
        assert SIEMSeverity.HIGH == 7
        assert SIEMSeverity.CRITICAL == 10


class TestSIEMConfig(TestCase):
    def test_defaults(self):
        cfg = SIEMConfig()
        assert cfg.enabled is False
        assert cfg.format == SIEMFormat.JSON
        assert cfg.protocol == "tcp"
        assert cfg.buffer_size == 1000
        assert cfg.enable_hash_chain is True

    @override_settings(SIEM_CONFIG={
        "ENABLED": True,
        "FORMAT": "cef",
        "PROTOCOL": "udp",
        "HOST": "siem.example.com",
        "PORT": 6514,
        "USE_TLS": False,
        "API_KEY": "test-key",
        "CERTIFICATE_PATH": "/etc/cert.pem",
        "BUFFER_SIZE": 500,
        "BATCH_SIZE": 50,
        "FLUSH_INTERVAL": 10,
        "MAX_RETRIES": 5,
        "RETRY_DELAY": 2,
        "MIN_SEVERITY": "high",
        "INCLUDE_CATEGORIES": ["authentication"],
        "EXCLUDE_CATEGORIES": ["system_admin"],
        "ENABLE_HASH_CHAIN": False,
        "HASH_ALGORITHM": "sha512",
        "VENDOR": "TestVendor",
        "PRODUCT": "TestProduct",
        "VERSION": "2.0",
    })
    def test_get_siem_config_from_settings(self):
        cfg = get_siem_config()
        assert cfg.enabled is True
        assert cfg.format == SIEMFormat.CEF
        assert cfg.protocol == "udp"
        assert cfg.host == "siem.example.com"
        assert cfg.port == 6514
        assert cfg.use_tls is False
        assert cfg.api_key == "test-key"
        assert cfg.certificate_path == "/etc/cert.pem"
        assert cfg.buffer_size == 500
        assert cfg.batch_size == 50
        assert cfg.flush_interval == 10
        assert cfg.max_retries == 5
        assert cfg.retry_delay == 2
        assert cfg.min_severity == "high"
        assert cfg.include_categories == ["authentication"]
        assert cfg.exclude_categories == ["system_admin"]
        assert cfg.enable_hash_chain is False
        assert cfg.hash_algorithm == "sha512"
        assert cfg.vendor == "TestVendor"
        assert cfg.product == "TestProduct"
        assert cfg.version == "2.0"

    def test_get_siem_config_defaults(self):
        cfg = get_siem_config()
        assert cfg.enabled is False
        assert cfg.format == SIEMFormat.JSON


# =============================================================================
# SIEMLogEntry
# =============================================================================


class TestSIEMLogEntry(TestCase):
    def test_compute_hash_deterministic(self):
        entry = _make_log_entry()
        h1 = entry.compute_hash("secret")
        h2 = entry.compute_hash("secret")
        assert h1 == h2

    def test_compute_hash_different_keys(self):
        entry = _make_log_entry()
        h1 = entry.compute_hash("key1")
        h2 = entry.compute_hash("key2")
        assert h1 != h2

    def test_compute_hash_includes_chain_fields(self):
        entry = _make_log_entry(previous_hash="abc", sequence_number=5)
        h1 = entry.compute_hash("secret")
        entry2 = _make_log_entry(
            event_id=entry.event_id,
            timestamp=entry.timestamp,
            action=entry.action,
            category=entry.category,
            severity=entry.severity,
            user_id=entry.user_id,
            source_ip=entry.source_ip,
            target_type=entry.target_type,
            target_id=entry.target_id,
            description=entry.description,
            previous_hash="def",
            sequence_number=5,
        )
        h2 = entry2.compute_hash("secret")
        assert h1 != h2


# =============================================================================
# FORMATTERS
# =============================================================================


class TestSIEMLogFormatterBase(TestCase):
    def test_base_raises_not_implemented(self):
        f = SIEMLogFormatter()
        with pytest.raises(NotImplementedError):
            f.format(_make_log_entry(), _make_siem_config())


class TestCEFFormatter(TestCase):
    def setUp(self):
        self.formatter = CEFFormatter()
        self.config = _make_siem_config()
        self.entry = _make_log_entry()

    def test_format_basic(self):
        result = self.formatter.format(self.entry, self.config)
        assert result.startswith("CEF:0|PRAHO|PlatformAudit|1.0|")
        assert "login_success" in result
        assert "192.168.1.1" in result

    def test_severity_mapping(self):
        for sev, expected in [("low", 1), ("medium", 4), ("high", 7), ("critical", 10)]:
            entry = _make_log_entry(severity=sev)
            result = self.formatter.format(entry, self.config)
            assert f"|{expected}|" in result

    def test_unknown_severity(self):
        entry = _make_log_entry(severity="unknown_sev")
        result = self.formatter.format(entry, self.config)
        assert "|0|" in result

    def test_sensitive_and_review_flags(self):
        entry = _make_log_entry(is_sensitive=True, requires_review=True)
        result = self.formatter.format(entry, self.config)
        assert "cfp1=1 cfp1Label=IsSensitive" in result
        assert "cfp2=1 cfp2Label=RequiresReview" in result

    def test_escape_cef(self):
        assert CEFFormatter._escape_cef("a\\b|c=d") == "a\\\\b\\|c\\=d"

    def test_none_fields(self):
        entry = _make_log_entry(
            source_ip=None, user_email=None, user_id=None,
            request_id=None, session_id=None, target_type=None, target_id=None,
        )
        result = self.formatter.format(entry, self.config)
        assert "src=unknown" in result
        assert "suser=system" in result


class TestLEEFFormatter(TestCase):
    def setUp(self):
        self.formatter = LEEFFormatter()
        self.config = _make_siem_config()

    def test_format_basic(self):
        entry = _make_log_entry()
        result = self.formatter.format(entry, self.config)
        assert result.startswith("LEEF:2.0|PRAHO|PlatformAudit|1.0|")
        assert "login_success" in result

    def test_severity_mapping(self):
        for sev, expected in [("low", 1), ("medium", 4), ("high", 7), ("critical", 10)]:
            entry = _make_log_entry(severity=sev)
            result = self.formatter.format(entry, self.config)
            assert f"sev={expected}" in result

    def test_tab_separated_attrs(self):
        entry = _make_log_entry()
        result = self.formatter.format(entry, self.config)
        # After the header, attributes should be tab-separated
        parts = result.split("|", 5)
        assert "\t" in parts[-1]

    def test_escape_leef(self):
        assert LEEFFormatter._escape_leef("a\tb\nc\r") == "a b c"

    def test_none_fields(self):
        entry = _make_log_entry(source_ip=None, user_email=None, user_id=None)
        result = self.formatter.format(entry, self.config)
        assert "src=unknown" in result
        assert "usrName=system" in result


class TestJSONFormatter(TestCase):
    def setUp(self):
        self.formatter = JSONFormatter()
        self.config = _make_siem_config()

    def test_valid_json(self):
        entry = _make_log_entry()
        result = self.formatter.format(entry, self.config)
        data = json.loads(result)
        assert data["event"]["action"] == "login_success"
        assert data["event"]["category"] == "authentication"
        assert data["user"]["email"] == "test@example.com"
        assert data["message"] == "User logged in"

    def test_json_structure(self):
        entry = _make_log_entry(
            is_sensitive=True,
            requires_review=True,
            old_values={"a": 1},
            new_values={"a": 2},
            compliance_frameworks=["GDPR"],
        )
        data = json.loads(self.formatter.format(entry, self.config))
        assert data["@version"] == "1"
        assert data["praho"]["audit"]["is_sensitive"] is True
        assert data["praho"]["audit"]["requires_review"] is True
        assert data["praho"]["audit"]["old_values"] == {"a": 1}
        assert data["praho"]["audit"]["new_values"] == {"a": 2}
        assert data["praho"]["audit"]["compliance_frameworks"] == ["GDPR"]

    def test_critical_severity_outcome(self):
        entry = _make_log_entry(severity="critical")
        data = json.loads(self.formatter.format(entry, self.config))
        assert data["event"]["outcome"] == "failure"

    def test_non_critical_outcome(self):
        entry = _make_log_entry(severity="low")
        data = json.loads(self.formatter.format(entry, self.config))
        assert data["event"]["outcome"] == "success"


class TestSyslogFormatter(TestCase):
    def setUp(self):
        self.formatter = SyslogFormatter()
        self.config = _make_siem_config()

    def test_format_basic(self):
        entry = _make_log_entry()
        result = self.formatter.format(entry, self.config)
        # PRI = 16*8 + 6 = 134 for low severity
        assert result.startswith("<134>1 ")
        assert "praho-platform" in result

    def test_severity_mapping(self):
        # low=6 -> pri=134, medium=4 -> pri=132, high=3 -> pri=131, critical=2 -> pri=130
        for sev, pri in [("low", 134), ("medium", 132), ("high", 131), ("critical", 130)]:
            entry = _make_log_entry(severity=sev)
            result = self.formatter.format(entry, self.config)
            assert result.startswith(f"<{pri}>1 ")

    def test_structured_data(self):
        entry = _make_log_entry()
        result = self.formatter.format(entry, self.config)
        assert "[audit@praho" in result
        assert f'eventId="{entry.event_id}"' in result

    def test_none_fields(self):
        entry = _make_log_entry(
            user_id=None, source_ip=None, target_type=None,
            target_id=None, request_id=None,
        )
        result = self.formatter.format(entry, self.config)
        assert 'userId="-"' in result
        assert 'sourceIp="-"' in result


class TestOCSFFormatter(TestCase):
    def setUp(self):
        self.formatter = OCSFFormatter()
        self.config = _make_siem_config()

    def test_valid_json(self):
        entry = _make_log_entry()
        result = self.formatter.format(entry, self.config)
        data = json.loads(result)
        assert data["class_uid"] == 2001
        assert data["category_uid"] == 2
        assert data["message"] == "User logged in"

    def test_severity_mapping(self):
        for sev, expected in [("low", 1), ("medium", 2), ("high", 3), ("critical", 4)]:
            entry = _make_log_entry(severity=sev)
            data = json.loads(self.formatter.format(entry, self.config))
            assert data["severity_id"] == expected

    def test_metadata_fields(self):
        entry = _make_log_entry()
        data = json.loads(self.formatter.format(entry, self.config))
        assert data["metadata"]["product"]["name"] == "PlatformAudit"
        assert data["metadata"]["product"]["vendor_name"] == "PRAHO"

    def test_observables(self):
        entry = _make_log_entry()
        data = json.loads(self.formatter.format(entry, self.config))
        assert len(data["observables"]) == 2
        assert data["observables"][0]["value"] == "login_success"

    def test_unmapped_hash_chain(self):
        entry = _make_log_entry(previous_hash="abc", entry_hash="def", sequence_number=5)
        data = json.loads(self.formatter.format(entry, self.config))
        assert data["unmapped"]["hash_chain"]["previous_hash"] == "abc"
        assert data["unmapped"]["hash_chain"]["entry_hash"] == "def"


# =============================================================================
# TRANSPORT
# =============================================================================


class TestSIEMTransport(TestCase):
    def test_connect_tcp(self):
        config = _make_siem_config(protocol="tcp", use_tls=False)
        transport = SIEMTransport(config)
        with patch("apps.audit.siem.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            assert transport.connect() is True
            mock_sock.connect.assert_called_once_with(("localhost", 514))

    def test_connect_tcp_tls(self):
        config = _make_siem_config(protocol="tcp", use_tls=True)
        transport = SIEMTransport(config)
        with patch("apps.audit.siem.socket.socket") as mock_sock_cls, \
             patch("apps.audit.siem.ssl.create_default_context") as mock_ctx:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_wrapped = MagicMock()
            mock_ctx.return_value.wrap_socket.return_value = mock_wrapped
            assert transport.connect() is True
            mock_wrapped.connect.assert_called_once()

    def test_connect_tcp_tls_with_cert(self):
        config = _make_siem_config(protocol="tcp", use_tls=True, certificate_path="/etc/cert.pem")
        transport = SIEMTransport(config)
        with patch("apps.audit.siem.socket.socket") as mock_sock_cls, \
             patch("apps.audit.siem.ssl.create_default_context") as mock_ctx:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_wrapped = MagicMock()
            ctx_instance = mock_ctx.return_value
            ctx_instance.wrap_socket.return_value = mock_wrapped
            assert transport.connect() is True
            ctx_instance.load_cert_chain.assert_called_once_with("/etc/cert.pem")

    def test_connect_udp(self):
        config = _make_siem_config(protocol="udp")
        transport = SIEMTransport(config)
        with patch("apps.audit.siem.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            assert transport.connect() is True
            mock_sock.connect.assert_not_called()

    def test_connect_failure(self):
        config = _make_siem_config(protocol="tcp", use_tls=False)
        transport = SIEMTransport(config)
        with patch("apps.audit.siem.socket.socket") as mock_sock_cls:
            mock_sock_cls.return_value.connect.side_effect = OSError("fail")
            assert transport.connect() is False

    def test_connect_already_connected(self):
        config = _make_siem_config()
        transport = SIEMTransport(config)
        transport._socket = MagicMock()
        assert transport.connect() is True

    def test_disconnect(self):
        config = _make_siem_config()
        transport = SIEMTransport(config)
        mock_sock = MagicMock()
        transport._socket = mock_sock
        transport.disconnect()
        mock_sock.close.assert_called_once()
        assert transport._socket is None

    def test_disconnect_no_socket(self):
        transport = SIEMTransport(_make_siem_config())
        transport.disconnect()  # Should not raise

    def test_disconnect_close_error(self):
        transport = SIEMTransport(_make_siem_config())
        mock_sock = MagicMock()
        mock_sock.close.side_effect = OSError("close error")
        transport._socket = mock_sock
        transport.disconnect()
        assert transport._socket is None

    def test_send_tcp(self):
        config = _make_siem_config(protocol="tcp", use_tls=False)
        transport = SIEMTransport(config)
        mock_sock = MagicMock()
        transport._socket = mock_sock
        assert transport.send("test message") is True
        mock_sock.sendall.assert_called_once_with(b"test message\n")

    def test_send_udp(self):
        config = _make_siem_config(protocol="udp")
        transport = SIEMTransport(config)
        mock_sock = MagicMock()
        transport._socket = mock_sock
        assert transport.send("test message") is True
        mock_sock.sendto.assert_called_once_with(b"test message\n", ("localhost", 514))

    def test_send_reconnects(self):
        config = _make_siem_config(protocol="tcp", use_tls=False, max_retries=1)
        transport = SIEMTransport(config)
        with patch.object(transport, "connect", return_value=True):
            # No socket initially, connect will be called
            # But after connect returns True, _socket is still None because we mocked connect
            # So sendall will fail on None. Let's set socket after connect.
            def set_socket():
                mock_sock = MagicMock()
                transport._socket = mock_sock
                return True
            transport.connect = set_socket
            assert transport.send("msg") is True

    def test_send_all_retries_fail(self):
        config = _make_siem_config(protocol="tcp", use_tls=False, max_retries=2, retry_delay=0)
        transport = SIEMTransport(config)
        with patch.object(transport, "connect", return_value=False):
            assert transport.send("msg") is False

    def test_send_batch(self):
        config = _make_siem_config()
        transport = SIEMTransport(config)
        with patch.object(transport, "send", side_effect=[True, False, True]):
            result = transport.send_batch(["a", "b", "c"])
            assert result == 2


# =============================================================================
# HASH CHAIN
# =============================================================================


class TestHashChainManager(TestCase):
    def setUp(self):
        from django.core.cache import cache  # noqa: PLC0415
        cache.delete(HashChainManager.CACHE_KEY)

    def test_initial_state(self):
        mgr = HashChainManager(secret_key="test-secret")
        seq, h = mgr.get_chain_state()
        assert seq == 0
        assert h == ""

    def test_compute_entry_hash(self):
        mgr = HashChainManager(secret_key="test-secret")
        entry = _make_log_entry()
        h, seq = mgr.compute_entry_hash(entry)
        assert seq == 1
        assert h != ""
        assert entry.entry_hash == h
        assert entry.sequence_number == 1
        assert entry.previous_hash == ""

    def test_chain_state_persists(self):
        mgr = HashChainManager(secret_key="test-secret")
        entry1 = _make_log_entry()
        h1, _ = mgr.compute_entry_hash(entry1)

        entry2 = _make_log_entry(event_id=str(uuid.uuid4()))
        _h2, seq2 = mgr.compute_entry_hash(entry2)
        assert seq2 == 2
        assert entry2.previous_hash == h1

    def test_verify_chain_valid(self):
        mgr = HashChainManager(secret_key="test-secret")
        entries = []
        for _i in range(3):
            entry = _make_log_entry(event_id=str(uuid.uuid4()))
            mgr.compute_entry_hash(entry)
            entries.append(entry)
        is_valid, errors = mgr.verify_chain(entries)
        assert is_valid is True
        assert errors == []

    def test_verify_chain_tampered_hash(self):
        mgr = HashChainManager(secret_key="test-secret")
        entries = []
        for _i in range(3):
            entry = _make_log_entry(event_id=str(uuid.uuid4()))
            mgr.compute_entry_hash(entry)
            entries.append(entry)
        # Tamper with middle entry
        entries[1].entry_hash = "tampered"
        is_valid, errors = mgr.verify_chain(entries)
        assert is_valid is False
        assert len(errors) >= 1

    def test_verify_chain_broken_link(self):
        mgr = HashChainManager(secret_key="test-secret")
        entries = []
        for _i in range(3):
            entry = _make_log_entry(event_id=str(uuid.uuid4()))
            mgr.compute_entry_hash(entry)
            entries.append(entry)
        entries[1].previous_hash = "wrong"
        is_valid, _errors = mgr.verify_chain(entries)
        assert is_valid is False

    def test_verify_chain_sequence_gap(self):
        mgr = HashChainManager(secret_key="test-secret")
        entries = []
        for _i in range(3):
            entry = _make_log_entry(event_id=str(uuid.uuid4()))
            mgr.compute_entry_hash(entry)
            entries.append(entry)
        entries[2].sequence_number = 99
        is_valid, _errors = mgr.verify_chain(entries)
        assert is_valid is False

    def test_get_chain_state_from_cache(self):
        mgr = HashChainManager(secret_key="test-secret")
        mgr.update_chain_state(10, "cached-hash")
        seq, h = mgr.get_chain_state()
        assert seq == 10
        assert h == "cached-hash"

    def test_verify_empty_chain(self):
        mgr = HashChainManager(secret_key="test-secret")
        is_valid, errors = mgr.verify_chain([])
        assert is_valid is True
        assert errors == []


# =============================================================================
# SIEM SERVICE
# =============================================================================


class TestSIEMService(TestCase):
    def test_init_default(self):
        svc = SIEMService(config=_make_siem_config())
        assert isinstance(svc.formatter, JSONFormatter)

    def test_init_cef_format(self):
        svc = SIEMService(config=_make_siem_config(format=SIEMFormat.CEF))
        assert isinstance(svc.formatter, CEFFormatter)

    def test_start_disabled(self):
        cfg = _make_siem_config(enabled=False)
        svc = SIEMService(config=cfg)
        svc.start()
        assert svc._running is False

    def test_start_enabled(self):
        cfg = _make_siem_config(enabled=True)
        svc = SIEMService(config=cfg)
        svc.start()
        assert svc._running is True
        svc.stop()

    def test_stop(self):
        cfg = _make_siem_config(enabled=True)
        svc = SIEMService(config=cfg)
        svc.start()
        svc.stop()
        assert svc._running is False

    def test_log_audit_event_disabled(self):
        cfg = _make_siem_config(enabled=False)
        svc = SIEMService(config=cfg)
        assert svc.log_audit_event(_make_audit_event_mock()) is True

    def test_log_audit_event_queued(self):
        cfg = _make_siem_config(enabled=True)
        svc = SIEMService(config=cfg)
        result = svc.log_audit_event(_make_audit_event_mock())
        assert result is True
        assert not svc._buffer.empty()

    def test_log_audit_event_severity_filter(self):
        cfg = _make_siem_config(enabled=True, min_severity="high")
        svc = SIEMService(config=cfg)
        mock_event = _make_audit_event_mock(severity="low")
        result = svc.log_audit_event(mock_event)
        assert result is True
        assert svc._buffer.empty()

    def test_log_audit_event_include_category_filter(self):
        cfg = _make_siem_config(enabled=True, include_categories=["security_event"])
        svc = SIEMService(config=cfg)
        mock_event = _make_audit_event_mock(category="authentication")
        result = svc.log_audit_event(mock_event)
        assert result is True
        assert svc._buffer.empty()

    def test_log_audit_event_exclude_category_filter(self):
        cfg = _make_siem_config(enabled=True, exclude_categories=["authentication"])
        svc = SIEMService(config=cfg)
        mock_event = _make_audit_event_mock(category="authentication")
        result = svc.log_audit_event(mock_event)
        assert result is True
        assert svc._buffer.empty()

    def test_log_audit_event_category_passes_include(self):
        cfg = _make_siem_config(enabled=True, include_categories=["authentication"])
        svc = SIEMService(config=cfg)
        mock_event = _make_audit_event_mock(category="authentication")
        result = svc.log_audit_event(mock_event)
        assert result is True
        assert not svc._buffer.empty()

    def test_log_audit_event_category_passes_exclude(self):
        cfg = _make_siem_config(enabled=True, exclude_categories=["security_event"])
        svc = SIEMService(config=cfg)
        mock_event = _make_audit_event_mock(category="authentication")
        result = svc.log_audit_event(mock_event)
        assert result is True
        assert not svc._buffer.empty()

    def test_log_audit_event_file_protocol(self):
        cfg = _make_siem_config(enabled=True, protocol="file")
        svc = SIEMService(config=cfg)
        with patch.object(svc, "_write_to_file") as mock_write:
            result = svc.log_audit_event(_make_audit_event_mock())
            assert result is True
            mock_write.assert_called_once()

    def test_log_audit_event_buffer_full(self):
        cfg = _make_siem_config(enabled=True, buffer_size=1)
        svc = SIEMService(config=cfg)
        # Fill the buffer
        svc._buffer.put("existing")
        with patch.object(svc.transport, "send", return_value=True):
            result = svc.log_audit_event(_make_audit_event_mock())
            assert result is True

    def test_log_audit_event_exception(self):
        cfg = _make_siem_config(enabled=True)
        svc = SIEMService(config=cfg)
        with patch.object(svc, "_create_log_entry", side_effect=Exception("boom")):
            result = svc.log_audit_event(_make_audit_event_mock())
            assert result is False

    def test_log_audit_event_no_hash_chain(self):
        cfg = _make_siem_config(enabled=True, enable_hash_chain=False)
        svc = SIEMService(config=cfg)
        result = svc.log_audit_event(_make_audit_event_mock())
        assert result is True

    def test_write_to_file(self):
        cfg = _make_siem_config()
        svc = SIEMService(config=cfg)
        with patch("apps.audit.siem.os.makedirs"), \
             patch("builtins.open", new_callable=MagicMock) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__ = Mock(return_value=mock_file)
            mock_open.return_value.__exit__ = Mock(return_value=False)
            svc._write_to_file("test log line")
            mock_file.write.assert_called_once_with("test log line\n")

    def test_flush_buffer(self):
        cfg = _make_siem_config(enabled=True)
        svc = SIEMService(config=cfg)
        svc._buffer.put("msg1")
        svc._buffer.put("msg2")
        with patch.object(svc.transport, "send_batch", return_value=2):
            svc._flush_buffer()
            assert svc._buffer.empty()

    def test_flush_buffer_empty(self):
        cfg = _make_siem_config(enabled=True)
        svc = SIEMService(config=cfg)
        with patch.object(svc.transport, "send_batch") as mock_send:
            svc._flush_buffer()
            mock_send.assert_not_called()

    def test_create_log_entry(self):
        cfg = _make_siem_config()
        svc = SIEMService(config=cfg)
        mock_event = _make_audit_event_mock(category="authentication")
        entry = svc._create_log_entry(mock_event)
        assert entry.action == "login_success"
        assert entry.category == "authentication"
        assert "ISO27001-A.9" in entry.compliance_frameworks

    def test_create_log_entry_no_user(self):
        cfg = _make_siem_config()
        svc = SIEMService(config=cfg)
        mock_event = _make_audit_event_mock(user=None, user_id=None)
        entry = svc._create_log_entry(mock_event)
        assert entry.user_email is None
        assert entry.user_id is None

    def test_create_log_entry_no_content_type(self):
        cfg = _make_siem_config()
        svc = SIEMService(config=cfg)
        mock_event = _make_audit_event_mock(content_type=None)
        entry = svc._create_log_entry(mock_event)
        assert entry.target_type is None

    def test_passes_severity_filter(self):
        cfg = _make_siem_config(min_severity="medium")
        svc = SIEMService(config=cfg)
        assert svc._passes_severity_filter("low") is False
        assert svc._passes_severity_filter("medium") is True
        assert svc._passes_severity_filter("high") is True
        assert svc._passes_severity_filter("critical") is True

    def test_passes_category_filter_no_filters(self):
        cfg = _make_siem_config()
        svc = SIEMService(config=cfg)
        assert svc._passes_category_filter("anything") is True

    def test_compliance_frameworks_mapping(self):
        assert "authentication" in SIEMService.COMPLIANCE_FRAMEWORKS
        assert "GDPR-Art32" in SIEMService.COMPLIANCE_FRAMEWORKS["authentication"]

    def test_compliance_unknown_category(self):
        cfg = _make_siem_config()
        svc = SIEMService(config=cfg)
        mock_event = _make_audit_event_mock(category="unknown_cat")
        entry = svc._create_log_entry(mock_event)
        assert entry.compliance_frameworks == []


class TestSIEMServiceVerifyLogIntegrity(TestCase):
    def test_verify_log_integrity_empty(self):
        cfg = _make_siem_config()
        svc = SIEMService(config=cfg)
        now = timezone.now()
        is_valid, errors = svc.verify_log_integrity(now - timedelta(hours=1), now)
        assert is_valid is True
        assert errors == []


# =============================================================================
# GLOBAL SIEM INSTANCE
# =============================================================================


class TestGlobalSIEMService(TestCase):
    def test_get_siem_service(self):
        import apps.audit.siem as siem_module  # noqa: PLC0415
        siem_module._siem_service = None
        svc = get_siem_service()
        assert isinstance(svc, SIEMService)
        # Reset
        siem_module._siem_service = None

    def test_log_to_siem(self):
        import apps.audit.siem as siem_module  # noqa: PLC0415
        siem_module._siem_service = None
        mock_event = _make_audit_event_mock()
        result = log_to_siem(mock_event)
        # Disabled by default, returns True
        assert result is True
        siem_module._siem_service = None


# =============================================================================
# siem_integration.py — Enums
# =============================================================================


class TestIntegrationSIEMProvider(TestCase):
    def test_providers(self):
        assert SIEMProvider.GENERIC_WEBHOOK.value == "generic"
        assert SIEMProvider.SPLUNK.value == "splunk"
        assert SIEMProvider.ELASTICSEARCH.value == "elasticsearch"
        assert SIEMProvider.DATADOG.value == "datadog"
        assert SIEMProvider.SUMO_LOGIC.value == "sumo_logic"


class TestIntegrationSIEMSeverity(TestCase):
    def test_from_audit_severity(self):
        assert IntegrationSIEMSeverity.from_audit_severity("low") == IntegrationSIEMSeverity.LOW
        assert IntegrationSIEMSeverity.from_audit_severity("medium") == IntegrationSIEMSeverity.MEDIUM
        assert IntegrationSIEMSeverity.from_audit_severity("high") == IntegrationSIEMSeverity.HIGH
        assert IntegrationSIEMSeverity.from_audit_severity("critical") == IntegrationSIEMSeverity.CRITICAL
        assert IntegrationSIEMSeverity.from_audit_severity("unknown") == IntegrationSIEMSeverity.INFO


# =============================================================================
# SIEMEvent
# =============================================================================


class TestSIEMEvent(TestCase):
    def _make_event(self, **kwargs: object) -> SIEMEvent:
        defaults = {
            "event_id": "evt-1",
            "event_time": "2026-01-01T00:00:00Z",
            "event_type": "login_success",
            "event_category": "authentication",
            "severity": 1,
            "severity_name": "LOW",
            "actor_type": "user",
            "actor_id": "user-1",
            "actor_email": "test@example.com",
            "source_ip": "10.0.0.1",
            "user_agent": "Test/1.0",
            "session_id": "sess-1",
            "target_type": "user",
            "target_id": "target-1",
            "description": "User logged in successfully",
        }
        defaults.update(kwargs)
        return SIEMEvent(**defaults)

    def test_to_dict(self):
        event = self._make_event()
        d = event.to_dict()
        assert d["event_id"] == "evt-1"
        assert d["event_type"] == "login_success"
        assert d["praho_is_sensitive"] is False

    def test_to_cef(self):
        event = self._make_event()
        cef = event.to_cef()
        assert cef.startswith("CEF:0|PRAHO|Platform|1.0|")
        assert "login_success" in cef
        assert "src=10.0.0.1" in cef

    def test_to_cef_escapes_pipe(self):
        event = self._make_event(description="test|value")
        cef = event.to_cef()
        assert "test\\|value" in cef

    def test_to_cef_no_source_ip(self):
        event = self._make_event(source_ip=None, actor_email=None)
        cef = event.to_cef()
        # Fields with None are skipped
        assert "src=" not in cef

    def test_to_syslog(self):
        event = self._make_event()
        syslog = event.to_syslog()
        assert syslog.startswith("<9>1 ")
        assert "praho-platform" in syslog
        assert 'category="authentication"' in syslog

    def test_to_syslog_no_actor(self):
        event = self._make_event(actor_email=None, praho_request_id=None)
        syslog = event.to_syslog()
        assert "- -" in syslog


# =============================================================================
# SIEMIntegrationService
# =============================================================================


class TestSIEMIntegrationService(TestCase):
    def _make_config(self, provider=SIEMProvider.GENERIC_WEBHOOK, **kwargs: object) -> IntegrationSIEMConfig:
        defaults = {
            "provider": provider,
            "endpoint_url": "https://siem.example.com/api/events",
            "api_key": "test-key",
            "api_secret": "test-secret",
            "min_severity": IntegrationSIEMSeverity.LOW,
            "batch_size": 10,
            "timeout_seconds": 5,
        }
        defaults.update(kwargs)
        return IntegrationSIEMConfig(**defaults)

    def test_setup_session_generic(self):
        cfg = self._make_config(provider=SIEMProvider.GENERIC_WEBHOOK)
        svc = SIEMIntegrationService(cfg)
        assert svc._session.headers.get("Authorization") == "Bearer test-key"

    def test_setup_session_splunk(self):
        cfg = self._make_config(provider=SIEMProvider.SPLUNK)
        svc = SIEMIntegrationService(cfg)
        assert svc._session.headers.get("Authorization") == "Splunk test-key"

    def test_setup_session_datadog(self):
        cfg = self._make_config(provider=SIEMProvider.DATADOG)
        svc = SIEMIntegrationService(cfg)
        assert svc._session.headers.get("DD-API-KEY") == "test-key"

    def test_setup_session_elasticsearch(self):
        cfg = self._make_config(provider=SIEMProvider.ELASTICSEARCH, api_secret="secret")
        svc = SIEMIntegrationService(cfg)
        auth = svc._session.headers.get("Authorization")
        assert auth is not None
        assert auth.startswith("Basic ")

    def test_setup_session_sumo_logic(self):
        cfg = self._make_config(provider=SIEMProvider.SUMO_LOGIC)
        svc = SIEMIntegrationService(cfg)
        # Sumo Logic uses URL auth, no special header
        assert "Authorization" not in svc._session.headers

    def test_setup_session_custom_headers(self):
        cfg = self._make_config(custom_headers={"X-Custom": "value"})
        svc = SIEMIntegrationService(cfg)
        assert svc._session.headers.get("X-Custom") == "value"

    def test_setup_session_generic_no_key(self):
        cfg = self._make_config(provider=SIEMProvider.GENERIC_WEBHOOK, api_key=None)
        svc = SIEMIntegrationService(cfg)
        assert "Authorization" not in svc._session.headers

    def test_convert_to_siem_event(self):
        cfg = self._make_config()
        svc = SIEMIntegrationService(cfg)
        mock_event = _make_audit_event_mock()
        siem_event = svc.convert_to_siem_event(mock_event)
        assert siem_event.event_type == "login_success"
        assert siem_event.severity == IntegrationSIEMSeverity.LOW.value

    def test_convert_no_user(self):
        cfg = self._make_config()
        svc = SIEMIntegrationService(cfg)
        mock_event = _make_audit_event_mock(user=None, user_id=None, user_agent=None)
        siem_event = svc.convert_to_siem_event(mock_event)
        assert siem_event.actor_email is None
        assert siem_event.user_agent is None

    def test_convert_no_description(self):
        cfg = self._make_config()
        svc = SIEMIntegrationService(cfg)
        mock_event = _make_audit_event_mock(description="")
        siem_event = svc.convert_to_siem_event(mock_event)
        assert "action performed" in siem_event.description

    def test_convert_no_content_type(self):
        cfg = self._make_config()
        svc = SIEMIntegrationService(cfg)
        mock_event = _make_audit_event_mock(content_type=None)
        siem_event = svc.convert_to_siem_event(mock_event)
        assert siem_event.target_type is None

    def test_sign_payload(self):
        cfg = self._make_config(api_secret="secret")
        svc = SIEMIntegrationService(cfg)
        sig = svc._sign_payload("test data")
        assert sig.startswith("sha256=")

    def test_sign_payload_no_secret(self):
        cfg = self._make_config(api_secret=None)
        svc = SIEMIntegrationService(cfg)
        assert svc._sign_payload("test") == ""

    def test_format_for_provider_splunk(self):
        cfg = self._make_config(provider=SIEMProvider.SPLUNK)
        svc = SIEMIntegrationService(cfg)
        event = SIEMEvent(
            event_id="1", event_time="2026-01-01T00:00:00Z",
            event_type="test", event_category="test",
            severity=1, severity_name="LOW",
            actor_type="user", actor_id="1", actor_email="a@b.com",
            source_ip="1.2.3.4", user_agent="t", session_id="s",
            target_type="x", target_id="y", description="d",
        )
        payload, _headers = svc._format_for_provider([event])
        data = json.loads(payload)
        assert "event" in data
        assert data["event"]["event_id"] == "1"

    def test_format_for_provider_elasticsearch(self):
        cfg = self._make_config(provider=SIEMProvider.ELASTICSEARCH)
        svc = SIEMIntegrationService(cfg)
        event = SIEMEvent(
            event_id="1", event_time="2026-01-01T00:00:00Z",
            event_type="test", event_category="test",
            severity=1, severity_name="LOW",
            actor_type="user", actor_id="1", actor_email="a@b.com",
            source_ip="1.2.3.4", user_agent="t", session_id="s",
            target_type="x", target_id="y", description="d",
        )
        payload, headers = svc._format_for_provider([event])
        assert headers["Content-Type"] == "application/x-ndjson"
        lines = payload.strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"index": {"_index": "praho-audit"}}

    def test_format_for_provider_datadog(self):
        cfg = self._make_config(provider=SIEMProvider.DATADOG)
        svc = SIEMIntegrationService(cfg)
        event = SIEMEvent(
            event_id="1", event_time="2026-01-01T00:00:00Z",
            event_type="test", event_category="test",
            severity=1, severity_name="LOW",
            actor_type="user", actor_id="1", actor_email="a@b.com",
            source_ip="1.2.3.4", user_agent="t", session_id="s",
            target_type="x", target_id="y", description="d",
        )
        payload, _headers = svc._format_for_provider([event])
        data = json.loads(payload)
        assert isinstance(data, list)
        assert data[0]["ddsource"] == "praho-platform"

    def test_format_for_provider_generic(self):
        cfg = self._make_config(provider=SIEMProvider.GENERIC_WEBHOOK)
        svc = SIEMIntegrationService(cfg)
        event = SIEMEvent(
            event_id="1", event_time="2026-01-01T00:00:00Z",
            event_type="test", event_category="test",
            severity=1, severity_name="LOW",
            actor_type="user", actor_id="1", actor_email="a@b.com",
            source_ip="1.2.3.4", user_agent="t", session_id="s",
            target_type="x", target_id="y", description="d",
        )
        payload, _headers = svc._format_for_provider([event])
        data = json.loads(payload)
        assert isinstance(data, list)

    @patch("apps.audit.siem_integration.requests.Session.post")
    def test_send_events_success(self, mock_post):
        mock_post.return_value = Mock(status_code=200, raise_for_status=Mock())
        cfg = self._make_config()
        svc = SIEMIntegrationService(cfg)
        mock_event = _make_audit_event_mock()
        assert svc.send_events([mock_event]) is True

    @patch("apps.audit.siem_integration.requests.Session.post")
    def test_send_events_failure(self, mock_post):
        import requests as req  # noqa: PLC0415
        mock_post.side_effect = req.exceptions.ConnectionError("fail")
        cfg = self._make_config()
        svc = SIEMIntegrationService(cfg)
        mock_event = _make_audit_event_mock()
        assert svc.send_events([mock_event]) is False

    @patch("apps.audit.siem_integration.requests.Session.post")
    def test_send_events_empty(self, mock_post):
        cfg = self._make_config()
        svc = SIEMIntegrationService(cfg)
        assert svc.send_events([]) is True
        mock_post.assert_not_called()

    @patch("apps.audit.siem_integration.requests.Session.post")
    def test_send_events_severity_filter(self, mock_post):
        cfg = self._make_config(min_severity=IntegrationSIEMSeverity.HIGH)
        svc = SIEMIntegrationService(cfg)
        mock_event = _make_audit_event_mock(severity="low")
        assert svc.send_events([mock_event]) is True
        mock_post.assert_not_called()

    @patch("apps.audit.siem_integration.requests.Session.post")
    def test_send_events_sensitive_filter(self, mock_post):
        cfg = self._make_config(include_sensitive=False)
        svc = SIEMIntegrationService(cfg)
        mock_event = _make_audit_event_mock(is_sensitive=True, severity="high")
        assert svc.send_events([mock_event]) is True
        mock_post.assert_not_called()

    @patch("apps.audit.siem_integration.requests.Session.post")
    def test_send_events_include_sensitive(self, mock_post):
        mock_post.return_value = Mock(status_code=200, raise_for_status=Mock())
        cfg = self._make_config(include_sensitive=True)
        svc = SIEMIntegrationService(cfg)
        mock_event = _make_audit_event_mock(is_sensitive=True)
        assert svc.send_events([mock_event]) is True
        mock_post.assert_called_once()

    @patch("apps.audit.siem_integration.requests.Session.post")
    def test_send_events_with_signature(self, mock_post):
        mock_post.return_value = Mock(status_code=200, raise_for_status=Mock())
        cfg = self._make_config(api_secret="secret")
        svc = SIEMIntegrationService(cfg)
        mock_event = _make_audit_event_mock()
        svc.send_events([mock_event])
        call_kwargs = mock_post.call_args
        assert "X-PRAHO-Signature" in call_kwargs.kwargs.get("headers", {}) or \
               "X-PRAHO-Signature" in (call_kwargs[1].get("headers", {}) if len(call_kwargs) > 1 else {})

    @patch("apps.audit.siem_integration.requests.Session.post")
    def test_send_event_single(self, mock_post):
        mock_post.return_value = Mock(status_code=200, raise_for_status=Mock())
        cfg = self._make_config()
        svc = SIEMIntegrationService(cfg)
        mock_event = _make_audit_event_mock()
        assert svc.send_event(mock_event) is True


# =============================================================================
# siem_integration.py — Export and Config from Settings
# =============================================================================


class TestExportEvents(TestCase):
    @patch("apps.audit.siem_integration.requests.Session.post")
    def test_export_events_no_events(self, mock_post):
        cfg = IntegrationSIEMConfig(
            provider=SIEMProvider.GENERIC_WEBHOOK,
            endpoint_url="https://example.com/api",
        )
        svc = SIEMIntegrationService(cfg)
        sent, failed = svc.export_events(
            since=timezone.now() - timedelta(hours=1),
            until=timezone.now(),
        )
        assert sent == 0
        assert failed == 0

    @patch("apps.audit.siem_integration.requests.Session.post")
    def test_export_events_with_categories(self, mock_post):
        cfg = IntegrationSIEMConfig(
            provider=SIEMProvider.GENERIC_WEBHOOK,
            endpoint_url="https://example.com/api",
        )
        svc = SIEMIntegrationService(cfg)
        sent, failed = svc.export_events(categories=["authentication"])
        assert sent == 0
        assert failed == 0

    @patch("apps.audit.siem_integration.requests.Session.post")
    def test_export_events_with_limit(self, mock_post):
        cfg = IntegrationSIEMConfig(
            provider=SIEMProvider.GENERIC_WEBHOOK,
            endpoint_url="https://example.com/api",
        )
        svc = SIEMIntegrationService(cfg)
        sent, failed = svc.export_events(limit=5)
        assert sent == 0
        assert failed == 0


class TestGetSIEMConfigFromSettings(TestCase):
    def test_no_settings(self):
        assert get_siem_config_from_settings() is None

    @override_settings(SIEM_INTEGRATION={"enabled": False})
    def test_disabled(self):
        assert get_siem_config_from_settings() is None

    @override_settings(SIEM_INTEGRATION={
        "enabled": True,
        "provider": "splunk",
        "endpoint_url": "https://splunk.example.com:8088/services/collector",
        "api_key": "hec-token",
        "api_secret": "secret",
        "min_severity": "medium",
        "include_sensitive": True,
        "batch_size": 50,
        "timeout_seconds": 15,
        "verify_ssl": False,
        "custom_headers": {"X-Test": "value"},
    })
    def test_full_config(self):
        cfg = get_siem_config_from_settings()
        assert cfg is not None
        assert cfg.provider == SIEMProvider.SPLUNK
        assert cfg.endpoint_url == "https://splunk.example.com:8088/services/collector"
        assert cfg.api_key == "hec-token"
        assert cfg.min_severity == IntegrationSIEMSeverity.MEDIUM
        assert cfg.include_sensitive is True
        assert cfg.batch_size == 50
        assert cfg.verify_ssl is False

    @override_settings(SIEM_INTEGRATION={
        "enabled": True,
        "provider": "elastic",
        "endpoint_url": "https://elastic.example.com",
    })
    def test_elastic_alias(self):
        cfg = get_siem_config_from_settings()
        assert cfg is not None
        assert cfg.provider == SIEMProvider.ELASTICSEARCH

    @override_settings(SIEM_INTEGRATION={
        "enabled": True,
        "provider": "sumologic",
        "endpoint_url": "https://sumo.example.com",
    })
    def test_sumologic_alias(self):
        cfg = get_siem_config_from_settings()
        assert cfg is not None
        assert cfg.provider == SIEMProvider.SUMO_LOGIC

    @override_settings(SIEM_INTEGRATION={
        "enabled": True,
        "provider": "datadog",
        "endpoint_url": "https://dd.example.com",
    })
    def test_datadog_provider(self):
        cfg = get_siem_config_from_settings()
        assert cfg is not None
        assert cfg.provider == SIEMProvider.DATADOG

    @override_settings(SIEM_INTEGRATION={
        "enabled": True,
        "provider": "unknown_provider",
        "endpoint_url": "https://example.com",
    })
    def test_unknown_provider_defaults_to_generic(self):
        cfg = get_siem_config_from_settings()
        assert cfg is not None
        assert cfg.provider == SIEMProvider.GENERIC_WEBHOOK

    @override_settings(SIEM_INTEGRATION={
        "enabled": True,
        "provider": "generic",
        "endpoint_url": "https://example.com",
        "min_severity": "UNKNOWN_SEV",
    })
    def test_unknown_severity_defaults_to_low(self):
        cfg = get_siem_config_from_settings()
        assert cfg is not None
        assert cfg.min_severity == IntegrationSIEMSeverity.LOW
