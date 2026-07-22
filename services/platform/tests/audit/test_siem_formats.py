"""SIEM format renderer tests (ported from the retired transport test module).

Covers apps/audit/siem.py: format renderers (CEF/LEEF/JSON/Syslog/OCSF),
SIEMConfig, SIEMLogEntry, and the cache-backed HashChainManager.
"""

from __future__ import annotations

import json
import uuid
from unittest.mock import Mock

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
    SIEMSeverity,
    SyslogFormatter,
    get_siem_config,
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

    @override_settings(
        SIEM_CONFIG={
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
        }
    )
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
            source_ip=None,
            user_email=None,
            user_id=None,
            request_id=None,
            session_id=None,
            target_type=None,
            target_id=None,
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
            user_id=None,
            source_ip=None,
            target_type=None,
            target_id=None,
            request_id=None,
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


class TestHashChainManager(TestCase):
    """Needs real cache — HashChainManager stores hash chain state in cache."""

    def setUp(self):
        from django.core.cache import cache  # noqa: PLC0415

        cache.clear()

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
