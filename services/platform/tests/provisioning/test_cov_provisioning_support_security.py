"""Coverage additions for reachable provisioning security utilities."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase, override_settings

from apps.audit.models import AuditEvent
from apps.common.encryption import encrypt_sensitive_data
from apps.provisioning.security_utils import (
    IdempotencyManager,
    ProvisioningErrorClassifier,
    ProvisioningErrorType,
    ProvisioningParametersValidator,
    SecureTaskParameters,
    log_security_event_safe,
    sanitize_log_parameters,
)


class ProvisioningSecurityParameterTests(SimpleTestCase):
    def test_encrypted_parameters_round_trip_with_stable_integrity_hash(self) -> None:
        params: dict[str, object] = {"password": "Coverage-secret-927!", "domain": "tenant.example.com"}
        first = SecureTaskParameters.create(params)
        second = SecureTaskParameters.create(dict(reversed(list(params.items()))))
        self.assertEqual(first.decrypt(), params)
        self.assertEqual(first.parameter_hash, second.parameter_hash)
        self.assertNotIn("Coverage-secret-927!", first.encrypted_payload)
        self.assertIsNotNone(datetime.fromisoformat(first.created_at).tzinfo)

    def test_tampered_hash_and_ciphertext_are_rejected(self) -> None:
        secure = SecureTaskParameters.create({"domain": "tenant.example.com"})
        for invalid in (
            replace(secure, parameter_hash="0" * 64),
            replace(secure, encrypted_payload="invalid-ciphertext"),
        ):
            with (
                self.subTest(payload=invalid),
                self.assertRaisesMessage(ValidationError, "Parameter decryption failed"),
            ):
                invalid.decrypt()

    def test_decrypted_json_must_be_an_object(self) -> None:
        for plaintext, error in (("[]", "Invalid parameter format"), ("{", "Parameter decryption failed")):
            secure = SecureTaskParameters(
                encrypted_payload=encrypt_sensitive_data(plaintext),
                parameter_hash=hashlib.sha256(plaintext.encode()).hexdigest(),
                created_at="2026-10-07T00:00:00+00:00",
            )
            with self.subTest(plaintext=plaintext), self.assertRaisesMessage(ValidationError, error):
                secure.decrypt()

    def test_domain_normalization_and_rejections(self) -> None:
        self.assertEqual(
            ProvisioningParametersValidator.validate_domain("  Tenant.Example.COM  "), "tenant.example.com"
        )
        cases = (
            ("", "Domain cannot be empty"),
            ("a.b", "Domain too short"),
            ("a" * 254, "Domain too long"),
            ("bad/domain.example.com", "Invalid domain format"),
            ("admin.example.com", "restricted component"),
            ("tenant.local", "restricted component"),
        )
        for domain, error in cases:
            with self.subTest(domain=domain), self.assertRaisesMessage(ValidationError, error):
                ProvisioningParametersValidator.validate_domain(domain)

    def test_username_normalization_optional_value_and_rejections(self) -> None:
        self.assertIsNone(ProvisioningParametersValidator.validate_username(None))
        self.assertEqual(ProvisioningParametersValidator.validate_username("  Tenant_42  "), "tenant_42")
        cases = (
            ("x", "Username too short"),
            ("x" * 33, "Username too long"),
            ("9tenant", "Invalid username format"),
            ("tenant name", "Invalid username format"),
            ("root", "reserved"),
            ("www-data", "reserved"),
        )
        for username, error in cases:
            with self.subTest(username=username), self.assertRaisesMessage(ValidationError, error):
                ProvisioningParametersValidator.validate_username(username)

    def test_template_default_normalization_and_rejections(self) -> None:
        self.assertEqual(ProvisioningParametersValidator.validate_template(""), "Default")
        self.assertEqual(ProvisioningParametersValidator.validate_template("  Shared Hosting_2  "), "Shared Hosting_2")
        for template, error in (("x" * 51, "too long"), ("../Default", "invalid characters")):
            with self.subTest(template=template), self.assertRaisesMessage(ValidationError, error):
                ProvisioningParametersValidator.validate_template(template)

    def test_error_classification_preserves_retry_policy(self) -> None:
        cases = (
            ("CONNECTION TIMEOUT", ProvisioningErrorType.RETRYABLE_NETWORK, True),
            ("server busy", ProvisioningErrorType.RETRYABLE_SERVICE, True),
            ("invalid domain", ProvisioningErrorType.PERMANENT_VALIDATION, False),
            ("permission denied", ProvisioningErrorType.PERMANENT_AUTHORIZATION, False),
            ("quota exceeded", ProvisioningErrorType.PERMANENT_RESOURCE, False),
            ("unrecognized failure", ProvisioningErrorType.CRITICAL_SYSTEM, False),
        )
        for message, expected, retryable in cases:
            with self.subTest(message=message):
                classified = ProvisioningErrorClassifier.classify_error(message)
                self.assertEqual(classified, expected)
                self.assertEqual(ProvisioningErrorClassifier.is_retryable(classified), retryable)


@override_settings(
    CACHES={
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "wp17-support-security"}
    }
)
class ProvisioningIdempotencyTests(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    def test_completed_result_is_reused_until_cleared(self) -> None:
        key = IdempotencyManager.generate_key("service-42", "create", {"domain": "tenant.example.com"})
        self.assertEqual(IdempotencyManager.check_and_set(key), (True, None))
        self.assertEqual(IdempotencyManager.check_and_set(key), (False, "in_progress"))
        result = {"account_id": "account-42", "status": "completed"}
        IdempotencyManager.complete(key, result)
        self.assertEqual(IdempotencyManager.check_and_set(key), (False, result))
        IdempotencyManager.clear(key)
        self.assertEqual(IdempotencyManager.check_and_set(key, {"status": "claimed"}), (True, None))
        self.assertEqual(cache.get(key), {"status": "claimed"})

    def test_key_is_stable_and_separates_operations_and_parameters(self) -> None:
        first = IdempotencyManager.generate_key("42", "create", {"a": 1, "b": 2})
        self.assertEqual(first, IdempotencyManager.generate_key("42", "create", {"b": 2, "a": 1}))
        self.assertNotEqual(first, IdempotencyManager.generate_key("42", "suspend", {"a": 1, "b": 2}))
        self.assertNotEqual(first, IdempotencyManager.generate_key("42", "create", {"a": 2, "b": 2}))


class ProvisioningSecurityAuditTests(TestCase):
    def test_security_event_persists_sanitized_details_and_context(self) -> None:
        details: dict[str, object] = {
            "password": "plain-secret",
            "token": "plain-token",
            "encrypted_payload": "abcdef",
            "description": "x" * 105,
            "attempt": 2,
        }
        expected = {
            "password": "***REDACTED***",
            "token": "***REDACTED***",
            "encrypted_payload": "***ENCRYPTED(6 bytes)***",
            "description": "x" * 100 + "...(105 chars total)",
            "attempt": 2,
        }
        self.assertEqual(sanitize_log_parameters(details), expected)
        log_security_event_safe("virtualmin_parameter_validation_failed", details, "42", "tenant.example.com")
        event = AuditEvent.objects.get(action="virtualmin_parameter_validation_failed")
        self.assertEqual({key: event.metadata[key] for key in expected}, expected)
        self.assertEqual(event.metadata["service_id"], "42")
        self.assertEqual(event.metadata["domain"], "tenant.example.com")
        self.assertEqual(event.metadata["source_app"], "provisioning")
        self.assertTrue(event.metadata["virtualmin_integration"])
        self.assertEqual(event.actor_type, "system")
        self.assertEqual(event.ip_address, "127.0.0.1")
        self.assertEqual(details["password"], "plain-secret")
