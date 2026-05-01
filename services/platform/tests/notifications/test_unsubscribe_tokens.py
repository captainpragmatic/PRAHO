"""
Tests for UnsubscribeToken model and opaque unsubscribe URL flow.

Verifies GDPR Art. 5(1)(c) data minimization — no email addresses in URLs.
"""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.db.utils import OperationalError
from django.test import TestCase
from django.utils import timezone

from apps.customers.models import Customer
from apps.notifications.models import TOKEN_EXPIRY_DAYS, UnsubscribeToken
from apps.notifications.services import EmailPreferenceService, EmailService


class UnsubscribeTokenModelTests(TestCase):
    """Tests for UnsubscribeToken model lifecycle."""

    def test_create_token(self) -> None:
        """Test basic token creation."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="marketing",
        )
        self.assertIsNotNone(token.id)
        self.assertEqual(token.email, "test@example.com")
        self.assertEqual(token.template_key, "marketing")
        self.assertIsNone(token.used_at)
        self.assertIsNotNone(token.created_at)

    def test_token_str_masks_email(self) -> None:
        """Test string representation masks email for privacy."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="newsletter",
        )
        display = str(token)
        # Should contain token ID and masked email
        self.assertIn("tes***", display)
        self.assertNotIn("example.com", display)

    def test_token_uniqueness(self) -> None:
        """Test multiple tokens for same email get unique UUIDs."""
        t1 = UnsubscribeToken.objects.create(email="user@test.com", template_key="a")
        t2 = UnsubscribeToken.objects.create(email="user@test.com", template_key="a")
        self.assertNotEqual(t1.id, t2.id)

    def test_consume_success(self) -> None:
        """Test consuming a valid, unused token."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="marketing",
        )
        result = token.consume()
        self.assertTrue(result)
        self.assertIsNotNone(token.used_at)

    def test_consume_already_used(self) -> None:
        """Test consuming an already-used token returns False."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="marketing",
        )
        token.consume()

        # Second consume should fail
        result = token.consume()
        self.assertFalse(result)

    def test_consume_expired(self) -> None:
        """Test consuming an expired token returns False."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="marketing",
        )
        # Backdate creation to make it expired
        expired_time = timezone.now() - timedelta(days=TOKEN_EXPIRY_DAYS + 1)
        UnsubscribeToken.objects.filter(id=token.id).update(created_at=expired_time)
        token.refresh_from_db()

        result = token.consume()
        self.assertFalse(result)
        self.assertIsNone(token.used_at)

    def test_is_expired_false_for_new_token(self) -> None:
        """Test new token is not expired."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="marketing",
        )
        self.assertFalse(token.is_expired())

    def test_is_expired_true_for_old_token(self) -> None:
        """Test old token is expired."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="marketing",
        )
        old_time = timezone.now() - timedelta(days=TOKEN_EXPIRY_DAYS + 1)
        UnsubscribeToken.objects.filter(id=token.id).update(created_at=old_time)
        token.refresh_from_db()

        self.assertTrue(token.is_expired())

    def test_is_expired_boundary(self) -> None:
        """Test expiry at exact boundary."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="marketing",
        )
        # Set to exactly TOKEN_EXPIRY_DAYS ago (should be expired)
        boundary_time = timezone.now() - timedelta(days=TOKEN_EXPIRY_DAYS, seconds=1)
        UnsubscribeToken.objects.filter(id=token.id).update(created_at=boundary_time)
        token.refresh_from_db()

        self.assertTrue(token.is_expired())


class UnsubscribeURLGenerationTests(TestCase):
    """Tests for unsubscribe URL generation using opaque tokens."""

    def test_url_contains_no_email(self) -> None:
        """GDPR Art. 5: URL must not contain email address."""
        url = EmailService._generate_unsubscribe_url(
            "user@example.com", "marketing"
        )
        self.assertNotIn("user@example.com", url)
        self.assertNotIn("user%40example.com", url)
        self.assertNotIn("email=", url)

    def test_url_contains_uuid(self) -> None:
        """Test URL contains the opaque token UUID."""
        url = EmailService._generate_unsubscribe_url(
            "user@example.com", "marketing"
        )
        # URL should contain the notifications unsubscribe path with a UUID
        self.assertIn("/notifications/unsubscribe/", url)
        # Should end with a UUID pattern
        parts = url.rstrip("/").split("/")
        token_id = parts[-1]
        # Verify it's a valid UUID by looking it up
        token = UnsubscribeToken.objects.get(id=token_id)
        self.assertEqual(token.email, "user@example.com")
        self.assertEqual(token.template_key, "marketing")

    def test_url_creates_db_record(self) -> None:
        """Test URL generation creates a DB token record."""
        count_before = UnsubscribeToken.objects.count()
        EmailService._generate_unsubscribe_url("a@b.com", "billing")
        count_after = UnsubscribeToken.objects.count()

        self.assertEqual(count_after, count_before + 1)

    def test_multiple_urls_create_separate_tokens(self) -> None:
        """Test each URL generation creates a new token."""
        url1 = EmailService._generate_unsubscribe_url("a@b.com", "marketing")
        url2 = EmailService._generate_unsubscribe_url("a@b.com", "marketing")
        self.assertNotEqual(url1, url2)


class ProcessUnsubscribeTests(TestCase):
    """Tests for the updated process_unsubscribe using DB tokens."""

    def test_valid_token_processes_unsubscribe(self) -> None:
        """Test valid token triggers unsubscribe flow when no customer exists."""
        token = UnsubscribeToken.objects.create(
            email="unsub@example.com",
            template_key="marketing",
        )

        with patch("apps.notifications.services.EmailSuppressionService.suppress_email") as mock_suppress:
            result = EmailPreferenceService.process_unsubscribe(str(token.id))
            self.assertTrue(result)
            mock_suppress.assert_called_once_with("unsub@example.com", "unsubscribe")

        # Token should be consumed
        token.refresh_from_db()
        self.assertIsNotNone(token.used_at)

    def test_invalid_token_rejected(self) -> None:
        """Test invalid token ID is rejected."""
        result = EmailPreferenceService.process_unsubscribe(str(uuid4()))
        self.assertFalse(result)

    def test_malformed_uuid_rejected_as_invalid(self) -> None:
        """Malformed UUID (legacy ?token=... path) is logged as WARNING, not ERROR.

        Django's UUIDField.to_python raises ValidationError (NOT ValueError) for
        non-UUID strings. The inner except clause must catch ValidationError so
        a malformed token is logged as WARNING ("invalid or unknown token") rather
        than bubbling to the outer except Exception and being logged as ERROR
        ("failed to process token") — the latter would generate spurious oncall
        pages for normal user input. Asserting log level (not just return value)
        is the only proof that distinguishes the fixed code from the pre-fix code,
        since both return False.
        """
        with self.assertLogs("apps.notifications.services", level="WARNING") as captured:
            result = EmailPreferenceService.process_unsubscribe("not-a-valid-uuid")

        self.assertFalse(result)
        # Exactly one WARNING about the invalid token; no ERROR-level "failed to process".
        warnings = [r for r in captured.records if r.levelname == "WARNING"]
        errors = [r for r in captured.records if r.levelname == "ERROR"]
        self.assertEqual(len(warnings), 1)
        self.assertIn("Invalid or unknown token", warnings[0].getMessage())
        self.assertEqual(errors, [])

    def test_already_used_token_rejected(self) -> None:
        """Test already-consumed token is rejected."""
        token = UnsubscribeToken.objects.create(
            email="used@example.com",
            template_key="marketing",
        )
        token.consume()

        result = EmailPreferenceService.process_unsubscribe(str(token.id))
        self.assertFalse(result)

    def test_expired_token_rejected(self) -> None:
        """Test expired token is rejected."""
        token = UnsubscribeToken.objects.create(
            email="expired@example.com",
            template_key="marketing",
        )
        old_time = timezone.now() - timedelta(days=TOKEN_EXPIRY_DAYS + 1)
        UnsubscribeToken.objects.filter(id=token.id).update(created_at=old_time)

        result = EmailPreferenceService.process_unsubscribe(str(token.id))
        self.assertFalse(result)

    def test_unsubscribe_with_customer(self) -> None:
        """Unsubscribe via token withdraws consent and emits a correct GDPR audit event."""
        customer = Customer.objects.create(
            name="Unsubscribe Customer",
            customer_type="individual",
            primary_email="customer@example.com",
            marketing_consent=True,
        )
        token = UnsubscribeToken.objects.create(
            email="customer@example.com",
            template_key="marketing",
        )

        with patch("apps.audit.services.AuditService.log_simple_event") as mock_audit:
            result = EmailPreferenceService.process_unsubscribe(
                str(token.id), "marketing"
            )

        self.assertTrue(result)
        customer.refresh_from_db()
        self.assertFalse(customer.marketing_consent)

        mock_audit.assert_called_once()
        call_args = mock_audit.call_args
        self.assertEqual(call_args.args[0], "marketing_consent_withdrawn")
        self.assertEqual(call_args.kwargs["content_object"], customer)
        self.assertEqual(call_args.kwargs["old_values"], {"marketing_consent": True})
        self.assertEqual(call_args.kwargs["new_values"], {"marketing_consent": False})
        self.assertEqual(call_args.kwargs["metadata"]["source"], "unsubscribe_link")
        self.assertEqual(call_args.kwargs["metadata"]["category"], "marketing")

    def test_unsubscribe_audit_failure_does_not_block_consent_withdrawal(self) -> None:
        """GDPR Art. 7(3): service-layer audit errors must never block a consent withdrawal.

        Note: patching log_simple_event raises a Python exception, which the savepoint
        catches. It does NOT simulate the full PostgreSQL InFailedSqlTransaction recovery
        path (that would require a real failed SQL statement inside the savepoint, which
        is not feasible in a unit test). The savepoint pattern is correct by code reading;
        this test verifies the Python-level exception handling.
        """
        customer = Customer.objects.create(
            name="Resilient Customer",
            customer_type="individual",
            primary_email="resilient@example.com",
            marketing_consent=True,
        )
        token = UnsubscribeToken.objects.create(
            email="resilient@example.com",
            template_key="marketing",
        )

        with patch(
            "apps.audit.services.AuditService.log_simple_event",
            side_effect=OperationalError("audit table down"),
        ):
            result = EmailPreferenceService.process_unsubscribe(str(token.id), "marketing")

        self.assertTrue(result)
        customer.refresh_from_db()
        self.assertFalse(customer.marketing_consent)

    def test_unsubscribe_signal_audit_failure_does_not_block_consent_withdrawal(self) -> None:
        """GDPR Art. 7(3): signal-side audit errors must also not block consent.

        Customer.save() fires post_save → _handle_marketing_consent_change → log_compliance_event.
        On real Postgres, an OperationalError mid-SQL inside log_compliance_event would mark the
        connection InFailedSqlTransaction and force a rollback of the outer transaction unless
        wrapped in a savepoint. This test patches log_compliance_event (the signal-side path),
        distinct from the log_simple_event test above (the service-layer path).

        Test limitation: SQLite does not implement InFailedSqlTransaction state, so this test
        cannot empirically distinguish "savepoint present" from "savepoint absent" — falsified
        in this session by removing the savepoint and observing the test still pass. The
        savepoint is required for production Postgres correctness; this test verifies the
        Python-level exception flow only. Project-wide test-config limitation, also affects
        select_for_update() coverage.
        """
        customer = Customer.objects.create(
            name="Signal Resilient",
            customer_type="individual",
            primary_email="signal-resilient@example.com",
            marketing_consent=True,
        )
        token = UnsubscribeToken.objects.create(
            email="signal-resilient@example.com",
            template_key="marketing",
        )

        with patch(
            "apps.audit.services.AuditService.log_compliance_event",
            side_effect=OperationalError("compliance audit table down"),
        ):
            result = EmailPreferenceService.process_unsubscribe(str(token.id), "marketing")

        self.assertTrue(result)
        customer.refresh_from_db()
        self.assertFalse(customer.marketing_consent)


class UpdatePreferencesTests(TestCase):
    """Tests for EmailPreferenceService.update_preferences."""

    def _make_customer(self, *, marketing: bool = False) -> Customer:
        return Customer.objects.create(
            name="Pref Customer",
            customer_type="individual",
            primary_email="prefs@example.com",
            marketing_consent=marketing,
        )

    def test_update_preferences_persists_marketing_consent(self) -> None:
        """Setting marketing=True persists and emits a granted audit event."""
        customer = self._make_customer(marketing=False)

        with patch("apps.audit.services.AuditService.log_simple_event") as mock_audit:
            EmailPreferenceService.update_preferences(customer, {"marketing": True})

        customer.refresh_from_db()
        self.assertTrue(customer.marketing_consent)
        mock_audit.assert_called_once()
        self.assertEqual(mock_audit.call_args.args[0], "marketing_consent_granted")
        self.assertEqual(mock_audit.call_args.kwargs["old_values"], {"marketing_consent": False})
        self.assertEqual(mock_audit.call_args.kwargs["new_values"], {"marketing_consent": True})

    def test_update_preferences_no_audit_when_unchanged(self) -> None:
        """If consent value is unchanged, no audit event is emitted."""
        customer = self._make_customer(marketing=True)

        with patch("apps.audit.services.AuditService.log_simple_event") as mock_audit:
            EmailPreferenceService.update_preferences(customer, {"marketing": True})

        mock_audit.assert_not_called()

    def test_marketing_key_wins_over_newsletters_alias(self) -> None:
        """Explicit marketing=False cannot be silently reversed by newsletters=True."""
        customer = self._make_customer(marketing=True)

        EmailPreferenceService.update_preferences(
            customer, {"marketing": False, "newsletters": True}
        )

        customer.refresh_from_db()
        self.assertFalse(customer.marketing_consent)

    def test_newsletters_alias_applies_when_marketing_absent(self) -> None:
        """Legacy clients sending only 'newsletters' still update marketing_consent."""
        customer = self._make_customer(marketing=False)

        EmailPreferenceService.update_preferences(customer, {"newsletters": True})

        customer.refresh_from_db()
        self.assertTrue(customer.marketing_consent)

    def test_update_preferences_audit_failure_does_not_block_consent_change(self) -> None:
        """GDPR Art. 7(3): service-layer audit errors must never block a consent change.

        See test_unsubscribe_audit_failure_does_not_block_consent_withdrawal for the
        note on why a Python-level OperationalError mock is the practical limit of
        unit testing here.
        """
        customer = self._make_customer(marketing=False)

        with patch(
            "apps.audit.services.AuditService.log_simple_event",
            side_effect=OperationalError("audit table down"),
        ):
            EmailPreferenceService.update_preferences(customer, {"marketing": True})

        customer.refresh_from_db()
        self.assertTrue(customer.marketing_consent)

    def test_update_preferences_signal_audit_failure_does_not_block_consent_change(self) -> None:
        """GDPR Art. 7(3): signal-side audit errors must also not block consent.

        Counterpart to test_update_preferences_audit_failure: patches log_compliance_event
        (the customers.signals path) instead of log_simple_event (the service-layer path).
        """
        customer = self._make_customer(marketing=False)

        with patch(
            "apps.audit.services.AuditService.log_compliance_event",
            side_effect=OperationalError("compliance audit table down"),
        ):
            EmailPreferenceService.update_preferences(customer, {"marketing": True})

        customer.refresh_from_db()
        self.assertTrue(customer.marketing_consent)
