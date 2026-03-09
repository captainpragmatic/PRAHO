"""
Tests for CustomerProfileSerializer.to_representation().

Verifies that date_joined is included in the serialized output and that
last_login is excluded (GDPR Article 5(1)(c) data minimization — behavioral
metadata must not be returned to the customer portal).

Platform tests — full database access via Django TestCase.
"""

from datetime import datetime, timezone as dt_timezone

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.api.customers.serializers import CustomerProfileSerializer

User = get_user_model()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_KNOWN_DATE_JOINED = datetime(2025, 6, 15, 10, 30, 0, tzinfo=dt_timezone.utc)
_KNOWN_LAST_LOGIN = datetime(2026, 1, 20, 8, 0, 0, tzinfo=dt_timezone.utc)


def _create_user(
    email: str,
    *,
    last_login: datetime | None = None,
    date_joined: datetime | None = None,
    first_name: str = "Test",
    last_name: str = "User",
) -> "User":  # type: ignore[name-defined]
    """Create a User with explicit last_login / date_joined."""
    user = User.objects.create_user(
        email=email,
        password="testpass123",
        first_name=first_name,
        last_name=last_name,
    )
    # Override the auto-set fields
    User.objects.filter(pk=user.pk).update(
        date_joined=date_joined or _KNOWN_DATE_JOINED,
        last_login=last_login,
    )
    return User.objects.get(pk=user.pk)


def _ensure_profile(user: "User") -> None:
    """Return the user's profile (created by signal), updating preferences."""
    profile = user.profile
    profile.preferred_language = "ro"
    profile.timezone = "Europe/Bucharest"
    profile.email_notifications = True
    profile.sms_notifications = False
    profile.marketing_emails = False
    profile.save()
    return profile


# ---------------------------------------------------------------------------
# CustomerProfileSerializer — GDPR data minimization
# ---------------------------------------------------------------------------


class CustomerProfileSerializerGDPRTestCase(TestCase):
    """
    Verify GDPR Article 5(1)(c) data minimization: last_login is behavioral
    metadata and must NOT appear in the customer-facing profile API response.
    date_joined is acceptable account information and must still be present.
    """

    def setUp(self) -> None:
        self.user = _create_user(
            "profile-serial@example.ro",
            last_login=_KNOWN_LAST_LOGIN,
            date_joined=_KNOWN_DATE_JOINED,
        )
        _ensure_profile(self.user)

    def _serialize(self) -> dict:
        serializer = CustomerProfileSerializer(instance=self.user)
        return serializer.to_representation(self.user)

    def test_last_login_is_absent_from_output(self) -> None:
        """
        last_login must NOT be present in the serialized output.

        Behavioral metadata (last_login) must be excluded per GDPR
        Article 5(1)(c) data minimization. This applies even when the user
        has a recorded last_login timestamp.
        """
        data = self._serialize()
        self.assertNotIn(
            "last_login",
            data,
            "CustomerProfileSerializer must NOT expose 'last_login' (GDPR data minimization)",
        )

    def test_last_login_absent_when_user_never_logged_in(self) -> None:
        """last_login must NOT be present even when its value would be None."""
        never_logged_in = _create_user(
            "never-logged-in@example.ro",
            last_login=None,
            date_joined=_KNOWN_DATE_JOINED,
        )
        _ensure_profile(never_logged_in)

        data = CustomerProfileSerializer(instance=never_logged_in).to_representation(never_logged_in)
        self.assertNotIn("last_login", data)

    def test_date_joined_field_is_present_in_output(self) -> None:
        """Serialized output must contain a 'date_joined' key."""
        data = self._serialize()
        self.assertIn("date_joined", data, "CustomerProfileSerializer must include 'date_joined'")

    def test_date_joined_is_iso_format_string(self) -> None:
        """date_joined should be an ISO 8601 string."""
        data = self._serialize()
        date_joined_value = data["date_joined"]
        self.assertIsNotNone(date_joined_value)
        self.assertIsInstance(date_joined_value, str)
        parsed = datetime.fromisoformat(date_joined_value)
        self.assertEqual(parsed.year, _KNOWN_DATE_JOINED.year)
        self.assertEqual(parsed.month, _KNOWN_DATE_JOINED.month)
        self.assertEqual(parsed.day, _KNOWN_DATE_JOINED.day)


# ---------------------------------------------------------------------------
# CustomerProfileSerializer — existing fields not broken
# ---------------------------------------------------------------------------


class CustomerProfileSerializerExistingFieldsTestCase(TestCase):
    """Ensure the GDPR last_login removal did not break existing fields."""

    def setUp(self) -> None:
        self.user = _create_user(
            "existing-fields@example.ro",
            last_login=_KNOWN_LAST_LOGIN,
            date_joined=_KNOWN_DATE_JOINED,
            first_name="Maria",
            last_name="Ionescu",
        )
        _ensure_profile(self.user)

    def test_first_name_still_serialized(self) -> None:
        data = CustomerProfileSerializer(instance=self.user).to_representation(self.user)
        self.assertEqual(data["first_name"], "Maria")

    def test_last_name_still_serialized(self) -> None:
        data = CustomerProfileSerializer(instance=self.user).to_representation(self.user)
        self.assertEqual(data["last_name"], "Ionescu")

    def test_preferred_language_still_serialized(self) -> None:
        data = CustomerProfileSerializer(instance=self.user).to_representation(self.user)
        self.assertIn("preferred_language", data)

    def test_timezone_still_serialized(self) -> None:
        data = CustomerProfileSerializer(instance=self.user).to_representation(self.user)
        self.assertIn("timezone", data)

    def test_notification_preferences_still_serialized(self) -> None:
        data = CustomerProfileSerializer(instance=self.user).to_representation(self.user)
        self.assertIn("email_notifications", data)
        self.assertIn("sms_notifications", data)
        self.assertIn("marketing_emails", data)
