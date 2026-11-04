"""Private signed authentication categories must distinguish guesses from outages."""

import pyotp
from django.core.cache import cache
from django.db import connection
from django.test import TestCase, override_settings

from apps.common.counters import Counter
from apps.users import portal_sessions
from apps.users.models import User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class PortalAuthDetectionCategoriesTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.password = "Fixture-password-123!"
        self.user = User.objects.create_user(email="private@example.test", password=self.password)

    def test_password_and_second_factor_refusals_have_private_categories(self) -> None:
        wrong_password = self.portal_post("/api/users/login/", {"email": self.user.email, "password": "wrong"})
        self.assertEqual(wrong_password.status_code, 401)
        self.assertEqual(wrong_password.json().get("failure_category"), "credentials")
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = pyotp.random_base32()
        self.user.save(update_fields=["two_factor_enabled", "_two_factor_secret"])
        wrong_factor = self.portal_post("/api/users/login/", {"email": self.user.email, "password": self.password})
        self.assertEqual(wrong_factor.status_code, 401)
        self.assertEqual(wrong_factor.json().get("failure_category"), "second_factor")

    def test_actual_mfa_counter_outage_is_never_a_wrong_factor(self) -> None:
        self.user.two_factor_enabled = True
        secret = pyotp.random_base32()
        self.user.two_factor_secret = secret
        self.user.save(update_fields=["two_factor_enabled", "_two_factor_secret"])
        # Fail only the real MFA counter INSERT. HMAC nonce admission uses the same
        # table and must remain live so this request actually reaches verification.
        with connection.cursor() as cursor:
            if connection.vendor == "postgresql":
                cursor.execute("""
                    CREATE FUNCTION pg_temp.crowdsec_mfa_counter_down() RETURNS trigger
                    LANGUAGE plpgsql AS $$ BEGIN
                    IF NEW.key LIKE 'mfa_attempts:%' THEN
                        RAISE EXCEPTION 'fixture MFA store unavailable' USING ERRCODE='58000';
                    END IF;
                    RETURN NEW; END $$
                """)
                cursor.execute("""
                    CREATE TRIGGER crowdsec_mfa_counter_down BEFORE INSERT ON common_counters
                    FOR EACH ROW EXECUTE FUNCTION pg_temp.crowdsec_mfa_counter_down()
                """)
            else:
                cursor.execute("""
                    CREATE TRIGGER crowdsec_mfa_counter_down BEFORE INSERT ON common_counters
                    WHEN NEW.key LIKE 'mfa_attempts:%'
                    BEGIN SELECT RAISE(ABORT, 'fixture MFA store unavailable'); END
                """)
        try:
            with override_settings(RATE_LIMITING_ENABLED=False):
                response = self.portal_post(
                    "/api/users/login/",
                    {"email": self.user.email, "password": self.password, "mfa_token": pyotp.TOTP(secret).now()},
                )
        finally:
            with connection.cursor() as cursor:
                suffix = " ON common_counters" if connection.vendor == "postgresql" else ""
                cursor.execute("DROP TRIGGER crowdsec_mfa_counter_down" + suffix)
        self.assertTrue(Counter.objects.filter(key__startswith="hmac_nonce:").exists(), "HMAC admission completed")
        self.assertEqual(response.status_code, 503, response.content)
        self.assertNotIn("failure_category", response.json())
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)

    def test_identity_confirmation_keeps_the_verified_factor_private(self) -> None:
        session = portal_sessions.open_session(self.user)
        path = "/api/users/session/reauth/"
        fields = {"user_id": self.user.pk, "session_id": str(session.pk)}
        password = self.portal_post(path, {**fields, "password": "wrong"})
        self.assertEqual(password.status_code, 400, password.content)
        self.assertEqual(password.json().get("failure_category"), "credentials")
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = pyotp.random_base32()
        self.user.save(update_fields=["two_factor_enabled", "_two_factor_secret"])
        session.credential_snapshot = self.user.get_session_auth_hash()
        session.save(update_fields=["credential_snapshot"])
        factor = self.portal_post(path, {**fields, "password": self.password, "mfa_code": "000000"})
        self.assertEqual(factor.status_code, 400, factor.content)
        self.assertEqual(factor.json().get("failure_category"), "second_factor")

    def test_mfa_ordinary_logs_never_duplicate_accounts_or_credentials(self) -> None:
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = pyotp.random_base32()
        self.user.save(update_fields=["two_factor_enabled", "_two_factor_secret"])
        codes = self.user.generate_backup_codes()
        wrong = next(f"{index:08d}" for index in range(100) if f"{index:08d}" not in codes)
        with self.assertLogs("apps.users.mfa", level="INFO") as captured:
            for token, status in ((wrong, 401), (codes[0], 200)):
                result = self.portal_post(
                    "/api/users/login/", {"email": self.user.email, "password": self.password, "mfa_token": token}
                )
                self.assertEqual(result.status_code, status, result.content)
        output = "\n".join(captured.output)
        for value in (self.user.email, self.password, wrong, *codes):
            self.assertNotIn(value, output)

    def test_unreadable_stored_factor_is_an_outage_without_an_attack_charge(self) -> None:
        User.objects.filter(pk=self.user.pk).update(
            two_factor_enabled=True, _two_factor_secret="aes:unreadable-ciphertext"
        )
        response = self.portal_post(
            "/api/users/login/", {"email": self.user.email, "password": self.password, "mfa_token": "000000"}
        )
        self.assertEqual(response.status_code, 503, response.content)
        self.assertNotIn("failure_category", response.json())
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)

    def test_malformed_attacker_codes_remain_ordinary_second_factor_refusals(self) -> None:
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = pyotp.random_base32()
        self.user.save(update_fields=["two_factor_enabled", "_two_factor_secret"])
        for token in ("00000000", "malformed", "☃"):
            with self.subTest(token=token):
                response = self.portal_post(
                    "/api/users/login/", {"email": self.user.email, "password": self.password, "mfa_token": token}
                )
                self.assertEqual(response.status_code, 401, response.content)
                self.assertEqual(response.json()["failure_category"], "second_factor")
