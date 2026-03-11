from __future__ import annotations

import pyotp
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase

from apps.users.mfa import backup_code_service, mfa_service, totp_service

User = get_user_model()


class MFASecurityIntegrationTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.user = User.objects.create_user(email="mfa-user@example.ro", password="testpass123")

    def tearDown(self) -> None:
        cache.clear()

    def test_enable_totp_encrypts_secret_and_allows_valid_token_verification(self) -> None:
        secret, _backup_codes = mfa_service.enable_totp(self.user)

        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)
        self.assertNotEqual(self.user._two_factor_secret, secret)
        self.assertEqual(self.user.two_factor_secret, secret)

        current_code = pyotp.TOTP(secret).now()
        verification = mfa_service.verify_mfa_code(self.user, current_code)

        self.assertTrue(verification["success"])
        self.assertEqual(verification["method"], "totp")

    def test_backup_code_is_single_use(self) -> None:
        _secret, backup_codes = mfa_service.enable_totp(self.user)
        first_backup_code = backup_codes[0]

        first_attempt = mfa_service.verify_mfa_code(self.user, first_backup_code)
        second_attempt = mfa_service.verify_mfa_code(self.user, first_backup_code)

        self.assertTrue(first_attempt["success"])
        self.assertEqual(first_attempt["method"], "backup_code")
        self.assertFalse(second_attempt["success"])

    def test_totp_replay_protection_blocks_same_code_reuse(self) -> None:
        secret, _backup_codes = mfa_service.enable_totp(self.user)
        token = pyotp.TOTP(secret).now()

        first = totp_service.verify_token(self.user, token)
        replay = totp_service.verify_token(self.user, token)

        self.assertTrue(first)
        self.assertFalse(replay)

    def test_backup_codes_are_hashed_on_user_model(self) -> None:
        codes = backup_code_service.generate_codes(self.user)
        self.user.save(update_fields=["backup_tokens"])
        self.user.refresh_from_db()

        self.assertEqual(len(codes), len(self.user.backup_tokens))
        for code, hashed in zip(codes, self.user.backup_tokens, strict=True):
            self.assertNotEqual(code, hashed)
