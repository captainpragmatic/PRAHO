"""A credential change locks its user without blocking a revocation's audit insert.

A password or second-factor change locks the user, then re-stamps the portal session that made it.
Ending a session holds that session's row while its audit insert takes a key-share lock on the
user. A FOR UPDATE on the user would make that insert wait while the change waits for the session
row: a deadlock. FOR NO KEY UPDATE still serialises the credential changes among themselves.
"""

from __future__ import annotations

import json
import time
from typing import Any
from unittest import skipUnless

import pyotp
from django.core.cache import cache
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from apps.customers.models import Customer
from apps.users import portal_sessions
from apps.users.models import CustomerMembership, PortalSession, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers

PASSWORD = "Original-secure123!"  # test fixture, not a credential
NEW_PASSWORD = "Replaced-secure456!"  # test fixture, not a credential


@skipUnless(connection.vendor == "postgresql", "row lock modes are PostgreSQL's")
@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class CredentialChangeLockTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.user = User.objects.create_user(email="locks@example.ro", password=PASSWORD)
        customer = Customer.objects.create(name="Locks SRL", customer_type="company", status="active")
        CustomerMembership.objects.create(user=self.user, customer=customer, role="owner", is_primary=True)
        self.session = portal_sessions.open_session(self.user)

    def call(self, suffix: str, **data: Any) -> Any:
        body = {"user_id": self.user.pk, "session_id": str(self.session.pk), **data}
        return self.portal_post("/api/users/" + suffix, body)

    def enable_two_factor(self) -> str:
        secret = str(self.call("mfa/setup/").json()["setup_data"]["manual_entry_key"])
        response = self.call("mfa/verify/", password=PASSWORD, token=pyotp.TOTP(secret).now())
        self.assertEqual(response.status_code, 200, response.content)
        return str(response.json()["backup_codes"][0])

    def assert_locks_and_restamp(self, queries: CaptureQueriesContext) -> None:
        locks = [q["sql"] for q in queries.captured_queries if 'FROM "users" ' in q["sql"] and " FOR " in q["sql"]]
        self.assertTrue(locks)
        self.assertTrue(all("FOR NO KEY UPDATE" in sql for sql in locks), locks)
        self.user.refresh_from_db()
        session = PortalSession.objects.get(pk=self.session.pk)
        self.assertIsNone(session.revoked_at)  # the session that made the change keeps going
        self.assertEqual(session.credential_snapshot, self.user.get_session_auth_hash())

    def test_a_password_change(self) -> None:
        path = "/api/users/change-password/"
        body = json.dumps(
            {
                "user_id": self.user.pk,
                "session_id": str(self.session.pk),
                "current_password": PASSWORD,
                "new_password": NEW_PASSWORD,
                "timestamp": time.time(),
            }
        ).encode()
        with CaptureQueriesContext(connection) as queries:
            response = self.client.put(path, body, content_type="application/json", **hmac_headers("PUT", path, body))
        self.assertEqual(response.status_code, 200, response.content)
        self.assert_locks_and_restamp(queries)

    def test_turning_two_factor_on(self) -> None:
        secret = str(self.call("mfa/setup/").json()["setup_data"]["manual_entry_key"])
        with CaptureQueriesContext(connection) as queries:
            response = self.call("mfa/verify/", password=PASSWORD, token=pyotp.TOTP(secret).now())
        self.assertEqual(response.status_code, 200, response.content)
        self.assert_locks_and_restamp(queries)

    def test_turning_two_factor_off(self) -> None:
        backup_code = self.enable_two_factor()
        self.session.refresh_from_db()
        with CaptureQueriesContext(connection) as queries:
            response = self.call("mfa/disable/", password=PASSWORD, token=backup_code)
        self.assertEqual(response.status_code, 200, response.content)
        self.assert_locks_and_restamp(queries)
