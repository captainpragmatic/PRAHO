"""Real Platform factor refusals cross Portal normalizers without becoming browser detail."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pyotp
from django.core.cache import cache
from django.db import DatabaseError, connection
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.customers.models import Customer
from apps.users.mfa import MFAService
from apps.users.models import CustomerMembership, User
from apps.users.pending_totp import PendingTOTPEnrolment, complete_enrolment, get_or_create_pending
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

PASSWORD = "Fixture-password-123!"
PORTAL_ROOT = Path(__file__).resolve().parents[3] / "portal"
OPERATIONS = {
    "verify": ("mfa/verify/", "users:mfa_setup_totp"),
    "disable": ("mfa/disable/", "users:mfa_disable"),
    "regenerate": ("mfa/regenerate-backup-codes/", "users:mfa_backup_codes"),
}
PORTAL_CONSUMER = r"""
import io,json,logging,sys
from unittest.mock import patch
import django
django.setup()
from django.core.cache import cache
from django.test import Client,override_settings
from django.test.utils import setup_test_environment
from django.urls import reverse
from requests import Response
from apps.api_client.services import PlatformAPIError,api_client
from apps.common.auth_events import EVENT_LOGGER,SecurityEventStreamHandler
setup_test_environment()
rows=json.load(sys.stdin)
output=[]
with override_settings(
 MIDDLEWARE=['django.contrib.sessions.middleware.SessionMiddleware','django.contrib.messages.middleware.MessageMiddleware'],
 SESSION_ENGINE='django.contrib.sessions.backends.cache',RATE_LIMITING_ENABLED=False,
 PORTAL_SESSION_ID_REQUIRED=False,PORTAL_BROWSER_FINGERPRINT_REQUIRED=False,PORTAL_SESSION_DEADLINES_REQUIRED=False,
 CROWDSEC_AUTH_EVENTS_ENABLED=True,CROWDSEC_AUTH_LOG_PATH='',
 CROWDSEC_AUTH_PSEUDONYM_KEY='mfa-cross-service-test-only-key',LANGUAGE_CODE='en',DEBUG=True,
 IPWARE_TRUSTED_PROXY_LIST=['127.0.0.1/32'],
 CACHES={'default':{'BACKEND':'django.core.cache.backends.locmem.LocMemCache'}}):
 for row in rows:
  cache.clear()
  client=Client()
  session=client.session
  session.update({'user_id':row['user_id'],'customer_id':row['customer_id'],'email':row['email'],'session_auth_hash':'unchanged-fixture-binding'})
  session.save()
  stream=io.StringIO()
  handler=SecurityEventStreamHandler(stream)
  handler.setFormatter(logging.Formatter('%(message)s'))
  response=Response()
  response.status_code=row['status']
  response.headers['Content-Type']='application/json'
  response._content=json.dumps(row['body']).encode()
  try:
   api_client._handle_api_response(response,'/users/mfa/refusal-fixture/')
  except PlatformAPIError as error:
   normalized_message=str(error)
  with patch.object(EVENT_LOGGER,'handlers',[handler]),patch.object(EVENT_LOGGER,'level',logging.INFO),patch.object(EVENT_LOGGER,'disabled',False),patch.object(EVENT_LOGGER,'propagate',False),patch('apps.api_client.services.portal_request',return_value=response),patch('apps.users.views.api_client.get_customer_profile',return_value={'mfa_enabled':True,'backup_codes_count':5}),patch('apps.users.views.api_client.setup_totp_mfa',return_value={'secret':'fixture-display-only','qr_code':'','provisioning_uri':''}):
   result=client.post(reverse(row['view']),row['form'],HTTP_X_FORWARDED_FOR='198.51.100.29')
  html=result.content.decode()
  form=result.context['form'] if result.context is not None and 'form' in result.context else None
  output.append({'events':[json.loads(line) for line in stream.getvalue().splitlines()],
   'status':result.status_code,'errors':list(form.non_field_errors()) if form is not None else [],'normalized_message':normalized_message,
   'private_visible':any(value in html for value in ('failure_category','>second_factor<','>credentials<')),
   'binding':client.session.get('session_auth_hash')})
  handler.close()
print(json.dumps(output))
"""


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    RATE_LIMITING_ENABLED=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class MFAAuthenticationDetectionTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.customer = Customer.objects.create(name="MFA detection", customer_type="company")
        self.serial = 0

    def person(self, operation: str) -> tuple[User, str]:
        self.serial += 1
        user = User.objects.create_user(email=f"mfa-detection-{self.serial}@example.test", password=PASSWORD)
        CustomerMembership.objects.create(user=user, customer=self.customer, role="owner", is_primary=True)
        if operation == "verify":
            return user, get_or_create_pending(user)
        secret = pyotp.random_base32()
        user.two_factor_enabled = True
        user.two_factor_secret = secret
        user.save(update_fields=["two_factor_enabled", "_two_factor_secret"])
        return user, secret

    def call(self, operation: str, user: User, **fields):
        return self.portal_post(
            "/api/users/" + OPERATIONS[operation][0],
            {"user_id": user.pk, "customer_id": self.customer.pk, **fields},
        )

    def row(self, operation: str, user: User, fields: dict[str, str], response) -> dict[str, object]:
        return {
            "user_id": user.pk,
            "customer_id": self.customer.pk,
            "email": user.email,
            "view": OPERATIONS[operation][1],
            "form": fields,
            "status": response.status_code,
            "body": response.json(),
        }

    def consume(self, rows: list[dict[str, object]]) -> list[dict[str, object]]:
        environment = {**os.environ, "PYTHONPATH": "", "DJANGO_SETTINGS_MODULE": "config.settings.dev"}
        result = subprocess.run(  # noqa: S603 -- fixed interpreter and repository-owned Portal process
            [sys.executable, "-c", PORTAL_CONSUMER],
            cwd=PORTAL_ROOT,
            env=environment,
            input=json.dumps(rows),
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout.strip().splitlines()[-1])

    def test_verified_factor_refusals_reach_real_portal_event_and_generic_browser_error(self) -> None:
        rows, categories = [], []
        for operation in OPERATIONS:
            for category in ("credentials", "second_factor"):
                user, secret = self.person(operation)
                invalid = next(
                    f"{value:06d}"
                    for value in range(10)
                    if not pyotp.TOTP(secret).verify(f"{value:06d}", valid_window=2)
                )
                fields = {
                    "password": "wrong-fixture-password" if category == "credentials" else PASSWORD,
                    "token": invalid,
                }
                response = self.call(operation, user, **fields)
                self.assertEqual(response.status_code, 400, response.content)
                rows.append(self.row(operation, user, fields, response))
                categories.append(category)
            if operation != "verify":
                user, _secret = self.person(operation)
                fields = {"password": PASSWORD, "token": "00000000"}
                response = self.call(operation, user, **fields)
                self.assertEqual(response.status_code, 400, response.content)
                rows.append(self.row(operation, user, fields, response))
                categories.append("second_factor")
        answers = self.consume(rows)
        generic_messages = {
            "users:mfa_setup_totp": "The password or the code is incorrect.",
            "users:mfa_disable": "Could not disable MFA. Check your password and authentication code.",
            "users:mfa_backup_codes": "Could not regenerate codes. Check your password and authentication code.",
        }
        for row, category, answer in zip(rows, categories, answers, strict=True):
            with self.subTest(view=row["view"], category=category):
                self.assertEqual(
                    [event["event"] for event in answer["events"]],
                    ["auth_failure" if category == "credentials" else "mfa_failure"],
                )
                self.assertEqual(row["body"].get("failure_category"), category)
                self.assertFalse(answer["private_visible"])
                self.assertEqual(answer["binding"], "unchanged-fixture-binding")
                self.assertEqual(answer["errors"], [generic_messages[row["view"]]])
                self.assertNotIn("failure_category", answer["normalized_message"])
                self.assertNotIn(category, answer["normalized_message"])
                if row["view"] != "users:mfa_setup_totp":
                    self.assertEqual(set(row["body"]), {"non_field_errors", "failure_category"})
                serialized = json.dumps(answer["events"])
                self.assertNotIn(row["email"], serialized)
                self.assertNotIn(row["form"]["password"], serialized)
                self.assertNotIn(row["form"]["token"], serialized)

    def test_shape_locked_expired_and_inactive_factor_refusals_are_uncategorized(self) -> None:
        rows, expected_events = [], []
        for operation in OPERATIONS:
            user, secret = self.person(operation)
            for token in ("bad", "1234567", "abcdef"):
                response = self.call(operation, user, password=PASSWORD, token=token)
                self.assertEqual(response.status_code, 400)
                self.assertNotIn("failure_category", response.json())
                rows.append(self.row(operation, user, {"password": PASSWORD, "token": token}, response))
                # Reauthentication's existing form accepts 6-8 digits, so seven digits reach
                # Platform but verify no factor; setup and nonnumeric inputs stop at the form.
                expected_events.append(["protection_degraded"] if operation != "verify" and token.isdigit() else [])
            user.account_locked_until = timezone.now() + timedelta(minutes=5)
            user.save(update_fields=["account_locked_until"])
            locked = self.call(operation, user, password=PASSWORD, token=pyotp.TOTP(secret).now())
            self.assertEqual(locked.json().get("code"), "account_locked")
            self.assertNotIn("failure_category", locked.json())
            rows.append(self.row(operation, user, {"password": PASSWORD, "token": "123456"}, locked))
            expected_events.append(["protection_degraded"])
        user, _secret = self.person("verify")
        PendingTOTPEnrolment.objects.filter(user=user).update(expires_at=timezone.now() - timedelta(seconds=1))
        expired = self.call("verify", user, password=PASSWORD, token="123456")
        self.assertEqual(expired.json().get("code"), "mfa_setup_expired")
        self.assertNotIn("failure_category", expired.json())
        rows.append(self.row("verify", user, {"password": PASSWORD, "token": "123456"}, expired))
        expected_events.append(["protection_degraded"])
        enabled, _secret = self.person("disable")
        already = self.call("verify", enabled, password=PASSWORD, token="123456")
        self.assertEqual(already.json().get("code"), "mfa_already_enabled")
        self.assertNotIn("failure_category", already.json())
        rows.append(self.row("verify", enabled, {"password": PASSWORD, "token": "123456"}, already))
        expected_events.append(["protection_degraded"])
        for operation in ("disable", "regenerate"):
            user = User.objects.create_user(email=f"not-enabled-{operation}@example.test", password=PASSWORD)
            response = self.call(operation, user, password="wrong-fixture-password", token="123456")
            self.assertEqual(response.json().get("code"), "mfa_not_enabled")
            self.assertNotIn("failure_category", response.json())
            rows.append(self.row(operation, user, {"password": PASSWORD, "token": "123456"}, response))
            expected_events.append(["protection_degraded"])
        for row, answer, expected in zip(rows, self.consume(rows), expected_events, strict=True):
            with self.subTest(view=row["view"], response=row["body"], token=row["form"]["token"]):
                self.assertEqual([event["event"] for event in answer["events"]], expected)
                self.assertFalse(answer["private_visible"])

    def test_actual_counter_failure_produces_no_factor_category_or_portal_attack(self) -> None:
        rows = []

        def unavailable(execute, sql, params, many, context):
            if "common_counters" in sql and any(
                isinstance(value, str) and value.startswith(("mfa_attempts:", "totp_used:")) for value in params or ()
            ):
                raise DatabaseError("Fixture factor store unavailable")
            return execute(sql, params, many, context)

        for operation in OPERATIONS:
            user, secret = self.person(operation)
            fields = {"password": PASSWORD, "token": pyotp.TOTP(secret).now()}
            with connection.execute_wrapper(unavailable):
                response = self.call(operation, user, **fields)
            self.assertEqual(response.status_code, 503, response.content)
            self.assertNotIn("failure_category", response.json())
            rows.append(self.row(operation, user, fields, response))
        for answer in self.consume(rows):
            self.assertEqual([event["event"] for event in answer["events"]], ["protection_degraded"])
            self.assertFalse(answer["private_visible"])

    def test_actual_wrong_password_remains_a_failure_with_an_unverified_factor_shape(self) -> None:
        rows = []
        for operation in ("disable", "regenerate"):
            for token in ("1234567", "abcdef"):
                user, _secret = self.person(operation)
                fields = {"password": "wrong-fixture-password", "token": token}
                response = self.call(operation, user, **fields)
                self.assertEqual(response.status_code, 400, response.content)
                self.assertEqual(response.json().get("failure_category"), "credentials")
                rows.append(self.row(operation, user, fields, response))
        for row, answer in zip(rows, self.consume(rows), strict=True):
            # The existing Portal form rejects letters before making any API request.
            expected = ["auth_failure"] if row["form"]["token"].isdigit() else []
            self.assertEqual([event["event"] for event in answer["events"]], expected)
            self.assertFalse(answer["private_visible"])
        user, _secret = self.person("verify")
        result = complete_enrolment(user.pk, password="wrong-fixture-password", code="abcdef", request=None)
        self.assertEqual(result.status, "incorrect")
        self.assertEqual(result.failure_category, "credentials")
        for operation in OPERATIONS:
            user, _secret = self.person(operation)
            response = self.call(operation, user, password="wrong-fixture-password", token="bad")
            self.assertNotIn("failure_category", response.json())
        user, _secret = self.person("verify")
        response = self.call("verify", user, password="wrong-fixture-password", token="abcdef")
        self.assertNotIn("failure_category", response.json())

    def test_staff_policy_and_mfa_internal_limit_are_not_failed_factors(self) -> None:
        rows = []
        user, _secret = self.person("disable")
        user.staff_role = "support"
        user.save(update_fields=["staff_role"])
        with patch("apps.users.mfa.staff_mfa_required", return_value=True):
            response = self.call("disable", user, password=PASSWORD, token="123456")
        self.assertEqual(response.json().get("code"), "staff_mfa_required")
        self.assertNotIn("failure_category", response.json())
        rows.append(self.row("disable", user, {"password": PASSWORD, "token": "123456"}, response))
        for operation in ("disable", "regenerate"):
            user, secret = self.person(operation)
            for _ in range(6):
                MFAService._check_rate_limit(user)
            response = self.call(operation, user, password=PASSWORD, token=pyotp.TOTP(secret).now())
            self.assertEqual(response.status_code, 400, response.content)
            self.assertNotIn("failure_category", response.json())
            rows.append(self.row(operation, user, {"password": PASSWORD, "token": "123456"}, response))
        for answer in self.consume(rows):
            self.assertEqual([event["event"] for event in answer["events"]], ["protection_degraded"])
            self.assertFalse(answer["private_visible"])
