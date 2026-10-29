"""Customer view: a staff member's scoped, read-only portal session as one customer member (ADR-0065).

Portal calls go through the real HMAC middleware (test settings strip it), where the binding and the
read-only gate run for every route, decorated or not.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from datetime import timedelta

from django.contrib.sessions.models import Session
from django.core.exceptions import PermissionDenied
from django.test import TestCase, override_settings
from django.urls import URLPattern, URLResolver, get_resolver, reverse
from django.utils import timezone

from apps.api import customer_view_policy
from apps.audit.models import AuditEvent
from apps.customers.models import Customer
from apps.users import customer_view, portal_sessions, session_policy
from apps.users.models import CustomerMembership, CustomerViewGrant, PortalSession, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers

PASSWORD = "Correct-Horse-Battery-9"
PORTAL = "https://portal.example.test"


class CustomerViewFixture(TestCase):
    def setUp(self) -> None:
        self.staff = User.objects.create_user(email="support@example.test", password=PASSWORD, staff_role="support")
        User.objects.filter(pk=self.staff.pk).update(two_factor_enabled=True)
        self.staff.refresh_from_db()
        self.customer = Customer.objects.create(name="Acme", primary_email="acme@example.test", status="active")
        self.other_customer = Customer.objects.create(name="Other", primary_email="o@example.test", status="active")
        self.target = User.objects.create_user(email="owner@example.test", password=PASSWORD)
        CustomerMembership.objects.create(user=self.target, customer=self.customer, role="owner", is_active=True)
        CustomerMembership.objects.create(user=self.target, customer=self.other_customer, role="owner", is_active=True)
        self.client.force_login(self.staff)
        self.mark_mfa_login()

    def mark_mfa_login(self) -> None:
        session = self.client.session
        session[customer_view.MFA_LOGIN_MARKER] = timezone.now().isoformat()
        session.save()

    def start_url(self) -> str:
        return reverse("customers:customer_view_start", args=[self.customer.pk, self.target.pk])

    def issue(self) -> str:
        response = self.client.post(
            self.start_url(), {"reason_category": "support_request", "reason": "Customer cannot find invoice 12"}
        )
        self.assertEqual(response.status_code, 200, response.content[:400])
        match = re.search(rb'name="code" value="([A-Za-z0-9_-]{43})"', response.content)
        assert match is not None, "the handoff page carries the one-time code"
        return match.group(1).decode()


@override_settings(PORTAL_PUBLIC_ORIGIN=PORTAL, CUSTOMER_VIEW_ENABLED=True)
class IssueTests(CustomerViewFixture):
    def test_the_handoff_posts_the_code_to_the_portal_and_stores_only_its_digest(self) -> None:
        response = self.client.post(
            self.start_url(), {"reason_category": "support_request", "reason": "Customer cannot find invoice 12"}
        )
        self.assertEqual(response.status_code, 200)
        found = re.search(rb'name="code" value="([^"]+)"', response.content)
        assert found is not None, "the handoff page carries the one-time code"
        code = found.group(1).decode()
        self.assertIn(f'action="{PORTAL}/customer-view/redeem/"', response.content.decode())
        grant = CustomerViewGrant.objects.get()
        self.assertNotEqual(grant.code_digest, code)
        self.assertEqual(grant.code_digest, customer_view._digest(code))
        self.assertIn(f"form-action 'self' {PORTAL};", response["Content-Security-Policy"])
        self.assertIn("no-store", response["Cache-Control"])
        self.assertTrue(AuditEvent.objects.filter(action="customer_view_issued").exists())

    def test_only_the_handoff_page_may_post_to_the_portal(self) -> None:
        page = self.client.get(self.start_url())
        self.assertIn("form-action 'self';", page["Content-Security-Policy"])

    def test_a_session_that_did_not_use_the_second_factor_cannot_issue(self) -> None:
        session = self.client.session
        del session[customer_view.MFA_LOGIN_MARKER]
        session.save()
        page = self.client.get(self.start_url())
        self.assertContains(page, 'data-customer-view-blocker="staff_login_mfa"')
        response = self.client.post(self.start_url(), {"reason_category": "support_request", "reason": "x" * 20})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(CustomerViewGrant.objects.exists())
        self.assertTrue(AuditEvent.objects.filter(action="customer_view_issue_denied").exists())

    def test_who_and_whom_are_checked(self) -> None:
        cases = {
            "billing staff": lambda: User.objects.filter(pk=self.staff.pk).update(staff_role="billing"),
            "prospect customer": lambda: Customer.objects.filter(pk=self.customer.pk).update(status="prospect"),
            "staff target": lambda: User.objects.filter(pk=self.target.pk).update(staff_role="support"),
            "inactive membership": lambda: CustomerMembership.objects.filter(
                user=self.target, customer=self.customer
            ).update(is_active=False),
        }
        for label, break_it in cases.items():
            with self.subTest(label), self.captureOnCommitCallbacks():
                sid = transaction_savepoint()
                break_it()
                response = self.client.post(
                    self.start_url(), {"reason_category": "support_request", "reason": "A reason long enough"}
                )
                self.assertEqual(response.status_code, 403, label)
                transaction_rollback(sid)
        self.assertFalse(CustomerViewGrant.objects.exists())

    def test_a_short_reason_is_refused(self) -> None:
        response = self.client.post(self.start_url(), {"reason_category": "support_request", "reason": "short"})
        self.assertEqual(response.status_code, 403)

    def test_twenty_grants_an_hour(self) -> None:
        codes = [self.issue() for _ in range(customer_view.HOURLY_LIMIT)]
        response = self.client.post(self.start_url(), {"reason_category": "support_request", "reason": "x" * 20})
        self.assertEqual(response.status_code, 403)
        # The quota limits issuing; the twentieth grant issued is still redeemable.
        self.assertEqual(customer_view.consume(codes[-1]).tier, PortalSession.TIER_CUSTOMER_VIEW)


def transaction_savepoint() -> str:
    from django.db import transaction  # noqa: PLC0415

    return transaction.savepoint()


def transaction_rollback(sid: str) -> None:
    from django.db import transaction  # noqa: PLC0415

    transaction.savepoint_rollback(sid)


@override_settings(PORTAL_PUBLIC_ORIGIN=PORTAL, CUSTOMER_VIEW_ENABLED=True)
class ConsumeTests(CustomerViewFixture):
    def test_a_code_opens_one_scoped_session_once(self) -> None:
        code = self.issue()
        row = customer_view.consume(code)
        self.assertEqual(row.tier, PortalSession.TIER_CUSTOMER_VIEW)
        self.assertEqual(row.user, self.target)
        self.assertEqual(row.viewed_as_customer_by, self.staff)
        self.assertLessEqual(row.expires_at - row.created_at, session_policy.TIERS["customer_view"].absolute + timedelta(seconds=1))
        with self.assertRaises(PermissionDenied):
            customer_view.consume(code)

    def test_an_expired_code_is_refused(self) -> None:
        code = self.issue()
        CustomerViewGrant.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        with self.assertRaises(PermissionDenied):
            customer_view.consume(code)

    def test_a_credential_change_between_issue_and_redeem_voids_the_code(self) -> None:
        for who in ("staff", "target"):
            with self.subTest(who):
                code = self.issue()
                user = self.staff if who == "staff" else self.target
                User.objects.filter(pk=user.pk).update(password=user.password + "x")
                with self.assertRaises(PermissionDenied):
                    customer_view.consume(code)
                User.objects.filter(pk=user.pk).update(password=user.password)

    def test_a_malformed_or_unknown_code_is_refused(self) -> None:
        for code in ("", "x" * 43, "a" * 44, None, 7):
            with self.subTest(code=code), self.assertRaises(PermissionDenied):
                customer_view.consume(code)


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    PORTAL_HMAC_MODE="legacy",
    PORTAL_PUBLIC_ORIGIN=PORTAL,
    CUSTOMER_VIEW_ENABLED=True,
    PORTAL_SESSION_REQUIRED=True,
)
class ScopedSessionTests(HMACTestMixin, CustomerViewFixture):
    def setUp(self) -> None:
        super().setUp()
        self.row = customer_view.consume(self.issue())

    def call(self, path: str, body: dict[str, object] | None = None, method: str = "POST") -> int:
        payload = {"user_id": self.target.pk, "session_id": str(self.row.pk), **(body or {})}
        payload.setdefault("timestamp", int(time.time()))
        raw = json.dumps(payload).encode()
        headers = hmac_headers(method, path, raw, portal_id=self.portal_id)
        return self.client.generic(method, path, raw, content_type="application/json", **headers).status_code

    def test_redeem_answers_the_session_and_never_a_credential(self) -> None:
        code = self.issue()
        response = self.portal_post("/api/users/customer-view/redeem/", {"code": code, "client_ip": "203.0.113.9"})
        self.assertEqual(response.status_code, 200, response.content)
        data = response.json()
        self.assertNotIn("session_auth_hash", data)
        self.assertEqual(data["customer"]["id"], self.customer.pk)
        again = self.portal_post("/api/users/customer-view/redeem/", {"code": code, "client_ip": "203.0.113.9"})
        self.assertEqual(again.status_code, 403)
        self.assertTrue(AuditEvent.objects.filter(action="customer_view_denied").exists())

    def test_reads_are_served_and_recorded(self) -> None:
        self.assertEqual(self.call("/api/users/customers/"), 200)
        self.assertTrue(AuditEvent.objects.filter(action="customer_view_accessed").exists())

    def test_reading_the_profile_never_creates_one(self) -> None:
        from apps.users.models import UserProfile  # noqa: PLC0415

        UserProfile.objects.filter(user=self.target).delete()
        self.assertEqual(self.call("/api/users/profile/"), 200)
        self.assertFalse(UserProfile.objects.filter(user=self.target).exists())

    def test_only_the_viewed_customer_is_listed(self) -> None:
        payload = {"user_id": self.target.pk, "session_id": str(self.row.pk), "timestamp": int(time.time())}
        raw = json.dumps(payload).encode()
        response = self.client.post(
            "/api/users/customers/",
            raw,
            content_type="application/json",
            **hmac_headers("POST", "/api/users/customers/", raw, portal_id=self.portal_id),
        )
        self.assertEqual([c["id"] for c in response.json()["results"]], [self.customer.pk])

    def test_writes_and_other_customers_are_refused_and_recorded(self) -> None:
        refused = [
            ("/api/users/change-password/", {"current_password": PASSWORD, "new_password": "N3w-Horse-Battery"}, "PUT"),
            ("/api/users/profile/", {"first_name": "Mallory"}, "PUT"),
            ("/api/gdpr/cookie-consent/", {"cookie_id": "c", "status": "accepted_all"}, "POST"),
            ("/api/gdpr/data-export/", {}, "POST"),
            ("/api/tickets/create/", {"customer_id": self.customer.pk, "title": "t"}, "POST"),
            ("/api/customers/details/", {"customer_id": self.other_customer.pk}, "POST"),
            ("/api/customers/details/", {"customer_id": f"{self.customer.pk}.0"}, "POST"),
            ("/api/not-a-route/", {}, "POST"),
        ]
        for path, body, method in refused:
            with self.subTest(path=path, body=body):
                self.assertEqual(self.call(path, body, method), 403)
        self.target.refresh_from_db()
        self.assertTrue(self.target.check_password(PASSWORD))
        self.assertEqual(self.target.first_name, "")
        self.assertGreaterEqual(AuditEvent.objects.filter(action="customer_view_denied").count(), len(refused))

    def test_every_api_route_outside_the_allowlist_is_refused(self) -> None:
        from django.test import RequestFactory  # noqa: PLC0415

        from apps.common.middleware import _is_auth_exempt  # noqa: PLC0415

        allowed = set(customer_view_policy.READS) | set(customer_view_policy.CONTROLS)
        for name, path in _api_routes():
            if name in allowed:
                continue
            # Public endpoints (health, catalogs, token exchange) never read a signed identity, so a
            # customer view cannot act as the customer through them; they are outside the binding.
            if _is_auth_exempt(RequestFactory().post(path)):
                continue
            with self.subTest(route=name):
                self.assertEqual(self.call(path), 403)

    def test_validation_needs_no_credential_of_the_customer(self) -> None:
        payload = {"user_id": self.target.pk, "session_id": str(self.row.pk), "timestamp": int(time.time())}
        raw = json.dumps(payload).encode()
        response = self.client.post(
            "/api/users/session/validate/",
            raw,
            content_type="application/json",
            **hmac_headers("POST", "/api/users/session/validate/", raw, portal_id=self.portal_id),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertNotIn("session_auth_hash", response.json())

    def test_the_view_ends_when_its_authority_does(self) -> None:
        breakers = {
            "staff signed out": lambda: Session.objects.all().delete(),
            "staff role changed": lambda: User.objects.filter(pk=self.staff.pk).update(staff_role="billing"),
            "staff credential changed": lambda: User.objects.filter(pk=self.staff.pk).update(password="changed"),
            "membership ended": lambda: CustomerMembership.objects.filter(customer=self.customer).update(
                is_active=False
            ),
            "customer suspended": lambda: Customer.objects.filter(pk=self.customer.pk).update(status="suspended"),
            "customer deleted": lambda: Customer.objects.filter(pk=self.customer.pk).update(deleted_at=timezone.now()),
            "target credential changed": lambda: User.objects.filter(pk=self.target.pk).update(password="changed"),
        }
        for label, break_it in breakers.items():
            with self.subTest(label):
                sid = transaction_savepoint()
                break_it()
                self.assertEqual(self.call("/api/users/customers/"), 401, label)
                transaction_rollback(sid)
        with override_settings(CUSTOMER_VIEW_ENABLED=False):
            self.assertEqual(self.call("/api/users/customers/"), 401)
        self.row.refresh_from_db()
        self.assertIsNotNone(self.row.revoked_at)
        self.assertTrue(AuditEvent.objects.filter(action="customer_view_ended").exists())

    def test_leaving_ends_only_the_scoped_session(self) -> None:
        own = portal_sessions.open_session(self.target)  # the customer's own browser session
        self.assertEqual(self.call("/api/users/session/end/"), 200)
        self.assertEqual(self.call("/api/users/customers/"), 401)
        self.assertIsNotNone(portal_sessions.resolve(str(own.pk), self.target.pk, interactive=False))
        self.assertTrue(AuditEvent.objects.filter(action="customer_view_ended").exists())

    def test_the_customer_s_own_logout_does_not_end_the_view(self) -> None:
        own = portal_sessions.open_session(self.target)
        portal_sessions.end(own, portal_sessions.REASON_LOGOUT)
        self.assertEqual(self.call("/api/users/customers/"), 200)

    def test_the_view_is_short_and_background_calls_never_extend_it(self) -> None:
        stale = timezone.now() - timedelta(minutes=5)
        PortalSession.objects.filter(pk=self.row.pk).update(
            last_seen_at=stale, idle_deadline=stale + timedelta(minutes=10)
        )
        self.call("/api/users/customers/", {"interactive": False})
        self.row.refresh_from_db()
        self.assertEqual(self.row.last_seen_at, stale)
        before = timezone.now()
        self.call("/api/users/customers/", {"interactive": True})
        self.row.refresh_from_db()
        self.assertGreaterEqual(self.row.last_seen_at, before)  # the touch happened
        self.assertGreater(self.row.idle_deadline, stale + timedelta(minutes=10))  # and extended idle
        self.assertLessEqual(self.row.idle_deadline - self.row.last_seen_at, session_policy.TIERS["customer_view"].idle)

    def test_the_sweep_ends_unusable_views_and_voids_stale_grants(self) -> None:
        stale = CustomerViewGrant.objects.create(
            code_digest="0" * 64,
            staff=self.staff,
            target=self.target,
            customer=self.customer,
            staff_session_key="k",
            staff_credential_snapshot="s",
            target_credential_snapshot="t",
            reason_category="support_request",
            reason="A reason long enough",
            expires_at=timezone.now() - timedelta(seconds=1),
        )
        Session.objects.all().delete()  # the staff console session ended
        self.assertEqual(customer_view.sweep(), 1)
        stale.refresh_from_db()
        self.assertIsNotNone(stale.voided_at)


def _sample(converter: object) -> str:
    name = type(converter).__name__
    return {"IntConverter": "1", "UUIDConverter": str(uuid.uuid4()), "SlugConverter": "x"}.get(name, "x")


def _api_routes() -> list[tuple[str, str]]:
    """Every named route under /api/, with a concrete path for it."""
    routes: list[tuple[str, str]] = []

    def walk(patterns: list[object], namespace: str) -> None:
        for pattern in patterns:
            if isinstance(pattern, URLResolver):
                inner = pattern.namespace or ""
                walk(pattern.url_patterns, f"{namespace}:{inner}" if namespace and inner else inner or namespace)
            elif isinstance(pattern, URLPattern) and pattern.name and namespace.startswith("api"):
                name = f"{namespace}:{pattern.name}"
                converters = getattr(pattern.pattern, "converters", {})
                kwargs = {key: _sample(value) for key, value in converters.items()}
                if not converters:
                    kwargs = {group: "1" for group in pattern.pattern.regex.groupindex if group != "format"}
                try:
                    path = reverse(name, kwargs=kwargs)
                except Exception:  # noqa: S112  # a DRF format-suffix twin of a route already listed
                    continue
                routes.append((name, path))

    walk(get_resolver().url_patterns, "")
    assert len(routes) > 50, "the walk found too few API routes to prove anything"
    return routes


class InventoryTests(TestCase):
    def test_every_allowed_route_exists(self) -> None:
        names = {name for name, _path in _api_routes()}
        for name in (*customer_view_policy.READS, *customer_view_policy.CONTROLS):
            with self.subTest(route=name):
                self.assertIn(name, names)

    def test_patch_is_unused(self) -> None:
        # Every allowlisted method set is a read set; a write method on any allowed route is refused.
        for name, methods in customer_view_policy.READS.items():
            with self.subTest(route=name):
                self.assertTrue(methods <= {"GET", "HEAD", "POST"})
        self.assertNotIn("PUT", customer_view_policy.READS["api:customer_profile"])
