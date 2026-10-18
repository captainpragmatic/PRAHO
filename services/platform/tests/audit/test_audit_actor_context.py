"""The audit actor context: who is acting, carried from the entry point to the receivers."""

from __future__ import annotations

import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from pathlib import Path
from typing import Any
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser
from django.db import transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.urls import path
from django_q.signals import post_execute, pre_execute
from django_q.tasks import async_task
from rest_framework.decorators import api_view
from rest_framework.request import Request

from apps.audit.actor_context import (
    acting_as,
    bind_current_actor,
    current_actor,
    record_request_actor,
)
from apps.audit.middleware import AuditActorMiddleware
from apps.audit.models import _mutation_allowed, audit_mutation_allowed
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.users.models import APIToken, User
from tests.helpers.fsm_helpers import force_status

SETTINGS_DIR = Path(__file__).resolve().parents[2] / "config" / "settings"
AUTH_MIDDLEWARE = "django.contrib.auth.middleware.AuthenticationMiddleware"
ACTOR_MIDDLEWARE = "apps.audit.middleware.AuditActorMiddleware"

_seen_by_task: list[Any] = []


def record_actor_in_task() -> str:
    """Module-level so Django-Q can import it."""
    _seen_by_task.append(current_actor())
    return "ok"


@api_view(["GET"])
def whoami_view(request: Request) -> JsonResponse:
    actor = current_actor()
    return JsonResponse({"actor": actor.pk if actor else None})


urlpatterns = [path("whoami/", whoami_view)]


class ActingAsTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.admin = User.objects.create_user(email="actor-admin@example.com", password="pw", staff_role="admin")
        cls.other = User.objects.create_user(email="actor-other@example.com", password="pw", staff_role="support")

    def test_no_actor_by_default(self) -> None:
        self.assertIsNone(current_actor())

    def test_acting_as_binds_and_resets(self) -> None:
        with acting_as(self.admin):
            self.assertEqual(current_actor(), self.admin)
        self.assertIsNone(current_actor())

    def test_reset_happens_when_the_block_raises(self) -> None:
        with self.assertRaises(RuntimeError), acting_as(self.admin):
            raise RuntimeError("boom")
        self.assertIsNone(current_actor())

    def test_nested_contexts_restore_the_outer_actor(self) -> None:
        with acting_as(self.admin):
            with acting_as(self.other):
                self.assertEqual(current_actor(), self.other)
            self.assertEqual(current_actor(), self.admin)
            with acting_as(None):
                self.assertIsNone(current_actor())
            self.assertEqual(current_actor(), self.admin)

    def test_only_authenticated_users_or_none_are_accepted(self) -> None:
        for bad in (AnonymousUser(), "admin", User(email="unsaved@example.com")):
            with self.subTest(bad=repr(bad)), self.assertRaises(ValueError), acting_as(bad):
                pass  # pragma: no cover

    def test_a_reused_thread_does_not_inherit_the_actor(self) -> None:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with acting_as(self.admin):
                self.assertIsNone(pool.submit(current_actor).result())
            # The same worker thread again, after the actor is gone.
            self.assertIsNone(pool.submit(current_actor).result())

    def test_a_copied_context_carries_the_submitters_actor(self) -> None:
        with ThreadPoolExecutor(max_workers=2) as pool, acting_as(self.admin):
            futures = [pool.submit(copy_context().run, current_actor) for _ in range(4)]
            self.assertEqual({f.result() for f in futures}, {self.admin})

    def test_concurrent_async_tasks_keep_their_own_actor(self) -> None:
        async def work(user: User, delay: float) -> Any:
            with acting_as(user):
                await asyncio.sleep(delay)
                return current_actor()

        async def run() -> list[Any]:
            return list(await asyncio.gather(work(self.admin, 0.02), work(self.other, 0.01)))

        self.assertEqual(asyncio.run(run()), [self.admin, self.other])

    def test_the_mutation_permission_is_per_context(self) -> None:
        with audit_mutation_allowed("test"):
            self.assertTrue(_mutation_allowed())
            with ThreadPoolExecutor(max_workers=1) as pool:
                self.assertFalse(pool.submit(_mutation_allowed).result())

            async def check() -> bool:
                return _mutation_allowed()

            async def run() -> list[bool]:
                async def in_task() -> bool:
                    with audit_mutation_allowed("inner"):
                        await asyncio.sleep(0)
                    return _mutation_allowed()

                return [await asyncio.create_task(in_task()), await check()]

            self.assertEqual(asyncio.run(run()), [True, True])
        self.assertFalse(_mutation_allowed())


class OnCommitBindingTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.admin = User.objects.create_user(email="commit-admin@example.com", password="pw", staff_role="admin")

    def test_on_commit_audit_keeps_the_scheduling_actor(self) -> None:
        seen: list[Any] = []
        with acting_as(self.admin):
            callback = bind_current_actor(lambda: seen.append(current_actor()))
        # Run after the request context has gone, as a real on_commit callback does.
        self.assertIsNone(current_actor())
        callback()
        self.assertEqual(seen, [self.admin])
        self.assertIsNone(current_actor())

    def test_the_binding_carries_the_actor_and_nothing_else(self) -> None:
        seen: list[bool] = []
        with acting_as(self.admin), audit_mutation_allowed("scheduling-time permission"):
            callback = bind_current_actor(lambda: seen.append(_mutation_allowed()))
        callback()
        self.assertEqual(seen, [False])

    def test_a_real_on_commit_callback_is_bound(self) -> None:
        seen: list[Any] = []
        with self.captureOnCommitCallbacks(execute=False) as callbacks, acting_as(self.admin):
            transaction.on_commit(bind_current_actor(lambda: seen.append(current_actor())))
        for callback in callbacks:
            callback()
        self.assertEqual(seen, [self.admin])


class OrderStatusOnCommitActorTests(TestCase):
    """The order status handler runs on commit, after the request has ended, and must still know who acted."""

    def test_the_status_handler_run_on_commit_sees_the_staff_member_who_changed_the_order(self) -> None:
        staff = User.objects.create_user(email="order-staff@example.com", password="pw", staff_role="admin")
        currency, _created = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        customer = Customer.objects.create(name="OnCommit SRL", customer_type="company", status="active")
        order = Order.objects.create(
            customer=customer,
            currency=currency,
            customer_email="oncommit@example.com",
            customer_name=customer.name,
            payment_method="bank_transfer",
            subtotal_cents=1000,
            tax_cents=210,
            total_cents=1210,
            billing_address={},
        )
        seen: list[Any] = []

        with patch("apps.orders.signals._handle_order_status_change", lambda *args: seen.append(current_actor())):
            with self.captureOnCommitCallbacks(execute=False) as callbacks, acting_as(staff):
                force_status(order, "awaiting_payment")

            self.assertIsNone(current_actor())  # the request-time binding is gone
            for callback in callbacks:
                callback()
        self.assertEqual(seen, [staff])


class DjangoQTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.admin = User.objects.create_user(email="q-admin@example.com", password="pw", staff_role="admin")

    def test_pre_execute_clears_and_post_execute_restores_in_one_context(self) -> None:
        with acting_as(self.admin):
            pre_execute.send(sender="django_q", func=None, task={})
            self.assertIsNone(current_actor())
            post_execute.send(sender="django_q", task={})
            self.assertEqual(current_actor(), self.admin)

    def test_post_execute_alone_changes_nothing(self) -> None:
        with acting_as(self.admin):
            post_execute.send(sender="django_q", task={})
            self.assertEqual(current_actor(), self.admin)

    def test_actor_context_never_leaks_into_a_task(self) -> None:
        _seen_by_task.clear()
        with acting_as(self.admin):
            async_task("tests.audit.test_audit_actor_context.record_actor_in_task", sync=True)
            self.assertEqual(current_actor(), self.admin)
        self.assertEqual(_seen_by_task, [None])


class MiddlewareTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.admin = User.objects.create_user(email="mw-admin@example.com", password="pw", staff_role="admin")

    def _run(self, user: Any, view: Any = None) -> tuple[HttpResponse, list[Any]]:
        seen: list[Any] = []

        def get_response(request: HttpRequest) -> HttpResponse:
            seen.append(current_actor())
            if view:
                view(request)
            return HttpResponse("ok")

        request = RequestFactory().get("/")
        request.user = user
        response = AuditActorMiddleware(get_response)(request)
        return response, seen

    def test_the_request_user_is_the_actor_during_the_request_only(self) -> None:
        _, seen = self._run(self.admin)
        self.assertEqual(seen, [self.admin])
        self.assertIsNone(current_actor())

    def test_an_anonymous_request_has_no_actor(self) -> None:
        _, seen = self._run(AnonymousUser())
        self.assertEqual(seen, [None])

    def test_the_actor_is_reset_when_the_view_raises(self) -> None:
        def boom(request: HttpRequest) -> None:
            raise RuntimeError("view failed")

        with self.assertRaises(RuntimeError):
            self._run(self.admin, boom)
        self.assertIsNone(current_actor())

    def test_a_user_resolved_after_the_middleware_is_honoured(self) -> None:
        seen: list[Any] = []

        def get_response(request: HttpRequest) -> HttpResponse:
            record_request_actor(request, self.admin)  # a signed Portal call resolving its user
            seen.append(current_actor())
            return HttpResponse("ok")

        request = RequestFactory().get("/")
        request.user = AnonymousUser()
        AuditActorMiddleware(get_response)(request)
        self.assertEqual(seen, [self.admin])
        self.assertIsNone(current_actor())

    def test_the_async_path_binds_and_resets(self) -> None:
        seen: list[Any] = []

        async def get_response(request: HttpRequest) -> HttpResponse:
            seen.append(current_actor())
            return HttpResponse("ok")

        request = RequestFactory().get("/")
        request.user = self.admin
        middleware: Any = AuditActorMiddleware(get_response)
        asyncio.run(middleware(request))
        self.assertEqual(seen, [self.admin])
        self.assertIsNone(current_actor())


class MiddlewareListsTests(SimpleTestCase):
    def test_every_platform_middleware_list_has_the_actor_middleware_after_authentication(self) -> None:
        for name in ("base", "staging", "prod", "test"):
            with self.subTest(settings=name):
                source = (SETTINGS_DIR / f"{name}.py").read_text()
                self.assertRegex(
                    source,
                    re.compile(
                        rf'"{re.escape(AUTH_MIDDLEWARE)}",\s*\n\s*"{re.escape(ACTOR_MIDDLEWARE)}"',
                    ),
                )


@override_settings(ROOT_URLCONF="tests.audit.test_audit_actor_context")
class DrfIdentityTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.user = User.objects.create_user(email="api-user@example.com", password="pw")
        cls.raw_key = APIToken.generate_key()
        APIToken.objects.create(
            user=cls.user, key_hash=APIToken.hash_key(cls.raw_key), key_prefix=cls.raw_key[:8], name="actor test"
        )

    def test_a_token_authenticated_api_view_sees_the_token_user_as_actor(self) -> None:
        response = self.client.get("/whoami/", HTTP_AUTHORIZATION=f"Bearer {self.raw_key}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"actor": self.user.pk})
        self.assertIsNone(current_actor())
