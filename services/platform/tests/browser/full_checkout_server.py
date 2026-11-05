"""Explicit test-only Platform process; real WSGI app, synthetic Stripe boundary.

No routes here are installed in production URL configurations. The provider route
accepts one test token, one registered synthetic client secret and one exact Portal
origin. It cannot choose the amount/currency/customer or bypass Platform auth.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import threading
import time
from collections.abc import Callable, Iterable
from contextlib import ExitStack
from pathlib import Path
from socketserver import ThreadingMixIn
from types import SimpleNamespace
from typing import Any, Never
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import requests

FIXTURE_KEY = "sk_test_hosting_browser_only"
WEBHOOK_KEY = "whsec_hosting_browser_only"
MAX_PROVIDER_BODY = 1024
TOKEN_LENGTH = 32


class ThreadedServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class QuietHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 -- stdlib signature.
        pass


def main() -> None:  # noqa: C901, PLR0915 -- One guarded test process owns SDK patches and WSGI lifetime.
    assert os.environ.get("HOSTING_CHECKOUT_FULL") == "1"
    assert os.environ.get("DB_NAME") == "test_hosting_browser"
    assert os.environ.get("DB_HOST") in {"localhost", "127.0.0.1"}
    import django  # noqa: PLC0415 -- Guards precede Django initialization.

    django.setup()
    import stripe  # noqa: PLC0415
    from django.core.handlers.wsgi import WSGIHandler  # noqa: PLC0415
    from django.db import connection  # noqa: PLC0415
    from django.urls import reverse  # noqa: PLC0415

    directory = Path(os.environ["HOSTING_CHECKOUT_DIRECTORY"])
    token = os.environ["HOSTING_CHECKOUT_TOKEN"]
    assert len(token) == TOKEN_LENGTH
    journal: dict[str, list[dict[str, Any]]] = {"sdk": [], "requests": [], "webhooks": []}
    intents: dict[str, dict[str, Any]] = {}
    lock = threading.RLock()
    base_url = ""

    def record(kind: str, data: dict[str, Any]) -> None:
        with lock:
            journal[kind].append(data)
            pending = directory / "journal.json.pending"
            pending.write_text(json.dumps(journal))
            pending.replace(directory / "journal.json")

    def account(*args: Any, **kwargs: Any) -> SimpleNamespace:
        assert stripe.api_key == FIXTURE_KEY
        assert not connection.in_atomic_block
        record("sdk", {"action": "account", "in_atomic": connection.in_atomic_block})
        return SimpleNamespace(id="acct_hosting_browser")

    def create(**kwargs: Any) -> SimpleNamespace:
        from apps.billing.plan_change_payment_models import PlanChangePaymentAttempt  # noqa: PLC0415

        assert stripe.api_key == FIXTURE_KEY
        assert not connection.in_atomic_block
        attempt = PlanChangePaymentAttempt.objects.get(idempotency_key=kwargs["idempotency_key"])
        assert attempt.state == "submitting" and attempt.submission_count == 1
        assert attempt.payment_id is not None
        assert "off_session" not in kwargs and kwargs["confirm"] is False
        record("sdk", {"action": "create", "in_atomic": False, "payload": kwargs, "attempt": str(attempt.pk)})
        with lock:
            if kwargs["idempotency_key"] not in intents:
                intents[kwargs["idempotency_key"]] = {
                    **kwargs,
                    "id": f"pi_hosting_browser_{len(intents) + 1}",
                    "client_secret": f"pi_hosting_browser_{len(intents) + 1}_secret_fixture",
                    "status": "requires_payment_method",
                    "customer": None,
                    "amount_received": 0,
                }
            return SimpleNamespace(**intents[kwargs["idempotency_key"]])

    def retrieve(identifier: str, **kwargs: Any) -> SimpleNamespace:
        assert not connection.in_atomic_block
        return SimpleNamespace(**next(item for item in intents.values() if item["id"] == identifier))

    def cancel(identifier: str, **kwargs: Any) -> SimpleNamespace:
        assert not connection.in_atomic_block
        item = next(item for item in intents.values() if item["id"] == identifier)
        item["status"] = "canceled"
        return SimpleNamespace(**item)

    def forbidden_network(*args: Any, **kwargs: Any) -> Never:
        raise AssertionError("Unhandled external Stripe HTTP is forbidden in full checkout acceptance")

    original_send = requests.Session.send

    def owned_http(session: requests.Session, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        allowed = {base_url}
        origin_path = directory / "portal-origin.json"
        if origin_path.exists():
            allowed.add(json.loads(origin_path.read_text())["origin"])
        parsed = urlsplit(request.url or "")
        if f"{parsed.scheme}://{parsed.netloc}" not in allowed:
            raise AssertionError("The financial test server may contact only its two owned loopback origins")
        return original_send(session, request, **kwargs)

    def forbidden_process(*args: Any, **kwargs: Any) -> Never:
        raise AssertionError("The checkout financial server must not launch native commands or external workers")

    application = WSGIHandler()

    def answer(
        start_response: Callable[..., Any], status: str, body: dict[str, Any], *, origin: str | None = None
    ) -> list[bytes]:
        encoded = json.dumps(body).encode()
        headers = [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(encoded))),
            ("Cache-Control", "no-store"),
        ]
        if origin:
            headers.extend(
                [
                    ("Access-Control-Allow-Origin", origin),
                    ("Access-Control-Allow-Methods", "POST, OPTIONS"),
                    ("Access-Control-Allow-Headers", "Content-Type"),
                ]
            )
        start_response(status, headers)
        return [encoded]

    def wsgi(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:  # noqa: PLR0911 -- Closed synthetic provider admission rejects independently.
        path = environ.get("PATH_INFO", "")
        if path == "/__hosting_checkout__/confirm":
            origin_path = directory / "portal-origin.json"
            origin = json.loads(origin_path.read_text())["origin"] if origin_path.exists() else ""
            if (
                parse_qs(environ.get("QUERY_STRING", "")) != {"token": [token]}
                or not origin
                or environ.get("HTTP_ORIGIN") != origin
            ):
                return answer(start_response, "403 Forbidden", {"error": "Synthetic provider authority differs"})
            if environ["REQUEST_METHOD"] == "OPTIONS":
                return answer(start_response, "200 OK", {}, origin=origin)
            if environ["REQUEST_METHOD"] != "POST":
                return answer(start_response, "405 Method Not Allowed", {}, origin=origin)
            length = int(environ.get("CONTENT_LENGTH") or 0)
            if not 0 < length <= MAX_PROVIDER_BODY:
                return answer(start_response, "400 Bad Request", {}, origin=origin)
            data = json.loads(environ["wsgi.input"].read(length))
            if set(data) != {"client_secret"}:
                return answer(start_response, "400 Bad Request", {}, origin=origin)
            item = next((value for value in intents.values() if value["client_secret"] == data["client_secret"]), None)
            if item is None:
                return answer(start_response, "403 Forbidden", {}, origin=origin)
            item.update(status="succeeded", amount_received=item["amount"])
            event = {
                "id": "evt_" + item["id"],
                "type": "payment_intent.succeeded",
                "api_version": "2023-10-16",
                "data": {
                    "object": {
                        key: item[key]
                        for key in (
                            "id",
                            "status",
                            "amount",
                            "amount_received",
                            "currency",
                            "metadata",
                            "customer",
                            "client_secret",
                        )
                    }
                },
            }
            raw = json.dumps(event).encode()
            stamp = str(int(time.time()))
            digest = hmac.new(WEBHOOK_KEY.encode(), stamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
            response = requests.post(
                base_url + reverse("integrations:stripe_webhook"),
                data=raw,
                headers={"Content-Type": "application/json", "Stripe-Signature": f"t={stamp},v1={digest}"},
                timeout=30,
            )
            record("webhooks", {"status": response.status_code, "body": response.json()})
            return answer(
                start_response,
                "200 OK",
                {} if response.ok else {"error": {"message": "Synthetic webhook refused"}},
                origin=origin,
            )
        if path.startswith("/api/"):
            length = int(environ.get("CONTENT_LENGTH") or 0)
            raw = environ["wsgi.input"].read(length) if length else b""
            environ["wsgi.input"] = io.BytesIO(raw)
            data = json.loads(raw) if raw else {}

            def observed_start(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> Any:
                record(
                    "requests",
                    {
                        "path": path,
                        "status": status,
                        "has_signature": bool(environ.get("HTTP_X_SIGNATURE")),
                        "session_id": data.get("session_id"),
                        "step_up_at": data.get("step_up_at"),
                    },
                )
                return start_response(status, headers, exc_info)

            return application(environ, observed_start)
        return application(environ, start_response)

    with ExitStack() as stack:
        for target, side_effect in (
            ("stripe.Account.retrieve", account),
            ("stripe.PaymentIntent.create", create),
            ("stripe.PaymentIntent.retrieve", retrieve),
            ("stripe.PaymentIntent.cancel", cancel),
            ("stripe.RequestsClient.request", forbidden_network),
            ("subprocess.Popen", forbidden_process),
        ):
            stack.enter_context(patch(target, side_effect=side_effect))
        stack.enter_context(patch.object(requests.Session, "send", owned_http))
        server = make_server("127.0.0.1", 0, wsgi, server_class=ThreadedServer, handler_class=QuietHandler)
        base_url = f"http://127.0.0.1:{server.server_port}"
        ready = directory / "platform-ready.json.pending"
        ready.write_text(json.dumps({"url": base_url, "pid": os.getpid()}))
        ready.replace(directory / "platform-ready.json")
        server.serve_forever()


if __name__ == "__main__":
    main()
