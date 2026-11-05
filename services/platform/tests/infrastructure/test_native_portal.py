"""Native UI uses real signed login/session policy and private paired listeners."""

import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import requests
from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.core.management import call_command
from django.test import Client, SimpleTestCase, TestCase, override_settings

from apps.customers.models import Customer
from apps.infrastructure.native_portal import NativeUIPair, child_environment, validate_ui
from apps.users.models import CustomerMembership, PortalSession, User
from tests.helpers.hmac import hmac_headers
from tests.helpers.native_authority import make_authority
from tests.helpers.native_portal import PROFILE_KEYS, load_profile, runner_module


class NativePortalAuthorityTests(SimpleTestCase):
    def test_failed_authority_publication_closes_both_owned_sockets_even_for_interrupt(self):
        for failure in (OSError("fixture write failed"), KeyboardInterrupt("fixture canceled")):
            with self.subTest(failure=type(failure).__name__), TemporaryDirectory() as directory:
                authority = make_authority(Path(directory))
                pair = NativeUIPair(authority, Path(directory) / "ui.json")
                listeners: list[socket.socket] = []

                def refuse_publication(*args, listeners=listeners, pair=pair, failure=failure):
                    listeners.extend(pair.listeners.values())
                    raise failure

                with (
                    patch("apps.infrastructure.native_portal._write", side_effect=refuse_publication),
                    self.assertRaises(type(failure)),
                ):
                    pair.__enter__()
                self.assertEqual(len(listeners), 2)
                self.assertTrue(all(listener.fileno() == -1 for listener in listeners))
                self.assertEqual(pair.listeners, {})
                self.assertFalse(pair.path.exists())

    def test_portal_profile_refuses_tampered_coordinator_authority_before_creating_session_database(self):
        root = Path(__file__).resolve().parents[4]
        with TemporaryDirectory() as directory:
            authority = make_authority(Path(directory))
            path = Path(directory) / "ui.json"
            with NativeUIPair(authority, path) as pair:
                environment = child_environment(pair, "portal", root, dict(os.environ))
                changed = json.loads(path.read_bytes())
                changed["run"] = "00000000-0000-0000-0000-000000000000"
                path.write_text(json.dumps(changed))
                result = subprocess.run(  # noqa: S603 -- Actual Portal settings, no business DB/provider authority.
                    [sys.executable, "-c", "import django; django.setup()"],
                    cwd=root / "services/portal",
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("native Portal UI authority", result.stderr)
                self.assertFalse(path.with_name(path.name + ".portal.sqlite3").exists())

    def test_fresh_actual_platform_startup_enforces_registry_isolation_and_has_no_fake_stripe_key(self):
        root = Path(__file__).resolve().parents[4]
        with TemporaryDirectory() as directory:
            authority = make_authority(Path(directory))
            path = Path(directory) / "ui.json"
            with NativeUIPair(authority, path) as pair:
                environment = child_environment(
                    pair,
                    "platform",
                    root,
                    {
                        **dict(os.environ),
                        "DB_HOST": "127.0.0.1",
                        "DB_PORT": "1",
                        "DB_NAME": "praho_native_ui_test",
                        "DB_USER": "native-fixture",
                        "DB_PASSWORD": "fixture-only",
                    },
                )
                code = (
                    "import django; django.setup(); from django.conf import settings; "
                    "from config.settings import base; "
                    "assert settings.STRIPE_SECRET_KEY is None; assert settings.STRIPE_PUBLISHABLE_KEY is None; "
                    "assert settings.TESTING is False; "
                    "assert settings.CACHES['default']['BACKEND'].endswith('DatabaseCache'); "
                    "assert settings.REST_FRAMEWORK == base.REST_FRAMEWORK; "
                    "assert len(settings.REST_FRAMEWORK['DEFAULT_THROTTLE_CLASSES']) == 4; "
                    "assert settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']; "
                    "assert settings.REST_FRAMEWORK['DEFAULT_THROTTLE_CLASSES'] "
                    "is not base.REST_FRAMEWORK['DEFAULT_THROTTLE_CLASSES']; "
                    "assert settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES'] "
                    "is not base.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']; "
                    "print('Actual native Platform startup qualified')"
                )
                result = subprocess.run(  # noqa: S603 -- Actual profile/app startup, synthetic closed-port DB authority; no queries expected.
                    [sys.executable, "-c", code],
                    cwd=root / "services/platform",
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("startup qualified", result.stdout)

    def test_foreign_expired_external_and_unprivate_authorities_fail_closed(self):
        with TemporaryDirectory() as directory:
            authority = make_authority(Path(directory))
            path = Path(directory) / "ui.json"
            with NativeUIPair(authority, path):
                original = path.read_bytes()
                for changed in (
                    {"run": "00000000-0000-0000-0000-000000000000"},
                    {"expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()},
                    {"host": "external.invalid"},
                    {"platform_port": True},
                    {"portal_port": json.loads(original)["platform_port"]},
                ):
                    with self.subTest(changed=changed):
                        path.write_text(json.dumps({**json.loads(original), **changed}))
                        with self.assertRaises(ValueError):
                            validate_ui(authority, path)
                        path.write_bytes(original)
                path.chmod(0o644)
                with self.assertRaises(ValueError):
                    validate_ui(authority, path)
                path.chmod(0o600)
                link = path.with_name("ui-link.json")
                link.symlink_to(path)
                with self.assertRaises(OSError):
                    validate_ui(authority, link)

    def test_guard_rejects_real_elapsed_lifetime_before_calling_application(self):
        runner = runner_module()
        with TemporaryDirectory() as directory:
            authority = make_authority(Path(directory))
            path = Path(directory) / "ui.json"
            with NativeUIPair(authority, path, lifetime_seconds=1) as pair:
                calls = []

                def application(environ, start_response):
                    calls.append(environ)
                    start_response("200 OK", [("Content-Type", "text/plain")])
                    return [b"current"]

                guard = runner.AuthorityGuard(application, path, hashlib.sha256(path.read_bytes()).hexdigest())
                server = runner.inherited_server(pair.listeners["platform"].dup(), guard)
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                try:
                    with requests.Session() as browser:
                        browser.trust_env = False
                        url = f"http://127.0.0.1:{pair.value['platform_port']}/"
                        self.assertEqual(browser.get(url, timeout=3).status_code, 200)
                        threading.Event().wait(1.1)
                        self.assertEqual(browser.get(url, timeout=3).status_code, 503)
                        self.assertEqual(len(calls), 1)
                finally:
                    server.shutdown()
                    server.server_close()
                    worker.join(timeout=5)

    def test_pair_reserves_both_ports_and_binds_private_untampered_vm_authority(self):
        with TemporaryDirectory() as directory:
            authority = make_authority(Path(directory))
            path = Path(directory) / "ui.json"
            with NativeUIPair(authority, path) as pair:
                value = validate_ui(authority, path)
                self.assertNotEqual(value["platform_port"], value["portal_port"])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertNotIn(authority.key.decode(), path.read_text())
                for listener in pair.listeners.values():
                    with socket.socket() as contender, self.assertRaises(OSError):
                        contender.bind(listener.getsockname())
                original = path.read_bytes()
                value["secret"] = "replaced-secret" * 10
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    validate_ui(authority, path)
                path.write_bytes(original)
            with self.assertRaises(ValueError):
                validate_ui(authority, path)


class NativePortalAuthenticationTests(TestCase):
    def test_native_ui_signed_login_opens_real_bound_session_and_rejects_unsigned_replay(self):
        password = "Native-Portal-Owner-Passphrase-776!"
        customer = Customer.objects.create(name="Native Portal owner", customer_type="company", status="active")
        hasher = PBKDF2PasswordHasher()
        user = User(email="native-portal@example.invalid", password=hasher.encode(password, hasher.salt()))
        user.save()
        CustomerMembership.objects.create(user=user, customer=customer, role="owner", is_primary=True)
        with TemporaryDirectory() as directory:
            authority = make_authority(Path(directory))
            path = Path(directory) / "ui.json"
            with (
                NativeUIPair(authority, path) as pair,
                patch.dict(
                    os.environ,
                    {
                        "PRAHO_NATIVE_LAB": "1",
                        "DB_NAME": "praho_native_ui_test",
                        "NATIVE_VM_MANIFEST": str(authority.path),
                        "PRAHO_NATIVE_UI_AUTHORITY": str(path),
                    },
                ),
            ):
                os.environ.pop("PRAHO_NATIVE_SMTP_MANIFEST", None)
                profile = load_profile(authority, path)
                with override_settings(**{key: profile[key] for key in PROFILE_KEYS}):
                    call_command("createcachetable", verbosity=0)
                    client = Client(enforce_csrf_checks=True)
                    route = "/api/users/login/"
                    body = json.dumps(
                        {"email": user.email, "password": password, "client_user_agent": "Native UI test"}
                    ).encode()
                    unsigned_response = client.post(route, body, content_type="application/json", HTTP_HOST="127.0.0.1")
                    headers = hmac_headers(
                        "POST", route, body, portal_id=profile["NATIVE_UI_PORTAL_ID"], secret=pair.value["secret"]
                    )
                    request_headers = {
                        key.removeprefix("HTTP_").replace("_", "-"): value for key, value in headers.items()
                    }
                    response = client.post(
                        route, body, content_type="application/json", HTTP_HOST="127.0.0.1", headers=request_headers
                    )
                    self.assertEqual(response.status_code, 200, response.content)
                    self.assertEqual(unsigned_response.status_code, 401)
                    payload = response.json()
                    session = PortalSession.objects.get(pk=payload["session_id"])
                    self.assertEqual(session.user_id, user.pk)
                    self.assertTrue(session.ua_digest)
                    self.assertTrue(payload["step_up_at"])
                    self.assertEqual(
                        client.post(
                            route, body, content_type="application/json", HTTP_HOST="127.0.0.1", headers=request_headers
                        ).status_code,
                        401,
                    )
