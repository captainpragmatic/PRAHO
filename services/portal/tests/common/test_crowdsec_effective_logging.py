"""Exercise actual deployed settings and writer health in clean Portal processes."""

from __future__ import annotations

import json
import os
import secrets
import stat
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TypedDict

from django.test import SimpleTestCase

PORTAL = Path(__file__).resolve().parents[2]


class RecordingResult(TypedDict):
    recorded: bool
    enabled: bool
    health: dict[str, bool]


SCRIPT = """
import json, logging, os, sys
from pathlib import Path
import django
django.setup()
from django.conf import settings
from django.test import RequestFactory
from apps.common import auth_events

path = Path(settings.CROWDSEC_AUTH_LOG_PATH)
mode = sys.argv[1]
request = RequestFactory().post('/login/', {'email': 'PrivatePerson@example.test', 'password': 'never-record-this-password'}, REMOTE_ADDR='127.0.0.1', HTTP_X_FORWARDED_FOR='198.51.100.29')
request.session = {}
if mode not in {'normal', 'disabled'}:
    assert auth_events.emit_auth_event(request, 'auth_failure', 'credentials') is True
    assert auth_events.recording_health()['auth_events'] is True
    handler = auth_events.EVENT_LOGGER.handlers[0]
    if mode == 'missing':
        auth_events.EVENT_LOGGER.handlers = []
        auth_events.EVENT_LOGGER.propagate = True
    elif mode == 'logger_disabled':
        auth_events.EVENT_LOGGER.disabled = True
    elif mode == 'logger_level':
        auth_events.EVENT_LOGGER.setLevel(logging.CRITICAL)
    elif mode == 'handler_level':
        handler.setLevel(logging.CRITICAL)
    elif mode == 'closed':
        handler.close()
    elif mode == 'handler_filter':
        handler.addFilter(lambda record: False)
    elif mode == 'logger_filter':
        auth_events.EVENT_LOGGER.addFilter(lambda record: False)
    elif mode == 'null_handler':
        auth_events.EVENT_LOGGER.handlers = [logging.NullHandler()]
    elif mode == 'wrong_path':
        auth_events.EVENT_LOGGER.handlers = [auth_events.SecurityEventFileHandler(path.with_name('unacquired.jsonl'), delay=True)]
    elif mode == 'unsafe_file':
        path.chmod(0o644)
    else:
        raise AssertionError('Unknown controlled test mode')
    if mode in {'missing', 'logger_disabled', 'logger_level', 'handler_level', 'closed', 'null_handler', 'wrong_path'}:
        assert auth_events.recording_health()['auth_events'] is False, 'Stale healthy state survived a disabled writer'

recorded = auth_events.emit_auth_event(request, 'auth_failure', 'credentials')
health = auth_events.recording_health()
print(json.dumps({'recorded': recorded, 'health': health, 'enabled': settings.CROWDSEC_AUTH_EVENTS_ENABLED}))
logging.shutdown()
"""


class EffectiveCrowdSecLoggingTests(SimpleTestCase):
    def run_process(
        self, environment: str, mode: str, *, enabled: bool | None = True
    ) -> tuple[RecordingResult, list[dict[str, object]]]:
        with TemporaryDirectory(prefix="portal-auth-effective-") as folder:
            root = Path(folder)
            ordinary = root / "ordinary"
            dedicated = root / "security"
            ordinary.mkdir(mode=0o700)
            dedicated.mkdir(mode=0o700)
            event_path = dedicated / "portal-auth.jsonl"
            env = {
                name: value
                for name, value in os.environ.items()
                if name in {"PATH", "HOME", "SYSTEMROOT", "TMPDIR", "LANG", "LC_ALL"}
            }
            env.update(
                {
                    "PRAHO_SKIP_DOTENV": "1",
                    "DJANGO_SETTINGS_MODULE": f"config.settings.{environment}",
                    "ENVIRONMENT": "production" if environment == "prod" else environment,
                    "DJANGO_SECRET_KEY": secrets.token_urlsafe(64),
                    "PLATFORM_API_SECRET": secrets.token_urlsafe(64),
                    "PLATFORM_TO_PORTAL_WEBHOOK_SECRET": secrets.token_urlsafe(64),
                    "PORTAL_HMAC_SECRET": secrets.token_urlsafe(64),
                    "PORTAL_ID": "fixture-portal",
                    "ALLOWED_HOSTS": "portal.example.test,localhost",
                    "PORTAL_DOMAIN": "portal.example.test",
                    "PLATFORM_API_BASE_URL": "https://platform.example.test/api",
                    "PORTAL_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
                    "PORTAL_LOG_DIR": str(ordinary),
                    "CROWDSEC_AUTH_LOG_PATH": str(event_path),
                    "CROWDSEC_AUTH_PSEUDONYM_KEY": secrets.token_urlsafe(64),
                    "SESSION_DB_PATH": str(root / "sessions.sqlite3"),
                }
            )
            if enabled is not None:
                env["CROWDSEC_AUTH_EVENTS_ENABLED"] = "true" if enabled else "false"
            result = subprocess.run(  # noqa: S603 -- current interpreter, fixed program, isolated nonsecret fixture environment.
                [sys.executable, "-c", SCRIPT, mode],
                cwd=PORTAL,
                env=env,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr[-4000:])
            outcome = json.loads(result.stdout.splitlines()[-1])
            events = [json.loads(line) for line in event_path.read_text().splitlines()] if event_path.exists() else []
            if events and mode != "unsafe_file":
                self.assertEqual(stat.S_IMODE(event_path.stat().st_mode), 0o600)
            ordinary_output = result.stderr + result.stdout + "".join(path.read_text() for path in ordinary.iterdir())
            self.assertNotIn("auth_failure", ordinary_output)
            self.assertNotIn("PrivatePerson", ordinary_output)
            self.assertNotIn("never-record-this-password", ordinary_output)
            self.assertFalse((dedicated / "unacquired.jsonl").exists())
            for event in events:
                self.assertEqual(set(event), {"schema", "timestamp", "event", "ip", "account", "reason"})
                self.assertEqual(event["schema"], 1)
                self.assertEqual(event["ip"], "198.51.100.29")
                self.assertRegex(str(event["account"]), r"^[0-9a-f]{64}$")
            return outcome, events

    def test_production_settings_write_only_the_private_fixed_schema_file(self) -> None:
        outcome, events = self.run_process("prod", "normal")
        self.assertIs(outcome["recorded"], True)
        self.assertIs(outcome["health"]["auth_events"], True)
        self.assertEqual(len(events), 1)

    def test_staging_settings_write_only_the_private_fixed_schema_file(self) -> None:
        outcome, events = self.run_process("staging", "normal")
        self.assertIs(outcome["recorded"], True)
        self.assertIs(outcome["health"]["auth_events"], True)
        self.assertEqual(len(events), 1)

    def test_missing_or_disabled_writer_never_preserves_a_successful_noop(self) -> None:
        for mode in (
            "missing",
            "logger_disabled",
            "logger_level",
            "handler_level",
            "closed",
            "handler_filter",
            "logger_filter",
            "null_handler",
            "wrong_path",
            "unsafe_file",
        ):
            with self.subTest(mode=mode):
                outcome, events = self.run_process("dev", mode)
                self.assertIs(outcome["recorded"], False)
                self.assertIs(outcome["health"]["auth_events"], False)
                self.assertEqual(len(events), 1)

    def test_events_remain_disabled_by_default_in_base_and_deployed_settings(self) -> None:
        for environment in ("base", "dev", "prod", "staging"):
            with self.subTest(environment=environment):
                outcome, events = self.run_process(environment, "disabled", enabled=None)
                self.assertIs(outcome["enabled"], False)
                self.assertIs(outcome["recorded"], False)
                self.assertIs(outcome["health"]["auth_events"], False)
                self.assertEqual(events, [])
