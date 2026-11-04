"""Real Portal middleware and both response layers feed only sanitized attack events."""

import fcntl
import json
import logging
import multiprocessing
import os
import stat
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone as django_timezone
from requests import Response

from apps.common.auth_events import SecurityEventFileHandler, account_pseudonym


def _write_worker_events(path, ready, worker):
    handler = SecurityEventFileHandler(path, maxBytes=128, backupCount=100, delay=True)
    try:
        ready.wait(timeout=10)
        for index in range(50):
            handler.emit(
                logging.LogRecord("fixture", logging.INFO, "", 0, '{"worker":%s,"index":%s}', (worker, index), None)
            )
    finally:
        handler.close()


@override_settings(
    CROWDSEC_AUTH_EVENTS_ENABLED=True,
    RATE_LIMITING_ENABLED=True,
    DEBUG=True,
    IPWARE_TRUSTED_PROXY_LIST=["127.0.0.1/32"],
    PLATFORM_API_AUTH_MIN_DURATION_SECONDS=0,
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "crowdsec-events"}},
)
class CrowdSecAuthenticationEventsTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.credentials = {"email": "PrivatePerson@example.test", "password": "Private-password-123!"}
        self.address = "198.51.100.29"

    def answer(self, category: str, status: int = 401) -> Response:
        response = Response()
        response.status_code = status
        response.headers["Content-Type"] = "application/json"
        response._content = json.dumps(
            {"success": False, "error": "Invalid authentication code", "failure_category": category}
        ).encode()
        return response

    def submit(self):
        return self.client.post(
            reverse("users:login"), self.credentials, HTTP_X_FORWARDED_FOR=self.address, HTTP_HX_REQUEST="true"
        )

    def test_middleware_refusals_keep_attacks_visible_after_the_failure_budget(self) -> None:
        with (
            patch("apps.api_client.services.portal_request", return_value=self.answer("credentials")) as upstream,
            self.assertLogs("praho.crowdsec.auth", level="INFO") as recorded,
        ):
            responses = [self.submit() for _ in range(7)]
        self.assertEqual(upstream.call_count, 5)
        self.assertEqual([response.status_code for response in responses], [200] * 5 + [429, 429])
        events = [json.loads(record.getMessage()) for record in recorded.records]
        self.assertEqual([event["event"] for event in events], ["auth_failure"] * 5 + ["throttle_refusal"] * 2)
        self.assertEqual({event["ip"] for event in events}, {self.address})
        self.assertEqual(len({event["account"] for event in events}), 1)
        output = json.dumps(events)
        self.assertNotIn("privateperson", output.lower())
        self.assertNotIn(self.credentials["password"], output)
        self.assertNotIn("Invalid authentication code", responses[0].content.decode())

    def test_a_second_factor_refusal_and_an_outage_are_distinct(self) -> None:
        with self.assertLogs("praho.crowdsec.auth", level="INFO") as recorded:
            with patch("apps.api_client.services.portal_request", return_value=self.answer("second_factor")):
                refused = self.submit()
            with (
                patch("apps.api_client.services.portal_request", return_value=self.answer("second_factor", 503)),
                patch("apps.api_client.services.PlatformAPIClient._retry_wait", return_value=None),
            ):
                unavailable = self.submit()
        events = [json.loads(record.getMessage()) for record in recorded.records]
        self.assertEqual([event["event"] for event in events], ["mfa_failure", "protection_degraded"])
        self.assertNotIn("Invalid authentication code", refused.content.decode())
        self.assertIn("temporarily unavailable", unavailable.content.decode())

    def test_a_forged_cloudflare_pair_never_overrides_caddy_forwarding(self) -> None:
        with (
            patch("apps.api_client.services.portal_request", return_value=self.answer("credentials")),
            self.assertLogs("praho.crowdsec.auth", level="INFO") as recorded,
        ):
            self.client.post(
                reverse("users:login"),
                self.credentials,
                HTTP_X_FORWARDED_FOR=self.address,
                HTTP_CF_RAY="attacker-forged-ray",
                HTTP_CF_CONNECTING_IP="203.0.113.77",
            )
        event = json.loads(recorded.records[0].getMessage())
        self.assertEqual(event["ip"], self.address)

    def test_daily_pseudonyms_rotate_and_do_not_depend_on_local_timezone(self) -> None:
        day = datetime(2026, 11, 4, 0, 10, tzinfo=UTC)
        original = account_pseudonym(" PrivatePerson@EXAMPLE.test ", at=day)
        self.assertEqual(
            original, account_pseudonym("privateperson@example.test", at=day.astimezone(timezone(timedelta(hours=-4))))
        )
        self.assertNotEqual(original, account_pseudonym("privateperson@example.test", at=day + timedelta(days=1)))
        self.assertNotEqual(original, account_pseudonym("other@example.test", at=day))
        with override_settings(CROWDSEC_AUTH_PSEUDONYM_KEY="different-private-root-key"):
            self.assertNotEqual(original, account_pseudonym("privateperson@example.test", at=day))
        self.assertRegex(original, r"^[0-9a-f]{64}$")

    def test_event_writer_failure_exposes_degraded_health_without_a_new_refusal(self) -> None:
        with (
            patch("apps.api_client.services.portal_request", return_value=self.answer("credentials")),
            patch("apps.common.auth_events.EVENT_LOGGER.info", side_effect=OSError("private-sentinel-secret")),
            self.assertLogs("apps.common.auth_events", level="CRITICAL") as fallback,
        ):
            response = self.submit()
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("private-sentinel-secret", " ".join(fallback.output))
        status = self.client.get(reverse("portal_status"))
        self.assertEqual(status.status_code, 200)
        self.assertIs(status.json()["protection"]["auth_events"], False)

    @override_settings(CROWDSEC_AUTH_EVENTS_ENABLED=False)
    def test_disabled_logging_emits_nothing_and_reports_disabled(self) -> None:
        with (
            patch("apps.api_client.services.portal_request", return_value=self.answer("credentials")),
            self.assertNoLogs("praho.crowdsec.auth", level="INFO"),
        ):
            response = self.submit()
        self.assertEqual(response.status_code, 200)
        state = self.client.get(reverse("portal_status")).json()["protection"]
        self.assertIs(state["auth_events_enabled"], False)
        self.assertIs(state["auth_events"], False)

    def test_mapped_ipv6_events_use_the_actual_ipv4_host_family(self) -> None:
        self.address = "::ffff:198.51.100.29"
        with (
            patch("apps.api_client.services.portal_request", return_value=self.answer("credentials")),
            self.assertLogs("praho.crowdsec.auth", level="INFO") as recorded,
        ):
            self.submit()
        self.assertEqual(json.loads(recorded.records[0].getMessage())["ip"], "198.51.100.29")

    def test_event_files_and_rotations_remain_private_under_a_permissive_umask(self) -> None:
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            old_umask = os.umask(0o022)
            handler = SecurityEventFileHandler(folder / "auth.jsonl", maxBytes=40, backupCount=2, delay=True)
            try:
                for index in range(6):
                    handler.emit(
                        logging.LogRecord(
                            "fixture", logging.INFO, "", 0, '{"fixture":"bounded-record-%s"}', (index,), None
                        )
                    )
            finally:
                handler.close()
                os.umask(old_umask)
            self.assertGreater(len(list(folder.iterdir())), 1)
            for path in folder.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_event_handler_refuses_a_shared_directory_without_changing_its_mode(self) -> None:
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            folder.chmod(0o755)
            handler = SecurityEventFileHandler(folder / "auth.jsonl", maxBytes=100, backupCount=1, delay=True)
            try:
                with self.assertRaises(OSError):
                    handler.emit(logging.LogRecord("fixture", logging.INFO, "", 0, "safe fixture", (), None))
            finally:
                handler.close()
            self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o755)

    def sign_in(self) -> None:
        now = django_timezone.now()
        session = self.client.session
        session.update(
            {
                "user_id": 42,
                "customer_id": 7,
                "active_customer_id": 7,
                "email": self.credentials["email"],
                "session_auth_hash": "fixture-snapshot",
                "portal_session_id": "6f1c2a0e-8a5b-4d0c-9a77-0d4b3c2e1f00",
                "authenticated_at": now.isoformat(),
                "session_created_at": now.isoformat(),
                "validated_at": now.isoformat(),
                "next_validate_at": (now + timedelta(minutes=10)).isoformat(),
                "user_memberships": [{"customer_id": 7, "customer_name": "Fixture", "role": "owner"}],
                "user_memberships_fetched_at": now.timestamp(),
                "selected_customer_role": "owner",
            }
        )
        session.save()

    def test_identity_confirmation_records_only_verified_failure_categories(self) -> None:
        self.sign_in()
        answer = self.answer("second_factor", 400)
        answer._content = json.dumps(
            {"success": False, "code": "reauth_failed", "failure_category": "second_factor"}
        ).encode()
        with self.assertLogs("praho.crowdsec.auth", level="INFO") as recorded:
            with patch("apps.api_client.services.portal_request", return_value=answer):
                refused = self.client.post(
                    reverse("users:confirm_identity"),
                    {"password": self.credentials["password"], "token": "000000"},
                    HTTP_X_FORWARDED_FOR=self.address,
                )
            with (
                patch("apps.api_client.services.portal_request", return_value=self.answer("second_factor", 503)),
                patch("apps.api_client.services.PlatformAPIClient._retry_wait", return_value=None),
            ):
                unavailable = self.client.post(
                    reverse("users:confirm_identity"),
                    {"password": self.credentials["password"], "token": "000000"},
                    HTTP_X_FORWARDED_FOR=self.address,
                )
        self.assertEqual(
            [json.loads(record.getMessage())["event"] for record in recorded.records],
            ["mfa_failure", "protection_degraded"],
        )
        self.assertContains(refused, "password or code is not right")
        self.assertContains(unavailable, "could not check")

    def test_reset_acceptance_and_middleware_refusals_are_separate_events(self) -> None:
        answer = self.answer("", 200)
        answer._content = b'{"success":true}'
        with (
            patch("apps.api_client.services.portal_request", return_value=answer) as upstream,
            self.assertLogs("praho.crowdsec.auth", level="INFO") as recorded,
        ):
            responses = [
                self.client.post(
                    reverse("users:password_reset"),
                    {"email": self.credentials["email"]},
                    HTTP_X_FORWARDED_FOR=self.address,
                )
                for _ in range(7)
            ]
        self.assertEqual([response.status_code for response in responses], [302] * 5 + [429, 429])
        self.assertEqual(upstream.call_count, 5)
        events = [json.loads(record.getMessage()) for record in recorded.records]
        self.assertEqual(
            [event["event"] for event in events], ["password_reset_request"] * 5 + ["throttle_refusal"] * 2
        )
        self.assertEqual([event["reason"] for event in events], ["password_reset"] * 5 + ["reset"] * 2)

    def test_reset_upstream_outage_reports_degraded_without_an_attack_event(self) -> None:
        with (
            patch("apps.api_client.services.portal_request", return_value=self.answer("", 503)),
            patch("apps.api_client.services.PlatformAPIClient._retry_wait", return_value=None),
            self.assertLogs("praho.crowdsec.auth", level="INFO") as recorded,
        ):
            response = self.client.post(
                reverse("users:password_reset"), {"email": self.credentials["email"]}, HTTP_X_FORWARDED_FOR=self.address
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            [json.loads(record.getMessage())["event"] for record in recorded.records], ["protection_degraded"]
        )

    def test_ordinary_authentication_logs_do_not_duplicate_the_account_identifier(self) -> None:
        with (
            patch("apps.api_client.services.portal_request", return_value=self.answer("credentials")),
            self.assertLogs("apps", level="INFO") as recorded,
        ):
            self.submit()
        output = " ".join(record.getMessage() for record in recorded.records).lower()
        self.assertNotIn(self.credentials["email"].lower(), output)
        self.assertNotIn(self.credentials["password"].lower(), output)

    def test_failed_security_recording_preserves_a_complete_successful_login(self) -> None:
        now = django_timezone.now()
        response = self.answer("", 200)
        response._content = json.dumps(
            {
                "success": True,
                "user": {"id": 42, "customer_id": 7, "email": self.credentials["email"]},
                "session_id": "6f1c2a0e-8a5b-4d0c-9a77-0d4b3c2e1f00",
                "session_auth_hash": "fixture-snapshot",
                "session_tier": "standard",
                "session_expires_at": (now + timedelta(days=1)).isoformat(),
                "session_idle_deadline": (now + timedelta(hours=1)).isoformat(),
                "security_observation": {"enabled": True, "recorded": False, "degraded": True},
            }
        ).encode()
        with (
            patch("apps.api_client.services.portal_request", return_value=response),
            patch("apps.users.views._get_user_customer_memberships", return_value=[]),
            patch("apps.users.views.api_client.get_customer_profile", return_value={}),
            patch("apps.common.auth_events.EVENT_LOGGER.info", side_effect=OSError("private-log-error")),
        ):
            signed_in = self.submit()
        self.assertEqual(signed_in.status_code, 302)
        self.assertEqual(self.client.session["user_id"], 42)
        self.assertEqual(self.client.session["portal_session_id"], "6f1c2a0e-8a5b-4d0c-9a77-0d4b3c2e1f00")
        health = self.client.get(reverse("portal_status")).json()["protection"]
        self.assertIs(health["customer_ip_observations_enabled"], True)
        self.assertIs(health["customer_ip_observations"], False)
        self.assertIs(health["auth_events"], False)

    def test_health_store_write_failure_cannot_leave_a_stale_healthy_claim(self) -> None:
        cache.set("crowdsec:health:auth-events", True)
        with (
            patch("apps.api_client.services.portal_request", return_value=self.answer("credentials")),
            patch("apps.common.auth_events.cache", wraps=cache) as health_cache,
            self.assertLogs("praho.crowdsec.auth", level="INFO"),
        ):
            health_cache.set.side_effect = OSError("private-cache-error")
            response = self.submit()
        self.assertEqual(response.status_code, 200)
        self.assertIs(self.client.get(reverse("portal_status")).json()["protection"]["auth_events"], False)

    def test_an_idle_worker_reopens_a_file_rotated_away_by_another_worker(self) -> None:
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            idle = SecurityEventFileHandler(folder / "auth.jsonl", maxBytes=80, backupCount=2, delay=True)
            active = SecurityEventFileHandler(folder / "auth.jsonl", maxBytes=80, backupCount=2, delay=True)
            try:
                idle.emit(logging.LogRecord("fixture", logging.INFO, "", 0, '{"marker":"first"}', (), None))
                for index in range(6):
                    active.emit(
                        logging.LogRecord(
                            "fixture",
                            logging.INFO,
                            "",
                            0,
                            '{"marker":"other-%s-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}',
                            (index,),
                            None,
                        )
                    )
                idle.emit(logging.LogRecord("fixture", logging.INFO, "", 0, '{"marker":"last-event"}', (), None))
            finally:
                idle.close()
                active.close()
            retained = "".join(path.read_text() for path in folder.iterdir())
            self.assertIn('"last-event"', retained, "The current event must not be written to an unlinked backup inode")

    def test_a_busy_event_writer_reports_failure_within_a_short_budget(self) -> None:
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            lock = os.open(folder / "auth.jsonl.lock", os.O_CREAT | os.O_WRONLY, 0o600)
            handler = SecurityEventFileHandler(folder / "auth.jsonl", maxBytes=80, backupCount=2, delay=True)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                started = monotonic()
                with self.assertRaises(OSError):
                    handler.emit(logging.LogRecord("fixture", logging.INFO, "", 0, '{"marker":"bounded"}', (), None))
                self.assertLess(monotonic() - started, 1.0)
            finally:
                handler.close()
                os.close(lock)

    def test_independent_workers_retain_every_event_through_concurrent_rotation(self) -> None:
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            context = multiprocessing.get_context("fork")
            ready = context.Barrier(3)
            workers = [
                context.Process(target=_write_worker_events, args=(str(folder / "auth.jsonl"), ready, index))
                for index in range(2)
            ]
            try:
                for worker in workers:
                    worker.start()
                ready.wait(timeout=10)
                for worker in workers:
                    worker.join(timeout=15)
                    self.assertEqual(worker.exitcode, 0)
                records = [json.loads(line) for path in folder.iterdir() for line in path.read_text().splitlines()]
                self.assertEqual(len(records), 100)
                self.assertEqual(
                    {(record["worker"], record["index"]) for record in records},
                    {(worker, index) for worker in range(2) for index in range(50)},
                )
            finally:
                for worker in workers:
                    if worker.is_alive():
                        worker.terminate()
                    if worker.pid is not None:
                        worker.join(timeout=5)
