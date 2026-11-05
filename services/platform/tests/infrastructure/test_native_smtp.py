"""Native SMTP opt-in uses owned real network acceptance, never production delivery."""

import json
import smtplib
import socket
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ImproperlyConfigured
from django.core.mail import EmailMultiAlternatives
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from apps.infrastructure.native_smtp import NativeSMTPCapture, accepted_messages, validate_capture, verify_email_logs
from apps.notifications.models import EmailLog
from apps.notifications.services import compose_message, stored_message
from apps.notifications.tasks import send_email_task
from apps.provisioning.hosting_warning_delivery import notification_handover_refusal, sweep_hosting_warnings
from apps.users.models import User
from tests.helpers.native_authority import make_authority, native_settings
from tests.provisioning.test_hosting_warning_delivery import WarningFixture


def mail_settings(configuration: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in configuration.items() if key.startswith("EMAIL_")}


class NativeSMTPTests(SimpleTestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.authority = make_authority(self.root)
        self.path = self.root / "smtp.json"

    def test_default_is_file_capture_and_does_not_depend_on_any_smtp_listener(self):
        config = native_settings(self.authority)
        self.assertEqual(config["EMAIL_BACKEND"], "django.core.mail.backends.filebased.EmailBackend")
        self.assertEqual(Path(config["EMAIL_FILE_PATH"]).parent, self.root)

    def test_failed_manifest_publication_closes_owned_listener_even_for_interrupt(self):
        for index, failure in enumerate((OSError("fixture write failed"), KeyboardInterrupt("fixture canceled"))):
            with self.subTest(failure=type(failure).__name__):
                capture = NativeSMTPCapture(self.authority, self.path.with_name(f"failed-{index}.json"))
                ports: list[int] = []

                def refuse_publication(*args, ports=ports, capture=capture, failure=failure):
                    ports.append(capture.port)
                    raise failure

                with (
                    patch("apps.infrastructure.native_smtp._write_private", side_effect=refuse_publication),
                    self.assertRaises(type(failure)),
                ):
                    capture.__enter__()
                self.assertFalse(capture.active)
                self.assertIsNone(capture.server)
                if capture.thread is None:
                    self.fail("The manifest must be published only after the capture thread starts")
                self.assertFalse(capture.thread.is_alive())
                with socket.socket() as released:
                    released.bind(("127.0.0.1", ports[0]))

    def test_live_owned_optin_overrides_ambient_smtp_and_captures_real_mime(self):
        with NativeSMTPCapture(self.authority, self.path) as capture:
            config = native_settings(self.authority, self.path)
            self.assertEqual(config["EMAIL_BACKEND"], "django.core.mail.backends.smtp.EmailBackend")
            self.assertEqual(
                {key: config[key] for key in ("EMAIL_HOST", "EMAIL_PORT", "EMAIL_HOST_USER", "EMAIL_HOST_PASSWORD")},
                {
                    "EMAIL_HOST": "127.0.0.1",
                    "EMAIL_PORT": capture.port,
                    "EMAIL_HOST_USER": "",
                    "EMAIL_HOST_PASSWORD": "",
                },
            )
            self.assertEqual(
                (config["EMAIL_USE_TLS"], config["EMAIL_USE_SSL"], config["EMAIL_TIMEOUT"]), (False, False, 5)
            )
            self.assertEqual(config["EMAIL_PROVIDER"], "smtp")
            with override_settings(**mail_settings(config)):
                message = EmailMultiAlternatives(
                    "Verificare ș",
                    "Text\n.leading dot",
                    "sender@example.invalid",
                    ["to@example.invalid"],
                    cc=["cc@example.invalid"],
                    bcc=["bcc@example.invalid"],
                )
                message.attach_alternative("<p>Ș HTML</p>", "text/html")
                self.assertEqual(message.send(), 1)
            messages = accepted_messages(self.authority, self.path)
            self.assertEqual(len(messages), 1)
            self.assertEqual(messages[0].sender, "sender@example.invalid")
            self.assertEqual(
                set(messages[0].recipients), {"to@example.invalid", "cc@example.invalid", "bcc@example.invalid"}
            )
            self.assertEqual(messages[0].subject, "Verificare ș")
            self.assertEqual(messages[0].text, "Text\n.leading dot")
            self.assertEqual(messages[0].html, "<p>Ș HTML</p>")
            self.assertNotIn(b"Bcc:", messages[0].mime)
            for file in self.root.rglob("*"):
                if file.is_file():
                    self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    def test_stopped_capture_refuses_optin_but_cleanup_retains_safe_file_backend(self):
        with NativeSMTPCapture(self.authority, self.path):
            pass
        with self.assertRaisesRegex(ImproperlyConfigured, "SMTP"):
            native_settings(self.authority, self.path)
        config = native_settings(self.authority, self.path, cleanup=True)
        self.assertEqual(config["EMAIL_BACKEND"], "django.core.mail.backends.filebased.EmailBackend")

    def test_manifest_refuses_foreign_run_host_expiry_permissions_symlink_and_unknown_shape(self):
        with NativeSMTPCapture(self.authority, self.path):
            original = self.path.read_bytes()
            for mutation in (
                {"run": str(uuid4())},
                {"host": "smtp.production.invalid"},
                {"host": "127.0.0.2"},
                {"expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()},
                {"expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat()},
                {"port": True},
                {"schema": 2},
                {"unexpected": "extra"},
                {"instance": str(uuid4())},
                {"instance": True},
                {"authority": "f" * 64},
                {"vm_manifest": str(self.root / "foreign-vm.json")},
            ):
                with self.subTest(mutation=mutation):
                    self.path.write_text(json.dumps({**json.loads(original), **mutation}))
                    with self.assertRaises(ValueError):
                        validate_capture(self.authority, self.path)
                    self.path.write_bytes(original)
            self.path.chmod(0o644)
            with self.assertRaises(ValueError):
                validate_capture(self.authority, self.path)
            self.path.chmod(0o600)
            alias = self.root / "alias.json"
            alias.symlink_to(self.path)
            with self.assertRaises(ValueError):
                validate_capture(self.authority, alias)

    def test_unfinished_data_is_not_accepted_and_capture_never_relays(self):
        with NativeSMTPCapture(self.authority, self.path) as capture:
            client = smtplib.SMTP("127.0.0.1", capture.port, timeout=5)
            self.addCleanup(client.close)
            client.ehlo()
            client.mail("sender@example.invalid")
            client.rcpt("recipient@external.invalid")
            self.assertEqual(client.docmd("DATA")[0], 354)
            client.send(b"Subject: never complete\r\n\r\npartial\r\n")
            client.close()
            self.assertEqual(accepted_messages(self.authority, self.path), [])

    def test_persistence_failure_never_returns_successful_data_acceptance(self):
        with (
            NativeSMTPCapture(self.authority, self.path) as capture,
            smtplib.SMTP("127.0.0.1", capture.port, timeout=5) as client,
        ):
            with (
                patch("apps.infrastructure.native_smtp.os.fsync", side_effect=OSError("fixture disk failure")),
                self.assertRaises(smtplib.SMTPDataError) as refused,
            ):
                client.sendmail("sender@example.invalid", ["recipient@example.invalid"], "Subject: refused\r\n\r\nbody")
            self.assertEqual(refused.exception.smtp_code, 451)

    def test_cleanup_loads_after_vm_and_capture_expiry_without_contacting_smtp(self):
        with NativeSMTPCapture(self.authority, self.path):
            pass
        manifest = json.loads(self.authority.path.read_text())
        manifest["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        self.authority.path.write_text(json.dumps(manifest))
        with patch(
            "apps.infrastructure.native_smtp.smtplib.SMTP", side_effect=AssertionError("Cleanup must not use SMTP")
        ):
            config = native_settings(self.authority, self.path, cleanup=True)
        self.assertEqual(config["EMAIL_BACKEND"], "django.core.mail.backends.filebased.EmailBackend")
        with self.assertRaises(ImproperlyConfigured):
            native_settings(self.authority, self.path)

    def test_foreground_cli_expires_and_retains_exact_capture_authority(self):
        root = Path(__file__).resolve().parents[4]
        result = subprocess.run(  # noqa: S603 -- Exact repository CLI, original owned fixture paths, no shell.
            [
                sys.executable,
                str(root / "tests/virtualmin_lab/native/smtp_capture.py"),
                "serve",
                "--manifest",
                str(self.authority.path),
                "--smtp-manifest",
                str(self.path),
                "--lifetime-seconds",
                "1",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("capture ready", result.stdout)
        self.assertIn("capture closed", result.stdout)
        manifest = json.loads(self.path.read_text())
        self.assertEqual(
            (manifest["run"], manifest["phase"], manifest["host"]),
            (self.authority.manifest["run"], "closed", "127.0.0.1"),
        )
        self.assertNotIn(self.authority.key.decode(), result.stdout + result.stderr)


class NativeSMTPWarningTests(WarningFixture, TestCase):
    def test_captured_content_cannot_prove_a_different_provider_or_unfinished_log(self):
        with TemporaryDirectory() as directory:
            authority = make_authority(Path(directory))
            path = Path(directory) / "smtp.json"
            with (
                NativeSMTPCapture(authority, path),
                override_settings(**mail_settings(native_settings(authority, path))),
            ):
                log = self.queue_critical()
                self.assertTrue(send_email_task(str(log.pk))["success"])
                log.refresh_from_db()
                for changed in (
                    {"provider": "ses"},
                    {"status": "queued"},
                    {"delivery_attempts": 0},
                    {"claim_token": uuid4()},
                ):
                    with self.subTest(changed=changed):
                        original = {key: getattr(log, key) for key in changed}
                        EmailLog.objects.filter(pk=log.pk).update(**changed)
                        with self.assertRaisesRegex(ValueError, "completed SMTP acceptance"):
                            verify_email_logs(authority, path, [str(log.pk)])
                        EmailLog.objects.filter(pk=log.pk).update(**original)

    def test_real_native_optin_qualifies_public_readiness_and_stored_warning_smtp_acceptance(self):
        actor = User.objects.create_superuser(email="native-smtp-staff@example.invalid", password=None)
        self.client.force_login(actor)
        url = reverse("provisioning:node_hosting_policy", args=[self.server.pk])
        data = {"action": "handover_mail", "reason": "Owned native SMTP acceptance", "acknowledged": "on"}
        with TemporaryDirectory() as directory:
            root = Path(directory)
            authority = make_authority(root)
            path = root / "smtp.json"
            default = native_settings(authority)
            with override_settings(**mail_settings(default)):
                self.assertIn("actual delivery transport", notification_handover_refusal(self.server) or "")
                with patch("apps.provisioning.hosting_node_views.async_task") as queue:
                    response = self.client.post(url, data)
                self.assertContains(response, "actual delivery transport")
                queue.assert_not_called()
            with NativeSMTPCapture(authority, path):
                config = native_settings(authority, path)
                with override_settings(**mail_settings(config)):
                    self.assertIsNone(notification_handover_refusal(self.server))
                    with (
                        patch(
                            "apps.provisioning.hosting_node_views.async_task", return_value="native-smtp-fixture"
                        ) as queue,
                        self.captureOnCommitCallbacks(execute=True),
                    ):
                        self.assertEqual(self.client.post(url, data).status_code, 302)
                    queue.assert_called_once()
                    # Queue admission is not native handover proof; WarningFixture owns its separate synthetic policy.
                    observed = self.publish(1024**3)
                    sweep_hosting_warnings(at=observed + timedelta(minutes=10))
                    log = EmailLog.objects.get()
                    result = send_email_task(str(log.pk))
                    self.assertTrue(result["success"], result)
                    log.refresh_from_db()
                    self.assertEqual(log.status, "sent")
                    self.assertIn("100%", log.get_decrypted_body_text())
                    evidence = verify_email_logs(authority, path, [str(log.pk)])
                    self.assertEqual(evidence["accepted_count"], 1)
                    self.assertEqual(evidence["email_log_ids"], [str(log.pk)])
                    self.assertFalse(send_email_task(str(log.pk))["success"])
                    self.assertEqual(verify_email_logs(authority, path, [str(log.pk)]), evidence)
                    log.subject = "Changed after acceptance"
                    log.save(update_fields=["subject"])
                    with self.assertRaisesRegex(ValueError, "match"):
                        verify_email_logs(authority, path, [str(log.pk)])

    def test_identical_extra_smtp_acceptance_refuses_an_exact_once_claim(self):
        with TemporaryDirectory() as directory:
            authority = make_authority(Path(directory))
            path = Path(directory) / "smtp.json"
            with (
                NativeSMTPCapture(authority, path),
                override_settings(**mail_settings(native_settings(authority, path))),
            ):
                log = self.queue_critical()
                self.assertTrue(send_email_task(str(log.pk))["success"])
                log.refresh_from_db()
                self.assertEqual(verify_email_logs(authority, path, [str(log.pk)])["accepted_count"], 1)
                self.assertEqual(compose_message(stored_message(log), []).send(), 1)
                with self.assertRaisesRegex(ValueError, "unambiguously"):
                    verify_email_logs(authority, path, [str(log.pk)])
