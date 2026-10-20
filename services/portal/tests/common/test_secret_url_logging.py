"""Bearer links must not survive formatting or telemetry callbacks."""

import logging
import sys
from datetime import timedelta
from types import SimpleNamespace

from django.test import SimpleTestCase

from apps.common.gunicorn_logging import RedactingLogger
from apps.common.logging import PortalJSONFormatter
from apps.common.secret_urls import redact_text

LINKS = (
    "/%61uth/password-reset-confirm/uid/reset-secret/",
    "/%70assword%2dreset/confirm/uid/reset-secret/",
    "/auth/password-reset-confirm/uid/reset-secret/",
    "/password-reset/confirm/uid/reset-secret/",
    "/register/confirm/01234567/register-secret/",
    "/notifications/unsubscribe/unsubscribe-secret/",
    "/password-reset/confirm/uid/%72%65%73%65%74-secret/",
)


class SecretURLLoggingTests(SimpleTestCase):
    def test_actual_json_formatter_scrubs_messages_extras_and_exceptions(self) -> None:
        for link in LINKS:
            secret = link.rstrip("/").rsplit("/", 1)[-1]
            with self.subTest(link=link):
                try:
                    raise ValueError(f"Failed request https://portal.example.com{link}")
                except ValueError:
                    record = logging.LogRecord(
                        "django.request", logging.ERROR, __file__, 1, "Failed %s", (link,), sys.exc_info()
                    )
                record.request_url = link
                record.request_id = "correlation-kept"
                rendered = PortalJSONFormatter().format(record)
                self.assertNotIn(secret, rendered)
                self.assertIn("correlation-kept", rendered)

    def test_gunicorn_scrubs_request_and_referrer_without_changing_environ(self) -> None:
        from gunicorn.config import Config  # noqa: PLC0415

        logger = RedactingLogger(Config())
        link = LINKS[0]
        environ = {
            "REQUEST_METHOD": "GET",
            "RAW_URI": link,
            "PATH_INFO": link,
            "SERVER_PROTOCOL": "HTTP/1.1",
            "HTTP_REFERER": link,
        }
        atoms = logger.atoms(SimpleNamespace(status="200 OK", headers=[]), [], environ, timedelta())
        self.assertNotIn("reset-secret", str(atoms))
        self.assertEqual(environ["RAW_URI"], link)

    def test_ordinary_identifiers_are_preserved(self) -> None:
        path = "/customers/01234567/settings/api_key/"
        self.assertEqual(redact_text(path), path)
