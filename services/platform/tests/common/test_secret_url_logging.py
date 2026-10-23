"""Bearer links must not survive formatting or telemetry callbacks."""

import io
import json
import logging
import sys
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.audit.logging_formatters import SIEMJSONFormatter
from apps.common.gunicorn_logging import RedactingLogger
from apps.common.secret_urls import SecretURLFilter, redact_text, redact_urls
from config.settings.sentry import sentry_options

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
                rendered = SIEMJSONFormatter().format(record)
                self.assertNotIn(secret, rendered)
                self.assertIn("correlation-kept", rendered)

    def test_sentry_scrubs_errors_and_transactions_without_mutating_input(self) -> None:
        link = LINKS[0]
        options = sentry_options("https://key@sentry.example.test/1", release="test")
        for name in ("before_send", "before_send_transaction"):
            with self.subTest(callback=name):
                event = {"request": {"url": link}, "breadcrumbs": {"values": [{"message": link}]}, "transaction": link}
                callback = options.get(name)
                assert callable(callback)
                scrubbed = callback(event, {})
                self.assertNotIn("reset-secret", str(scrubbed))
                self.assertEqual(event["request"]["url"], link)

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


class SecretURLFilterRobustnessTests(SimpleTestCase):
    """The filter runs outside any handler's try (#751 follow-up, M4): it must never raise, and must change
    a record only where a secret is redacted, keeping the lazy message and arguments otherwise."""

    SECRET_LINK = "/notifications/unsubscribe/unsubscribe-secret/"

    def _record(self, msg: str, args: tuple[object, ...], **extra: object) -> logging.LogRecord:
        record = logging.LogRecord("app", logging.INFO, __file__, 1, msg, args, None)
        for name, value in extra.items():
            setattr(record, name, value)
        return record

    def test_a_record_with_bad_format_arguments_is_kept_not_raised(self) -> None:
        record = self._record("%s %s", ("only-one",))

        try:
            kept = SecretURLFilter().filter(record)
        except Exception as error:
            self.fail(f"a logging filter must never raise into the caller ({type(error).__name__})")

        self.assertTrue(kept)

    def test_a_record_with_nothing_to_redact_keeps_its_message_and_arguments(self) -> None:
        record = self._record("user %s logged in", ("bob",))

        SecretURLFilter().filter(record)

        self.assertEqual((record.msg, record.args), ("user %s logged in", ("bob",)))

    def test_a_secret_in_an_argument_is_redacted(self) -> None:
        record = self._record("visited %s", (self.SECRET_LINK,))

        SecretURLFilter().filter(record)

        self.assertNotIn("unsubscribe-secret", record.getMessage())

    def test_a_cyclic_extra_does_not_raise(self) -> None:
        cyclic: dict[str, object] = {"url": self.SECRET_LINK}
        cyclic["self"] = cyclic
        record = self._record("event", (), context=cyclic)

        try:
            SecretURLFilter().filter(record)
        except RecursionError:
            self.fail("a cyclic extra must not recurse forever")

        self.assertNotIn("unsubscribe-secret", str(record.context["url"]))

    def test_unformattable_arguments_never_reach_stderr_unredacted(self) -> None:
        logger = logging.getLogger(f"tests.secret_urls.unformattable.{id(self)}")
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.addFilter(SecretURLFilter())
        logger.addHandler(handler)
        logger.propagate = False
        logger.setLevel(logging.DEBUG)  # Whatever the settings' root level, this record is handled
        self.addCleanup(logger.removeHandler, handler)

        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
            logger.error("%s %s", self.SECRET_LINK)  # noqa: PLE1206  # Deliberate: one argument for two placeholders

        written = stream.getvalue() + stderr.getvalue()
        self.assertTrue(written, "the record reached the handler")
        self.assertNotIn("unsubscribe-secret", written)

    def test_a_tuple_extra_is_redacted_and_stays_a_tuple(self) -> None:
        record = self._record("event", (), parts=("kept", self.SECRET_LINK))

        SecretURLFilter().filter(record)

        self.assertIsInstance(record.parts, tuple)
        self.assertNotIn("unsubscribe-secret", str(record.parts))


class JSONFormatterRedactionTests(SimpleTestCase):
    """The JSON line is redacted as data, then encoded (#751 follow-up, M5).

    Redacting the encoded text could swallow the backslash of an escaped quote right after a secret,
    leaving a line that is no longer JSON.
    """

    def test_a_secret_next_to_a_quote_is_redacted_and_the_line_stays_json(self) -> None:
        record = logging.LogRecord(
            "app", logging.INFO, __file__, 1, 'opened %s"quoted"', ("/notifications/unsubscribe/unsubscribe-secret",), None
        )

        line = SIEMJSONFormatter().format(record)

        try:
            json.loads(line)
        except ValueError:
            self.fail(f"the formatter must write valid JSON: {line}")
        self.assertNotIn("unsubscribe-secret", line)

    def test_a_secret_used_as_a_dictionary_key_is_redacted(self) -> None:
        record = logging.LogRecord("app", logging.INFO, __file__, 1, "results", (), None)
        record.results = {"/notifications/unsubscribe/unsubscribe-secret/": "failed"}

        line = SIEMJSONFormatter().format(record)

        self.assertNotIn("unsubscribe-secret", line)
        self.assertNotIn("unsubscribe-secret", str(redact_urls({"/notifications/unsubscribe/unsubscribe-secret/": 1})))
