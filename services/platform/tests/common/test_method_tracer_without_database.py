"""Method tracing remains available when database access is forbidden."""

from unittest.mock import patch

from django.core.cache import cache
from django.db import OperationalError
from django.test import SimpleTestCase, override_settings

from apps.common.logging import MethodTracer


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class MethodTracerWithoutDatabaseTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        MethodTracer.clear()
        self.addCleanup(cache.clear)
        self.addCleanup(MethodTracer.clear)
        was_enabled = MethodTracer._enabled
        MethodTracer.enable()
        self.addCleanup(setattr, MethodTracer, "_enabled", was_enabled)

    def test_trace_returns_value_and_records_default_summaries_without_database_access(self) -> None:
        @MethodTracer.trace
        def echo(value: str) -> str:
            return value

        value = "x" * 51
        try:
            result = echo(value)
        except (AssertionError, RuntimeError):
            self.fail("method tracing must work without database access")
        self.assertEqual(result, value)
        traces = MethodTracer.get_all_traces()
        self.assertEqual(len(traces), 1)
        self.assertEqual(traces[0].args_summary, f'arg0="{"x" * 50}..."')
        self.assertEqual(traces[0].return_summary, f'"{"x" * 50}..."')
        self.assertIsNone(traces[0].exception)

    def test_argument_summary_uses_defaults_when_settings_are_unavailable(self) -> None:
        with patch(
            "apps.settings.services.SettingsService.get_integer_setting",
            side_effect=OperationalError("settings offline"),
        ):
            try:
                summary = MethodTracer._summarize_args(("first", "second", "third", "fourth"), {})
            except OperationalError:
                self.fail("method summaries must tolerate an unavailable settings table")
        self.assertEqual(summary, 'arg0="first", arg1="second", arg2="third", ...')
