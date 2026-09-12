"""Display-only localisation, including timezone and service parity contracts."""

from datetime import UTC, date, datetime
from types import SimpleNamespace

from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase
from django.utils import timezone, translation

from apps.common.localisation import (
    DisplayLocalisation,
    LocalisationDefaults,
    format_localised_date,
    normalize_country_code,
    resolve_display,
)
from apps.common.localisation_middleware import LocalisationMiddleware, sync_language_selection


class DisplayLocalisationTests(SimpleTestCase):
    def test_country_normalization_excludes_unknown_and_aggregate_regions(self):
        for value in ("ZZ", "Unknown Region", "EU", "European Union", "UN", "QO", "XA", "XB"):
            with self.subTest(value=value):
                self.assertEqual(normalize_country_code(value), "")
        for value in ("DE", "Germany", "Germania"):
            self.assertEqual(normalize_country_code(value), "DE")

    def test_presets_and_explicit_override(self) -> None:
        for pattern, expected in (
            ("%d.%m.%Y", "23.11.2026"),
            ("%Y-%m-%d", "2026-11-23"),
            ("%d/%m/%Y", "23/11/2026"),
            ("%m/%d/%Y", "11/23/2026"),
        ):
            with self.subTest(pattern=pattern):
                policy = resolve_display(LocalisationDefaults(), {"date_format": pattern})
                self.assertEqual(format_localised_date(date(2026, 11, 23), policy), expected)

    def test_staff_and_customer_defaults_are_independent(self) -> None:
        defaults = LocalisationDefaults(staff_date_format="%Y-%m-%d", customer_date_format="%m/%d/%Y")
        self.assertEqual(resolve_display(defaults, staff=True).date_format, "%Y-%m-%d")
        self.assertEqual(resolve_display(defaults).date_format, "%m/%d/%Y")
        self.assertEqual(resolve_display(defaults, {"date_format": "%d/%m/%Y"}, staff=True).date_format, "%d/%m/%Y")

    def test_midnight_year_boundary_and_iso_input(self) -> None:
        policy = resolve_display(LocalisationDefaults())
        instant = datetime(2025, 12, 31, 22, 30, 15, tzinfo=UTC)
        for value in (instant, instant.isoformat(), "2025-12-31T22:30:15Z"):
            self.assertEqual(format_localised_date(value, policy, "datetime_seconds"), "01.01.2026 00:30:15")

    def test_dst_transition_uses_instant_and_preserves_active_timezone(self) -> None:
        policy = resolve_display(LocalisationDefaults())
        with timezone.override("America/New_York"):
            self.assertEqual(format_localised_date("2026-03-29T00:30:00Z", policy, "time"), "02:30")
            self.assertEqual(format_localised_date("2026-03-29T01:30:00Z", policy, "time"), "04:30")
            self.assertEqual(format_localised_date("2026-10-25T00:30:00Z", policy, "time"), "03:30")
            self.assertEqual(format_localised_date("2026-10-25T01:30:00Z", policy, "time"), "03:30")
            self.assertEqual(timezone.get_current_timezone_name(), "America/New_York")

    def test_calendar_and_naive_values_are_not_shifted(self) -> None:
        policy = resolve_display(LocalisationDefaults(), {"timezone": "Pacific/Auckland"})
        for value in (date(2025, 12, 31), "2025-12-31", datetime(2025, 12, 31, 22, 30)):
            self.assertEqual(format_localised_date(value, policy), "31.12.2025")

    def test_bad_values_have_no_fabricated_date(self) -> None:
        for value in (None, "", "bad", "2026-13-42", 123, {}, True):
            self.assertEqual(format_localised_date(value, resolve_display(LocalisationDefaults())), "")

    def test_invalid_legacy_preferences_and_defaults_inherit(self) -> None:
        defaults = LocalisationDefaults.from_mapping(
            {"timezone": "nope", "default_country": "ZZ", "staff_date_format": 1}
        )
        self.assertEqual(defaults, LocalisationDefaults())
        self.assertEqual(
            resolve_display(defaults, {"timezone": [], "preferred_language": "xx", "date_format": "%n"}),
            resolve_display(defaults),
        )


class LanguageLocalisationTests(SimpleTestCase):
    def request(self, *, authenticated: bool = True, **headers: str):
        request = RequestFactory().get("/example/", **headers)
        request.session = {}
        request.user = SimpleNamespace(is_authenticated=authenticated)
        request.localisation = DisplayLocalisation("ro", "RO", "UTC", "%d.%m.%Y")
        return request

    def test_language_and_headers_are_scoped_to_request(self) -> None:
        with translation.override("en"), timezone.override("Europe/London"):
            response = LocalisationMiddleware(lambda request: HttpResponse(translation.get_language()))(self.request())
            self.assertEqual(response.content, b"ro")
            self.assertEqual(response["Content-Language"], "ro")
            self.assertIn("Cookie", response["Vary"])
            self.assertEqual(translation.get_language(), "en")
            self.assertEqual(timezone.get_current_timezone_name(), "Europe/London")

    def test_anonymous_browser_language_and_default(self) -> None:
        for header, expected in (("en-US,en;q=0.9", "en"), ("fr", "ro"), ("", "ro")):
            response = LocalisationMiddleware(lambda request: HttpResponse(request.LANGUAGE_CODE))(
                self.request(authenticated=False, HTTP_ACCEPT_LANGUAGE=header)
            )
            self.assertEqual(response.content.decode(), expected)

    def test_signed_in_inheritance_beats_browser_language(self) -> None:
        response = LocalisationMiddleware(lambda request: HttpResponse(request.LANGUAGE_CODE))(
            self.request(HTTP_ACCEPT_LANGUAGE="en")
        )
        self.assertEqual(response.content, b"ro")

    def test_anonymous_supported_session_and_cookie_choices_precede_browser(self) -> None:
        for session in ({"_language": "ro"}, {"django_language": "ro"}, {"_language": "unsupported"}):
            with self.subTest(session=session):
                request = self.request(authenticated=False, HTTP_ACCEPT_LANGUAGE="en")
                request.session = session
                request.COOKIES["django_language"] = "en" if "ro" in session.values() else "ro"
                response = LocalisationMiddleware(lambda request: HttpResponse(request.LANGUAGE_CODE))(request)
                self.assertEqual(response.content, b"ro")

    def test_document_endpoints_keep_existing_language(self) -> None:
        request = self.request()
        request.path_info = "/billing/invoices/123/pdf/"
        with translation.override("en"):
            response = LocalisationMiddleware(lambda request: HttpResponse(translation.get_language()))(request)
        self.assertEqual(response.content, b"en")

    def test_inheritance_clears_legacy_explicit_choices(self) -> None:
        request = self.request()
        request.session = {"_language": "ro", "django_language": "ro"}
        response = HttpResponse()
        sync_language_selection(request, response, "")
        self.assertEqual(request.session, {"localisation_preferences_saved": True})
        self.assertEqual(response.cookies["django_language"]["max-age"], 0)
