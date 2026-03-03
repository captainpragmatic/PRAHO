"""
Tests for infrastructure URL routing.

Verifies that all infrastructure URL patterns accept integer PKs (not UUIDs),
matching the actual model primary key types. These tests catch the NoReverseMatch
bugs where URL patterns used <uuid:pk> but models use auto-incrementing int PKs.
"""

from __future__ import annotations

from typing import ClassVar

from django.test import TestCase
from django.urls import NoReverseMatch, reverse

from apps.infrastructure.urls import urlpatterns


class TestDeploymentURLsAcceptIntegerPK(TestCase):
    """All deployment URL patterns must accept integer PKs.

    NodeDeployment uses Django's default BigAutoField (integer PK).
    Using <uuid:pk> in URL patterns causes NoReverseMatch when reversing
    with an integer ID like deployment.id = 1.
    """

    DEPLOYMENT_URL_NAMES: ClassVar[list[str]] = [
        "infrastructure:deployment_detail",
        "infrastructure:deployment_logs",
        "infrastructure:deployment_retry",
        "infrastructure:deployment_destroy",
        "infrastructure:deployment_upgrade",
        "infrastructure:deployment_stop",
        "infrastructure:deployment_start",
        "infrastructure:deployment_reboot",
        "infrastructure:deployment_maintenance",
        "infrastructure:deployment_status_partial",
        "infrastructure:deployment_logs_partial",
    ]

    def test_all_deployment_urls_resolve_with_integer_pk(self) -> None:
        """Every deployment URL must reverse successfully with an integer PK."""
        for url_name in self.DEPLOYMENT_URL_NAMES:
            with self.subTest(url_name=url_name):
                try:
                    url = reverse(url_name, kwargs={"pk": 1})
                except NoReverseMatch:
                    self.fail(
                        f"{url_name} does not accept integer pk=1. "
                        f"Check that the URL pattern uses <int:pk>, not <uuid:pk>."
                    )
                self.assertIn("/deployments/1/", url)

    def test_deployment_urls_reject_uuid_strings(self) -> None:
        """Integer URL patterns must not match UUID-formatted strings."""
        uuid_str = "550e8400-e29b-41d4-a716-446655440000"
        for url_name in self.DEPLOYMENT_URL_NAMES:
            with self.subTest(url_name=url_name), self.assertRaises(NoReverseMatch):
                reverse(url_name, kwargs={"pk": uuid_str})


class TestProviderURLsAcceptIntegerPK(TestCase):
    """CloudProvider URL patterns must accept integer PKs."""

    def test_provider_edit_resolves_with_integer_pk(self) -> None:
        url = reverse("infrastructure:provider_edit", kwargs={"pk": 1})

        self.assertIn("/providers/1/edit/", url)

    def test_provider_edit_rejects_uuid(self) -> None:
        with self.assertRaises(NoReverseMatch):
            reverse(
                "infrastructure:provider_edit",
                kwargs={"pk": "550e8400-e29b-41d4-a716-446655440000"},
            )


class TestSizeURLsAcceptIntegerPK(TestCase):
    """NodeSize URL patterns must accept integer PKs."""

    def test_size_edit_resolves_with_integer_pk(self) -> None:
        url = reverse("infrastructure:size_edit", kwargs={"pk": 1})

        self.assertIn("/sizes/1/edit/", url)

    def test_size_edit_rejects_uuid(self) -> None:
        with self.assertRaises(NoReverseMatch):
            reverse(
                "infrastructure:size_edit",
                kwargs={"pk": "550e8400-e29b-41d4-a716-446655440000"},
            )


class TestRegionURLsAcceptIntegerPK(TestCase):
    """NodeRegion URL patterns must accept integer PKs."""

    def test_region_toggle_resolves_with_integer_pk(self) -> None:
        url = reverse("infrastructure:region_toggle", kwargs={"pk": 1})

        self.assertIn("/regions/1/toggle/", url)

    def test_region_toggle_rejects_uuid(self) -> None:
        with self.assertRaises(NoReverseMatch):
            reverse(
                "infrastructure:region_toggle",
                kwargs={"pk": "550e8400-e29b-41d4-a716-446655440000"},
            )


class TestNoUUIDPatternsInInfrastructureURLs(TestCase):
    """Regression guard: no infrastructure URL should use <uuid:pk>.

    All infrastructure models use integer auto-incrementing PKs.
    This test reads the URL configuration to catch future regressions.
    """

    def test_no_uuid_pk_in_url_patterns(self) -> None:
        """Infrastructure urlpatterns must not contain <uuid:pk>."""
        for pattern in urlpatterns:
            route = getattr(pattern, "pattern", None)
            route_str = str(route) if route else ""
            with self.subTest(route=route_str):
                self.assertNotIn(
                    "uuid",
                    route_str.lower(),
                    f"URL pattern '{route_str}' uses UUID converter but "
                    f"infrastructure models use integer PKs.",
                )
