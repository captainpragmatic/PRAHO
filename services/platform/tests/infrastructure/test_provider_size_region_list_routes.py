"""Three staff dashboard list pages, found untouched by the route sweep.

`provider_list`, `size_list` and `region_list` each run a real query and render it; a
status-only test would pass identically whether the query returned real rows or an empty
queryset the template silently swallowed. Content is the assertion, per the reported defect
this whole programme traces back to - a 200 that renders nothing computed.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from apps.infrastructure.models import CloudProvider, NodeRegion, NodeSize

User = get_user_model()


class ProviderListRouteTests(TestCase):
    def setUp(self) -> None:
        self.staff = User.objects.create_superuser(email="admin@test.com", password="testpass123")
        self.client.force_login(self.staff)

    def test_a_provider_name_and_code_render(self) -> None:
        CloudProvider.objects.create(
            name="Test Hetzner", provider_type="hetzner", code="het", credential_identifier="cred-1"
        )

        response = self.client.get(reverse("infrastructure:provider_list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Hetzner")
        self.assertContains(response, "HET")

    def test_no_providers_does_not_silently_render_an_empty_page(self) -> None:
        response = self.client.get(reverse("infrastructure:provider_list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Cloud Providers")


class SizeListRouteTests(TestCase):
    def setUp(self) -> None:
        self.staff = User.objects.create_superuser(email="admin@test.com", password="testpass123")
        self.client.force_login(self.staff)
        self.provider = CloudProvider.objects.create(
            name="Test Hetzner", provider_type="hetzner", code="het", credential_identifier="cred-1"
        )

    def test_a_sizes_display_name_and_provider_render(self) -> None:
        NodeSize.objects.create(
            provider=self.provider,
            name="Small",
            display_name="2 vCPU / 4GB",
            provider_type_id="cpx21",
            vcpus=2,
            memory_gb=4,
            disk_gb=40,
            hourly_cost_eur="0.0100",
            monthly_cost_eur="5.00",
        )

        response = self.client.get(reverse("infrastructure:size_list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "2 vCPU / 4GB")
        self.assertContains(response, "Test Hetzner")


class RegionListRouteTests(TestCase):
    def setUp(self) -> None:
        self.staff = User.objects.create_superuser(email="admin@test.com", password="testpass123")
        self.client.force_login(self.staff)
        self.provider = CloudProvider.objects.create(
            name="Test Hetzner", provider_type="hetzner", code="het", credential_identifier="cred-1"
        )

    def test_a_regions_name_and_city_render_grouped_by_provider(self) -> None:
        NodeRegion.objects.create(
            provider=self.provider,
            name="Falkenstein",
            provider_region_id="fsn1",
            normalized_code="fsn1",
            country_code="de",
            city="Falkenstein",
        )

        response = self.client.get(reverse("infrastructure:region_list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Falkenstein")
        self.assertContains(response, "Test Hetzner")
