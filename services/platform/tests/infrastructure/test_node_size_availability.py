"""A node size is offered only in the regions where its provider still sells it."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from apps.infrastructure.models import CloudProvider, NodeSize
from tests.helpers.node_catalogue import make_region

User = get_user_model()


class SizeCreateTests(TestCase):
    def setUp(self) -> None:
        self.client.force_login(User.objects.create_superuser(email="admin@test.com", password="testpass123"))
        self.hetzner = CloudProvider.objects.create(name="Hetzner", provider_type="hetzner", code="het")
        self.other = CloudProvider.objects.create(name="Vultr", provider_type="vultr", code="vul")

    def test_new_size_is_offered_in_every_active_region_of_its_provider(self) -> None:
        hel1 = make_region(self.hetzner, "hel1")
        fsn1 = make_region(self.hetzner, "fsn1")
        make_region(self.hetzner, "nbg1", active=False)
        make_region(self.other, "ewr")
        response = self.client.post(
            reverse("infrastructure:size_create"),
            {
                "provider": self.hetzner.pk, "name": "CX23", "display_name": "2 vCPU / 4GB / 40GB",
                "provider_type_id": "cx23", "vcpus": 2, "memory_gb": 4, "disk_gb": 40,
                "hourly_cost_eur": "0.0100", "monthly_cost_eur": "4.99", "max_domains": 50,
                "max_bandwidth_gb": 1000, "is_active": True, "sort_order": 2,
            },
        )
        self.assertEqual(response.status_code, 302)
        size = NodeSize.objects.get(provider_type_id="cx23")
        self.assertEqual(set(size.available_regions.all()), {hel1, fsn1})
