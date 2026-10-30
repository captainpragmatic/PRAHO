"""Migration 0004 keeps today's offer: every size is available in its provider's active regions."""

from __future__ import annotations

import importlib
from decimal import Decimal

from django.apps import apps
from django.db import connection
from django.test import TestCase

from apps.infrastructure.models import CloudProvider, NodeRegion, NodeSize

backfill = importlib.import_module(
    "apps.infrastructure.migrations.0004_node_size_available_regions"
).offer_sizes_in_every_active_region


def _region(provider: CloudProvider, location: str, *, active: bool = True) -> NodeRegion:
    return NodeRegion.objects.create(
        provider=provider, name=location, provider_region_id=location, normalized_code=location[:4],
        country_code="de", city=location, is_active=active,
    )


def _size(provider: CloudProvider, type_id: str) -> NodeSize:
    return NodeSize.objects.create(
        provider=provider, name=type_id.upper(), display_name=type_id, provider_type_id=type_id,
        vcpus=2, memory_gb=4, disk_gb=40, hourly_cost_eur=Decimal("0.0100"), monthly_cost_eur=Decimal("4.99"),
    )


class NodeSizeRegionBackfillTests(TestCase):
    def test_each_size_gets_every_active_region_of_its_own_provider(self) -> None:
        hetzner = CloudProvider.objects.create(name="Hetzner", provider_type="hetzner", code="het")
        vultr = CloudProvider.objects.create(name="Vultr", provider_type="vultr", code="vul")
        hel1 = _region(hetzner, "hel1")
        fsn1 = _region(hetzner, "fsn1")
        _region(hetzner, "nbg1", active=False)
        ewr = _region(vultr, "ewr")
        cpx11 = _size(hetzner, "cpx11")
        cx23 = _size(hetzner, "cx23")
        cx23.available_regions.add(hel1)  # An existing link is kept, not duplicated.
        vc2 = _size(vultr, "vc2-1c-1gb")

        # The backfill only writes rows; the editor is never entered, so it works inside the test transaction.
        backfill(apps, connection.schema_editor())

        self.assertEqual(set(cpx11.available_regions.all()), {hel1, fsn1})
        self.assertEqual(set(cx23.available_regions.all()), {hel1, fsn1})
        self.assertEqual(set(vc2.available_regions.all()), {ewr})
