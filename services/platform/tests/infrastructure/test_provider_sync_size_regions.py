"""The provider sync records, per size, the regions where a new node can still be created."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.test import TestCase

from apps.common.types import Ok
from apps.infrastructure.cloud_gateway import LocationInfo
from apps.infrastructure.hcloud_service import HcloudService
from apps.infrastructure.models import CloudProvider, NodeRegion, NodeSize
from apps.infrastructure.provider_sync import sync_hetzner_provider, sync_vultr_provider
from tests.helpers.node_catalogue import make_region, make_size
from tests.helpers.recorded_hcloud import CPX11, CPX22, CX11, CX23, RecordedHcloudTransport, location


class HetznerSizeRegionSyncTests(TestCase):
    def setUp(self) -> None:
        self.provider = CloudProvider.objects.create(name="Hetzner Cloud", provider_type="hetzner", code="het")

    def sync(self, transport: RecordedHcloudTransport, *, dry_run: bool = False) -> Any:
        service = HcloudService(token="fixture-token")
        with (
            patch.object(service.client._client, "request", transport),
            patch("apps.infrastructure.hcloud_service.get_hcloud_service", return_value=service),
        ):
            return sync_hetzner_provider(token="fixture-token", dry_run=dry_run)

    def regions_of(self, type_id: str) -> set[str]:
        size = NodeSize.objects.get(provider=self.provider, provider_type_id=type_id)
        return set(size.available_regions.values_list("provider_region_id", flat=True))

    def test_sizes_are_offered_only_where_hetzner_still_sells_them(self) -> None:
        hel1 = make_region(self.provider, "hel1")
        make_size(self.provider, "cpx11", hel1)  # Backfilled with every region before the first sync.
        result = self.sync(RecordedHcloudTransport([CPX11, CX23, CPX22, CX11]))
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(self.regions_of("cpx11"), {"ash", "hil"})
        self.assertEqual(self.regions_of("cx23"), {"fsn1", "nbg1", "hel1"})
        self.assertEqual(self.regions_of("cpx22"), {"fsn1", "nbg1", "hel1", "sin"})
        self.assertFalse(NodeSize.objects.filter(provider_type_id="cx11").exists())
        # Matched on Hetzner's own location name, not the hostname code ("ash" is normalized to "ash1").
        ash = NodeRegion.objects.get(provider=self.provider, provider_region_id="ash")
        self.assertEqual(ash.normalized_code, "ash1")

    def test_size_with_no_usable_region_is_withdrawn(self) -> None:
        hel1 = make_region(self.provider, "hel1")
        make_size(self.provider, "cx11", hel1)
        result = self.sync(RecordedHcloudTransport([CX23, CX11]))
        self.assertTrue(result.is_ok(), result)
        cx11 = NodeSize.objects.get(provider_type_id="cx11")
        self.assertFalse(cx11.is_active)
        self.assertEqual(self.regions_of("cx11"), set())
        self.assertEqual(NodeSize.offered_in(hel1).get().provider_type_id, "cx23")

    def test_types_sold_only_outside_known_locations_change_nothing(self) -> None:
        hel1 = make_region(self.provider, "hel1")
        make_size(self.provider, "cx23", hel1)
        result = self.sync(RecordedHcloudTransport([CPX11], locations=[location("hel1"), location("fsn1")]))
        self.assertTrue(result.is_err())
        self.assertIn("no server type", result.unwrap_err())
        self.assertEqual(self.regions_of("cx23"), {"hel1"})
        self.assertTrue(NodeSize.objects.get(provider_type_id="cx23").is_active)
        self.assertFalse(NodeSize.objects.filter(provider_type_id="cpx11").exists())
        self.assertFalse(NodeRegion.objects.filter(provider_region_id="fsn1").exists())

    def test_empty_catalogue_changes_nothing(self) -> None:
        hel1 = make_region(self.provider, "hel1")
        make_size(self.provider, "cx23", hel1)
        result = self.sync(RecordedHcloudTransport([]))
        self.assertTrue(result.is_err())
        self.assertTrue(NodeSize.objects.get(provider_type_id="cx23").is_active)
        self.assertEqual(self.regions_of("cx23"), {"hel1"})
        self.assertEqual(NodeRegion.objects.filter(provider=self.provider).count(), 1)

    def test_failure_while_applying_leaves_no_partial_write(self) -> None:
        make_region(self.provider, "hel1")
        with patch("apps.infrastructure.provider_sync._ensure_panel_types", side_effect=RuntimeError("disk full")):
            result = self.sync(RecordedHcloudTransport([CX23]))
        self.assertTrue(result.is_err())
        self.assertFalse(NodeSize.objects.filter(provider_type_id="cx23").exists())
        self.assertEqual(NodeRegion.objects.filter(provider=self.provider).count(), 1)

    def test_dry_run_writes_no_sizes_regions_or_links(self) -> None:
        hel1 = make_region(self.provider, "hel1")
        make_size(self.provider, "cpx11", hel1)
        result = self.sync(RecordedHcloudTransport([CPX11, CX23]), dry_run=True)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(self.regions_of("cpx11"), {"hel1"})
        self.assertFalse(NodeSize.objects.filter(provider_type_id="cx23").exists())
        self.assertEqual(NodeRegion.objects.filter(provider=self.provider).count(), 1)


class OtherProviderSizeRegionSyncTests(TestCase):
    def test_sizes_keep_every_active_region_of_a_provider_without_location_data(self) -> None:
        provider = CloudProvider.objects.create(name="Vultr", provider_type="vultr", code="vul")
        make_region(provider, "sgp", active=False)
        service = _VultrCatalogue()
        with patch("apps.infrastructure.vultr_service.get_vultr_service", return_value=service):
            result = sync_vultr_provider(token="fixture-token")
        self.assertTrue(result.is_ok(), result)
        size = NodeSize.objects.get(provider=provider, provider_type_id="vc2-1c-1gb")
        self.assertEqual(set(size.available_regions.values_list("provider_region_id", flat=True)), {"ewr", "fra"})


class _VultrCatalogue:
    """The two Vultr listings the sync reads, in the shapes VultrService returns."""

    def get_locations(self) -> Ok[list[LocationInfo]]:
        return Ok([LocationInfo(name="ewr", country="US", city="New Jersey"), LocationInfo(name="fra", country="DE")])

    def _request(self, method: str, path: str, **kwargs: object) -> Any:
        return _JsonResponse(
            {
                "plans": [
                    {"id": "vc2-1c-1gb", "vcpu_count": 1, "ram": 1024, "disk": 25, "monthly_cost": 5,
                     "locations": ["ewr", "fra"]},
                ],
                "meta": {"links": {"next": ""}},
            }
        )


class _JsonResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload
