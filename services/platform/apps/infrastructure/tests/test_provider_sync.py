"""
Tests for provider_sync.py

Tests the sync_hetzner_provider function that synchronizes Hetzner catalog
data into CloudProvider, NodeRegion, NodeSize, and PanelType records.
All hcloud API calls are mocked via HcloudService.
"""

from __future__ import annotations

from decimal import Decimal
from unittest import mock

from django.test import TestCase

from apps.infrastructure.models import CloudProvider, NodeRegion, NodeSize, PanelType
from apps.infrastructure.provider_sync import (
    _ensure_panel_types,
    _max_domains_for_memory,
    sync_hetzner_provider,
)


def _make_mock_location(name: str = "fsn1", description: str = "Falkenstein", country: str = "DE", city: str = "Falkenstein") -> mock.Mock:
    loc = mock.Mock()
    loc.name = name
    loc.description = description
    loc.country = country
    loc.city = city
    return loc


def _make_mock_server_type(  # noqa: PLR0913
    name: str = "cpx21",
    cores: int = 3,
    memory: float = 4.0,
    disk: int = 80,
    deprecated: bool = False,
    prices: list | None = None,
) -> mock.Mock:
    st = mock.Mock()
    st.name = name
    st.cores = cores
    st.memory = memory
    st.disk = disk
    st.deprecated = deprecated
    st.prices = prices or [
        {"location": "fsn1", "price_hourly": {"gross": "0.0080"}, "price_monthly": {"gross": "5.39"}},
    ]
    return st


class TestMaxDomainsForMemory(TestCase):
    """Tests for the _max_domains_for_memory helper."""

    def test_small_memory(self):
        self.assertEqual(_max_domains_for_memory(1), 25)
        self.assertEqual(_max_domains_for_memory(2), 25)

    def test_4gb(self):
        self.assertEqual(_max_domains_for_memory(4), 50)

    def test_8gb(self):
        self.assertEqual(_max_domains_for_memory(8), 100)

    def test_16gb(self):
        self.assertEqual(_max_domains_for_memory(16), 200)

    def test_32gb_and_above(self):
        self.assertEqual(_max_domains_for_memory(32), 500)
        self.assertEqual(_max_domains_for_memory(64), 500)

    def test_boundary_values(self):
        self.assertEqual(_max_domains_for_memory(3), 25)
        self.assertEqual(_max_domains_for_memory(7), 50)
        self.assertEqual(_max_domains_for_memory(15), 100)
        self.assertEqual(_max_domains_for_memory(31), 200)


class TestEnsurePanelTypes(TestCase):
    """Tests for _ensure_panel_types helper."""

    def test_creates_virtualmin_panel(self):
        count = _ensure_panel_types(dry_run=False)

        self.assertEqual(count, 1)
        panel = PanelType.objects.get(name="Virtualmin GPL")
        self.assertEqual(panel.panel_type, "virtualmin")
        self.assertEqual(panel.version, "7.10.0")
        self.assertEqual(panel.ansible_playbook, "virtualmin.yml")

    def test_idempotent(self):
        """Running twice does not create duplicates."""
        _ensure_panel_types(dry_run=False)
        count = _ensure_panel_types(dry_run=False)

        self.assertEqual(count, 0)
        self.assertEqual(PanelType.objects.filter(name="Virtualmin GPL").count(), 1)

    def test_dry_run_creates_nothing(self):
        count = _ensure_panel_types(dry_run=True)

        self.assertEqual(count, 1)  # reports what it would do
        self.assertEqual(PanelType.objects.count(), 0)


@mock.patch("apps.infrastructure.provider_sync.get_hcloud_service")
class TestSyncHetznerProvider(TestCase):
    """Tests for sync_hetzner_provider function."""

    def test_creates_provider_and_records(self, mock_get_svc):
        """First sync creates provider, regions, sizes, and panels."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(
            is_err=lambda: False,
            unwrap=lambda: [_make_mock_location("fsn1"), _make_mock_location("nbg1", "Nuremberg", "DE", "Nuremberg")],
        )
        svc.get_server_types.return_value = mock.Mock(
            is_err=lambda: False,
            unwrap=lambda: [_make_mock_server_type("cpx21", 3, 4, 80)],
        )

        result = sync_hetzner_provider(token="fake")

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data.provider_type, "hetzner")
        self.assertEqual(data.regions_created, 2)
        self.assertEqual(data.sizes_created, 1)
        self.assertTrue(data.success)

        # Verify DB records
        provider = CloudProvider.objects.get(provider_type="hetzner")
        self.assertEqual(provider.code, "het")
        self.assertTrue(provider.is_active)
        self.assertEqual(NodeRegion.objects.filter(provider=provider).count(), 2)
        self.assertEqual(NodeSize.objects.filter(provider=provider).count(), 1)

    def test_updates_existing_records(self, mock_get_svc):
        """Second sync updates existing records (idempotency)."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        locations = [_make_mock_location("fsn1")]
        server_types = [_make_mock_server_type("cpx21")]
        svc.get_locations.return_value = mock.Mock(is_err=lambda: False, unwrap=lambda: locations)
        svc.get_server_types.return_value = mock.Mock(is_err=lambda: False, unwrap=lambda: server_types)

        # First sync
        sync_hetzner_provider(token="fake")
        # Second sync
        result = sync_hetzner_provider(token="fake")

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data.regions_created, 0)
        self.assertEqual(data.regions_updated, 1)
        self.assertEqual(data.sizes_created, 0)
        self.assertEqual(data.sizes_updated, 1)

    def test_deactivates_removed_regions(self, mock_get_svc):
        """Regions no longer in API get deactivated."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_server_types.return_value = mock.Mock(is_err=lambda: False, unwrap=list)

        # First sync with two locations
        svc.get_locations.return_value = mock.Mock(
            is_err=lambda: False,
            unwrap=lambda: [_make_mock_location("fsn1"), _make_mock_location("nbg1", "Nuremberg")],
        )
        sync_hetzner_provider(token="fake")
        self.assertEqual(NodeRegion.objects.filter(is_active=True).count(), 2)

        # Second sync with only one location
        svc.get_locations.return_value = mock.Mock(
            is_err=lambda: False,
            unwrap=lambda: [_make_mock_location("fsn1")],
        )
        result = sync_hetzner_provider(token="fake")

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap().regions_deactivated, 1)
        self.assertEqual(NodeRegion.objects.filter(is_active=True).count(), 1)
        self.assertEqual(NodeRegion.objects.filter(is_active=False).count(), 1)

    def test_deactivates_removed_sizes(self, mock_get_svc):
        """Sizes no longer in API get deactivated."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(is_err=lambda: False, unwrap=list)

        # First sync with two sizes
        svc.get_server_types.return_value = mock.Mock(
            is_err=lambda: False,
            unwrap=lambda: [_make_mock_server_type("cpx21"), _make_mock_server_type("cpx31", 4, 8, 160)],
        )
        sync_hetzner_provider(token="fake")
        self.assertEqual(NodeSize.objects.filter(is_active=True).count(), 2)

        # Second sync with only one size
        svc.get_server_types.return_value = mock.Mock(
            is_err=lambda: False,
            unwrap=lambda: [_make_mock_server_type("cpx21")],
        )
        result = sync_hetzner_provider(token="fake")

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap().sizes_deactivated, 1)

    def test_skips_deprecated_server_types(self, mock_get_svc):
        """Deprecated server types are skipped."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(is_err=lambda: False, unwrap=list)
        svc.get_server_types.return_value = mock.Mock(
            is_err=lambda: False,
            unwrap=lambda: [
                _make_mock_server_type("cpx21", deprecated=False),
                _make_mock_server_type("cx11", deprecated=True),
            ],
        )

        result = sync_hetzner_provider(token="fake")

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap().sizes_created, 1)
        self.assertEqual(NodeSize.objects.count(), 1)

    def test_dry_run_creates_no_records(self, mock_get_svc):
        """Dry-run mode reports changes without writing to DB."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(
            is_err=lambda: False, unwrap=lambda: [_make_mock_location("fsn1")]
        )
        svc.get_server_types.return_value = mock.Mock(
            is_err=lambda: False, unwrap=lambda: [_make_mock_server_type("cpx21")]
        )

        result = sync_hetzner_provider(token="fake", dry_run=True)

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data.regions_created, 1)  # reported
        self.assertEqual(data.sizes_created, 1)  # reported
        # But nothing actually in DB (except provider created before dry_run logic)
        self.assertEqual(NodeRegion.objects.count(), 0)
        self.assertEqual(NodeSize.objects.count(), 0)

    def test_locations_api_failure(self, mock_get_svc):
        """Failure fetching locations returns Err."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(
            is_err=lambda: True,
            unwrap_err=lambda: "unauthorized",
        )

        result = sync_hetzner_provider(token="bad-token")

        self.assertTrue(result.is_err())
        self.assertIn("Failed to fetch locations", result.unwrap_err())

    def test_server_types_api_failure(self, mock_get_svc):
        """Failure fetching server types returns Err."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(is_err=lambda: False, unwrap=list)
        svc.get_server_types.return_value = mock.Mock(
            is_err=lambda: True,
            unwrap_err=lambda: "connection reset",
        )

        result = sync_hetzner_provider(token="fake")

        self.assertTrue(result.is_err())
        self.assertIn("Failed to fetch server types", result.unwrap_err())

    def test_pricing_extraction(self, mock_get_svc):
        """Server type pricing is correctly extracted from fsn1 entry."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(is_err=lambda: False, unwrap=list)
        svc.get_server_types.return_value = mock.Mock(
            is_err=lambda: False,
            unwrap=lambda: [
                _make_mock_server_type(
                    "cpx41", 8, 16, 240,
                    prices=[
                        {"location": "nbg1", "price_hourly": {"gross": "0.0300"}, "price_monthly": {"gross": "19.99"}},
                        {"location": "fsn1", "price_hourly": {"gross": "0.0280"}, "price_monthly": {"gross": "18.59"}},
                    ],
                )
            ],
        )

        sync_hetzner_provider(token="fake")

        size = NodeSize.objects.get(provider_type_id="cpx41")
        self.assertEqual(size.hourly_cost_eur, Decimal("0.0280"))
        self.assertEqual(size.monthly_cost_eur, Decimal("18.59"))
        self.assertEqual(size.max_domains, 200)  # 16GB -> 200

    def test_max_domains_set_from_memory(self, mock_get_svc):
        """max_domains on NodeSize is derived from memory_gb."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(is_err=lambda: False, unwrap=list)
        svc.get_server_types.return_value = mock.Mock(
            is_err=lambda: False,
            unwrap=lambda: [_make_mock_server_type("cpx11", 2, 2, 40)],
        )

        sync_hetzner_provider(token="fake")

        size = NodeSize.objects.get(provider_type_id="cpx11")
        self.assertEqual(size.max_domains, 25)  # 2GB -> 25
