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
    AWS_REGION_CODE_MAP,
    SyncResult,
    _ensure_panel_types,
    _max_domains_for_memory,
    sync_aws_provider,
    sync_digitalocean_provider,
    sync_hetzner_provider,
    sync_vultr_provider,
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
    vcpus: int = 3,
    memory_gb: float = 4.0,
    disk_gb: int = 80,
    available: bool = True,
    price_monthly: float = 5.39,
) -> mock.Mock:
    st = mock.Mock()
    st.name = name
    st.vcpus = vcpus
    st.memory_gb = memory_gb
    st.disk_gb = disk_gb
    st.available = available
    st.price_monthly = price_monthly
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


@mock.patch("apps.infrastructure.hcloud_service.get_hcloud_service")
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
                _make_mock_server_type("cpx21", available=True),
                _make_mock_server_type("cx11", available=False),
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
                    "cpx41", vcpus=8, memory_gb=16, disk_gb=240,
                    price_monthly=18.59,
                )
            ],
        )

        sync_hetzner_provider(token="fake")

        size = NodeSize.objects.get(provider_type_id="cpx41")
        self.assertEqual(size.monthly_cost_eur, Decimal("18.59"))
        # hourly = 18.59 / 730 = 0.025465... rounded to 4 decimal places
        self.assertEqual(size.hourly_cost_eur, (Decimal("18.59") / 730).quantize(Decimal("0.0001")))
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


class TestSyncResult(TestCase):
    """Tests for SyncResult dataclass."""

    def test_sync_result_summary_format(self):
        """Summary string follows expected format."""
        result = SyncResult(
            provider_type="test",
            regions_created=2,
            regions_updated=1,
            regions_deactivated=0,
            sizes_created=5,
            sizes_updated=3,
            sizes_deactivated=1,
            panels_ensured=1,
        )
        summary = result.summary
        self.assertIn("Regions: +2/~1/-0", summary)
        self.assertIn("Sizes: +5/~3/-1", summary)
        self.assertIn("Panels: 1", summary)

    def test_sync_result_success_property(self):
        """success is True only when errors list is empty."""
        result = SyncResult(provider_type="test")
        self.assertTrue(result.success)

        result.errors.append("something went wrong")
        self.assertFalse(result.success)


@mock.patch("apps.infrastructure.aws_service.get_aws_service")
class TestSyncAWSProvider(TestCase):
    """Tests for sync_aws_provider — especially C6 (normalized_code max_length=4)."""

    def test_sync_aws_normalized_code_fits_max_length(self, mock_get_svc):
        """AWS region codes like 'us-east-1a' must be mapped to 4-char codes (C6 fix)."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        # Simulate an AZ name like "us-east-1a" — 10 chars, way over max_length=4
        svc.get_locations.return_value = mock.Mock(
            is_err=lambda: False,
            unwrap=lambda: [_make_mock_location("us-east-1a", "US East (N. Virginia)", "US", "Virginia")],
        )
        svc.get_server_types.return_value = mock.Mock(is_err=lambda: False, unwrap=list)

        result = sync_aws_provider(token="fake-creds")

        self.assertTrue(result.is_ok())
        region = NodeRegion.objects.get(provider_region_id="us-east-1a")
        # Must fit max_length=4
        self.assertLessEqual(len(region.normalized_code), 4)
        self.assertEqual(region.normalized_code, "use1")

    def test_sync_aws_happy_path(self, mock_get_svc):
        """Full AWS sync creates provider, regions, and sizes."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(
            is_err=lambda: False,
            unwrap=lambda: [
                _make_mock_location("eu-central-1a", "EU Central", "DE", "Frankfurt"),
            ],
        )
        svc.get_server_types.return_value = mock.Mock(
            is_err=lambda: False,
            unwrap=lambda: [
                mock.Mock(name="t3.micro", vcpus=2, memory_gb=1.0, disk_gb=0, price_monthly=0, available=True),
            ],
        )

        result = sync_aws_provider(token="fake-creds")

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data.provider_type, "aws")
        self.assertEqual(data.regions_created, 1)
        provider = CloudProvider.objects.get(provider_type="aws")
        self.assertEqual(provider.code, "aws")

    def test_sync_aws_regions_api_failure(self, mock_get_svc):
        """Failure fetching AWS AZs returns Err."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(
            is_err=lambda: True,
            unwrap_err=lambda: "AccessDenied",
        )

        result = sync_aws_provider(token="bad-creds")

        self.assertTrue(result.is_err())
        self.assertIn("Failed to fetch AZs", result.unwrap_err())


class TestAWSRegionCodeMap(TestCase):
    """Verify all AWS_REGION_CODE_MAP values fit max_length=4."""

    def test_all_codes_fit_max_length(self):
        for region, code in AWS_REGION_CODE_MAP.items():
            self.assertLessEqual(
                len(code), 4,
                f"AWS region '{region}' maps to '{code}' which exceeds max_length=4",
            )

    def test_no_duplicate_codes(self):
        codes = list(AWS_REGION_CODE_MAP.values())
        self.assertEqual(len(codes), len(set(codes)), "Duplicate normalized codes found")


@mock.patch("apps.infrastructure.digitalocean_service.get_digitalocean_service")
class TestSyncDigitalOceanProvider(TestCase):
    """Tests for sync_digitalocean_provider — including M7 (code 'dgo')."""

    def test_sync_digitalocean_provider_code_is_3_chars(self, mock_get_svc):
        """DigitalOcean provider code must be 3 chars ('dgo'), not 2 ('do') — M7 fix."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(is_err=lambda: False, unwrap=list)
        svc.client.sizes.list.return_value = {"sizes": []}

        sync_digitalocean_provider(token="fake")

        provider = CloudProvider.objects.get(provider_type="digitalocean")
        self.assertEqual(provider.code, "dgo")
        self.assertEqual(len(provider.code), 3)

    def test_sync_digitalocean_happy_path(self, mock_get_svc):
        """Full DigitalOcean sync creates provider and regions."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(
            is_err=lambda: False,
            unwrap=lambda: [_make_mock_location("nyc1", "New York 1", "US", "New York")],
        )
        svc.client.sizes.list.return_value = {"sizes": []}

        result = sync_digitalocean_provider(token="fake")

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data.provider_type, "digitalocean")
        self.assertEqual(data.regions_created, 1)

    def test_sync_digitalocean_regions_api_failure(self, mock_get_svc):
        """Failure fetching DO regions returns Err."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(
            is_err=lambda: True,
            unwrap_err=lambda: "unauthorized",
        )

        result = sync_digitalocean_provider(token="bad-token")

        self.assertTrue(result.is_err())
        self.assertIn("Failed to fetch regions", result.unwrap_err())


@mock.patch("apps.infrastructure.vultr_service.get_vultr_service")
class TestSyncVultrProvider(TestCase):
    """Tests for sync_vultr_provider — including M5 (no private _request usage)."""

    def test_sync_vultr_happy_path(self, mock_get_svc):
        """Full Vultr sync creates provider and regions."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(
            is_err=lambda: False,
            unwrap=lambda: [_make_mock_location("ewr", "New Jersey", "US", "New Jersey")],
        )
        # Mock the session.get call (our M5 fix uses session directly)
        mock_resp = mock.Mock()
        mock_resp.json.return_value = {"plans": []}
        mock_resp.raise_for_status = mock.Mock()
        svc.session.get.return_value = mock_resp

        result = sync_vultr_provider(token="fake")

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data.provider_type, "vultr")
        self.assertEqual(data.regions_created, 1)

    def test_sync_vultr_uses_public_api_not_private(self, mock_get_svc):
        """Vultr sync must NOT call vultr_svc._request() (M5 fix)."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(is_err=lambda: False, unwrap=list)
        mock_resp = mock.Mock()
        mock_resp.json.return_value = {"plans": []}
        mock_resp.raise_for_status = mock.Mock()
        svc.session.get.return_value = mock_resp

        sync_vultr_provider(token="fake")

        # _request should NOT have been called
        svc._request.assert_not_called()
        # session.get SHOULD have been called (public attribute)
        svc.session.get.assert_called_once()

    def test_sync_vultr_regions_api_failure(self, mock_get_svc):
        """Failure fetching Vultr regions returns Err."""
        svc = mock.Mock()
        mock_get_svc.return_value = svc
        svc.get_locations.return_value = mock.Mock(
            is_err=lambda: True,
            unwrap_err=lambda: "forbidden",
        )

        result = sync_vultr_provider(token="bad-key")

        self.assertTrue(result.is_err())
        self.assertIn("Failed to fetch regions", result.unwrap_err())
