"""
Provider Catalog Sync

Synchronizes cloud provider catalog data (regions, server types, pricing)
from the Hetzner Cloud API into the database. Replaces hardcoded fixture data
with live provider data.

Usage:
    python manage.py sync_providers
    python manage.py sync_providers --provider hetzner --dry-run
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING

from apps.common.types import Err, Ok, Result
from apps.infrastructure.hcloud_service import get_hcloud_service

if TYPE_CHECKING:
    from apps.infrastructure.hcloud_service import HcloudService
    from apps.infrastructure.models import CloudProvider

logger = logging.getLogger(__name__)


# Hetzner location → normalized code + country mapping
HETZNER_LOCATION_MAP: dict[str, dict[str, str]] = {
    "fsn1": {"normalized_code": "fsn1", "country_code": "de", "city": "Falkenstein"},
    "nbg1": {"normalized_code": "nbg1", "country_code": "de", "city": "Nuremberg"},
    "hel1": {"normalized_code": "hel1", "country_code": "fi", "city": "Helsinki"},
    "ash": {"normalized_code": "ash1", "country_code": "us", "city": "Ashburn"},
    "hil": {"normalized_code": "hil1", "country_code": "us", "city": "Hillsboro"},
    "sin": {"normalized_code": "sin1", "country_code": "sg", "city": "Singapore"},
}

# Memory tier thresholds (GB) for max_domains calculation
MEMORY_TIER_XL = 32  # 500 domains
MEMORY_TIER_LG = 16  # 200 domains
MEMORY_TIER_MD = 8  # 100 domains
MEMORY_TIER_SM = 4  # 50 domains


@dataclass
class SyncResult:
    """Result of a provider sync operation."""

    provider_type: str
    regions_created: int = 0
    regions_updated: int = 0
    regions_deactivated: int = 0
    sizes_created: int = 0
    sizes_updated: int = 0
    sizes_deactivated: int = 0
    panels_ensured: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return len(self.errors) == 0

    @property
    def summary(self) -> str:
        return (
            f"Regions: +{self.regions_created}/~{self.regions_updated}/-{self.regions_deactivated} | "
            f"Sizes: +{self.sizes_created}/~{self.sizes_updated}/-{self.sizes_deactivated} | "
            f"Panels: {self.panels_ensured}"
        )


def sync_hetzner_provider(token: str, dry_run: bool = False) -> Result[SyncResult, str]:
    """
    Sync Hetzner Cloud catalog data into the database.

    Fetches locations and server types from the Hetzner API and upserts
    them into NodeRegion and NodeSize. Deactivates entries that no longer
    exist in the API (soft delete).

    Args:
        token: Hetzner Cloud API token
        dry_run: If True, don't write to database

    Returns:
        Result with SyncResult or error
    """
    from apps.infrastructure.models import CloudProvider  # noqa: PLC0415

    result = SyncResult(provider_type="hetzner")

    try:
        # 1. Ensure CloudProvider record exists
        provider, created = CloudProvider.objects.update_or_create(
            provider_type="hetzner",
            defaults={
                "name": "Hetzner Cloud",
                "code": "het",
                "is_active": True,
                "credential_identifier": "hcloud_token",
            },
        )
        if created:
            logger.info("✅ [ProviderSync] Created Hetzner Cloud provider record")

        hcloud_svc = get_hcloud_service(token)

        # 2. Sync locations → NodeRegion
        sync_err = _sync_locations(hcloud_svc, provider, result, dry_run)
        if sync_err is not None:
            return Err(sync_err)

        # 3. Sync server_types → NodeSize
        sync_err = _sync_server_types(hcloud_svc, provider, result, dry_run)
        if sync_err is not None:
            return Err(sync_err)

        # 4. Ensure PanelType records (PRAHO-owned data, not from API)
        result.panels_ensured = _ensure_panel_types(dry_run=dry_run)

        logger.info(f"✅ [ProviderSync] Hetzner sync complete: {result.summary}")
        return Ok(result)

    except Exception as e:
        logger.error(f"🔥 [ProviderSync] Hetzner sync failed: {e}")
        result.errors.append(str(e))
        return Err(f"Hetzner sync failed: {e}")


def _sync_locations(
    hcloud_svc: HcloudService,
    provider: CloudProvider,
    result: SyncResult,
    dry_run: bool,
) -> str | None:
    """Sync Hetzner locations into NodeRegion records. Returns error string or None."""
    from apps.infrastructure.models import NodeRegion  # noqa: PLC0415

    locations_result = hcloud_svc.get_locations()
    if locations_result.is_err():
        return f"Failed to fetch locations: {locations_result.unwrap_err()}"

    locations = locations_result.unwrap()
    seen_region_ids: set[str] = set()

    for loc in locations:
        seen_region_ids.add(loc.name)
        loc_info = HETZNER_LOCATION_MAP.get(loc.name, {})
        normalized_code = loc_info.get("normalized_code", loc.name[:4])
        country_code = loc_info.get("country_code", loc.country or "xx")
        city = loc_info.get("city", loc.city or loc.description or loc.name)

        if dry_run:
            logger.info(f"  [DRY-RUN] Would upsert region: {loc.name} ({city}, {country_code})")
            result.regions_created += 1
            continue

        _, created = NodeRegion.objects.update_or_create(
            provider=provider,
            provider_region_id=loc.name,
            defaults={
                "name": loc.description or loc.name,
                "normalized_code": normalized_code,
                "country_code": country_code,
                "city": city,
                "is_active": True,
            },
        )
        if created:
            result.regions_created += 1
        else:
            result.regions_updated += 1

    # Deactivate regions no longer in API
    if not dry_run:
        deactivated = (
            NodeRegion.objects.filter(
                provider=provider,
                is_active=True,
            )
            .exclude(
                provider_region_id__in=seen_region_ids,
            )
            .update(is_active=False)
        )
        result.regions_deactivated = deactivated

    return None


def _sync_server_types(
    hcloud_svc: HcloudService,
    provider: CloudProvider,
    result: SyncResult,
    dry_run: bool,
) -> str | None:
    """Sync Hetzner server types into NodeSize records. Returns error string or None."""
    from apps.infrastructure.models import NodeSize  # noqa: PLC0415

    types_result = hcloud_svc.get_server_types()
    if types_result.is_err():
        return f"Failed to fetch server types: {types_result.unwrap_err()}"

    server_types = types_result.unwrap()
    seen_type_ids: set[str] = set()

    for st in server_types:
        # Skip deprecated types
        if st.deprecated:
            continue

        seen_type_ids.add(st.name)

        # Extract EUR pricing from the prices list (prefer fsn1, fallback to first)
        hourly_eur, monthly_eur = _extract_pricing(st.prices)

        # Determine max_domains based on memory
        memory_gb = int(st.memory or 0)
        max_domains = _max_domains_for_memory(memory_gb)

        display_name = f"{st.cores} vCPU / {memory_gb}GB RAM / {st.disk}GB"

        if dry_run:
            logger.info(f"  [DRY-RUN] Would upsert size: {st.name} ({display_name}, {monthly_eur} EUR/mo)")
            result.sizes_created += 1
            continue

        _, created = NodeSize.objects.update_or_create(
            provider=provider,
            provider_type_id=st.name,
            defaults={
                "name": st.name.upper(),
                "display_name": display_name,
                "vcpus": st.cores or 0,
                "memory_gb": memory_gb,
                "disk_gb": st.disk or 0,
                "hourly_cost_eur": hourly_eur,
                "monthly_cost_eur": monthly_eur,
                "max_domains": max_domains,
                "is_active": True,
                "sort_order": st.cores or 0,
            },
        )
        if created:
            result.sizes_created += 1
        else:
            result.sizes_updated += 1

    # Deactivate sizes no longer in API
    if not dry_run:
        deactivated = (
            NodeSize.objects.filter(
                provider=provider,
                is_active=True,
            )
            .exclude(
                provider_type_id__in=seen_type_ids,
            )
            .update(is_active=False)
        )
        result.sizes_deactivated = deactivated

    return None


def _extract_pricing(prices: list[dict[str, object]] | None) -> tuple[Decimal, Decimal]:
    """Extract hourly/monthly EUR pricing. Prefers fsn1, falls back to first entry."""
    if not prices:
        return Decimal("0"), Decimal("0")

    chosen = None
    for entry in prices:
        if isinstance(entry, dict):
            if entry.get("location") == "fsn1":
                chosen = entry
                break
            if chosen is None:
                chosen = entry

    if chosen is None:
        return Decimal("0"), Decimal("0")

    price_hourly = chosen.get("price_hourly")
    price_monthly = chosen.get("price_monthly")
    hourly = Decimal(str(price_hourly["gross"])) if isinstance(price_hourly, dict) else Decimal("0")
    monthly = Decimal(str(price_monthly["gross"])) if isinstance(price_monthly, dict) else Decimal("0")
    return hourly, monthly


def _max_domains_for_memory(memory_gb: int) -> int:
    """Determine max_domains default based on server memory."""
    if memory_gb >= MEMORY_TIER_XL:
        return 500
    if memory_gb >= MEMORY_TIER_LG:
        return 200
    if memory_gb >= MEMORY_TIER_MD:
        return 100
    if memory_gb >= MEMORY_TIER_SM:
        return 50
    return 25


def _ensure_panel_types(dry_run: bool = False) -> int:
    """Ensure standard PanelType records exist."""
    from apps.infrastructure.models import PanelType  # noqa: PLC0415

    panels = [
        {
            "name": "Virtualmin GPL",
            "panel_type": "virtualmin",
            "version": "7.10.0",
            "ansible_playbook": "virtualmin.yml",
        },
    ]

    count = 0
    for panel_data in panels:
        if dry_run:
            logger.info(f"  [DRY-RUN] Would ensure panel: {panel_data['name']}")
            count += 1
            continue

        _, created = PanelType.objects.get_or_create(
            name=panel_data["name"],
            defaults={
                "panel_type": panel_data["panel_type"],
                "version": panel_data["version"],
                "ansible_playbook": panel_data["ansible_playbook"],
                "is_active": True,
            },
        )
        if created:
            count += 1

    return count
