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
from typing import TYPE_CHECKING, Any

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.infrastructure.aws_service import AWSService
    from apps.infrastructure.digitalocean_service import DigitalOceanService
    from apps.infrastructure.hcloud_service import HcloudService
    from apps.infrastructure.models import CloudProvider
    from apps.infrastructure.vultr_service import VultrService

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
    from apps.infrastructure.hcloud_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        get_hcloud_service,  # Circular: cross-app  # Deferred: avoids circular import
    )
    from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        CloudProvider,  # Circular: cross-app  # Deferred: avoids circular import
    )

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
    from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        NodeRegion,  # Circular: cross-app  # Deferred: avoids circular import
    )

    locations_result = hcloud_svc.get_locations()
    if locations_result.is_err():
        return f"Failed to fetch locations: {locations_result.unwrap_err()}"

    locations = locations_result.unwrap()
    seen_region_ids: set[str] = set()

    for loc in locations:
        loc_name = str(loc.name)
        seen_region_ids.add(loc_name)
        loc_info = HETZNER_LOCATION_MAP.get(loc_name, {})
        normalized_code = loc_info.get("normalized_code", loc_name[:4])
        country_code = loc_info.get("country_code", str(loc.country or "xx"))
        city = loc_info.get("city", str(loc.city or loc.description or loc_name))

        if dry_run:
            logger.info(f"  [DRY-RUN] Would upsert region: {loc_name} ({city}, {country_code})")
            result.regions_created += 1
            continue

        _, created = NodeRegion.objects.update_or_create(
            provider=provider,
            provider_region_id=loc_name,
            defaults={
                "name": str(loc.description or loc_name),
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
    from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        NodeSize,  # Circular: cross-app  # Deferred: avoids circular import
    )

    types_result = hcloud_svc.get_server_types()
    if types_result.is_err():
        return f"Failed to fetch server types: {types_result.unwrap_err()}"

    server_types = types_result.unwrap()
    seen_type_ids: set[str] = set()

    for st in server_types:
        # Skip deprecated types (not available = deprecated)
        if not st.available:
            continue

        st_name = str(st.name)
        seen_type_ids.add(st_name)

        # Extract EUR pricing from price_monthly (float from ServerTypeInfo)
        monthly_eur = Decimal(str(st.price_monthly)) if st.price_monthly else Decimal("0")
        hourly_eur = (monthly_eur / 730).quantize(Decimal("0.0001")) if monthly_eur else Decimal("0")

        # Determine max_domains based on memory
        memory_gb = int(st.memory_gb or 0)
        max_domains = _max_domains_for_memory(memory_gb)

        display_name = f"{st.vcpus} vCPU / {memory_gb}GB RAM / {st.disk_gb}GB"

        if dry_run:
            logger.info(f"  [DRY-RUN] Would upsert size: {st_name} ({display_name}, {monthly_eur} EUR/mo)")
            result.sizes_created += 1
            continue

        _, created = NodeSize.objects.update_or_create(
            provider=provider,
            provider_type_id=st_name,
            defaults={
                "name": st_name.upper(),
                "display_name": display_name,
                "vcpus": st.vcpus or 0,
                "memory_gb": memory_gb,
                "disk_gb": st.disk_gb or 0,
                "hourly_cost_eur": hourly_eur,
                "monthly_cost_eur": monthly_eur,
                "max_domains": max_domains,
                "is_active": True,
                "sort_order": st.vcpus or 0,
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


# DigitalOcean region → normalized code + country mapping
DIGITALOCEAN_REGION_MAP: dict[str, dict[str, str]] = {
    "nyc1": {"normalized_code": "nyc1", "country_code": "us", "city": "New York"},
    "nyc3": {"normalized_code": "nyc3", "country_code": "us", "city": "New York"},
    "sfo3": {"normalized_code": "sfo3", "country_code": "us", "city": "San Francisco"},
    "ams3": {"normalized_code": "ams3", "country_code": "nl", "city": "Amsterdam"},
    "fra1": {"normalized_code": "fra1", "country_code": "de", "city": "Frankfurt"},
    "sgp1": {"normalized_code": "sgp1", "country_code": "sg", "city": "Singapore"},
    "lon1": {"normalized_code": "lon1", "country_code": "gb", "city": "London"},
    "tor1": {"normalized_code": "tor1", "country_code": "ca", "city": "Toronto"},
    "blr1": {"normalized_code": "blr1", "country_code": "in", "city": "Bangalore"},
    "syd1": {"normalized_code": "syd1", "country_code": "au", "city": "Sydney"},
}


def sync_digitalocean_provider(token: str, dry_run: bool = False) -> Result[SyncResult, str]:
    """
    Sync DigitalOcean catalog data into the database.

    Fetches regions and sizes from the DigitalOcean API and upserts
    them into NodeRegion and NodeSize.

    Args:
        token: DigitalOcean API token
        dry_run: If True, don't write to database

    Returns:
        Result with SyncResult or error
    """
    from apps.infrastructure.digitalocean_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        get_digitalocean_service,  # Circular: cross-app
    )
    from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        CloudProvider,  # Circular: cross-app  # Deferred: avoids circular import
    )

    result = SyncResult(provider_type="digitalocean")

    try:
        provider, created = CloudProvider.objects.update_or_create(
            provider_type="digitalocean",
            defaults={
                "name": "DigitalOcean",
                "code": "dgo",
                "is_active": True,
                "credential_identifier": "do_token",
            },
        )
        if created:
            logger.info("✅ [ProviderSync] Created DigitalOcean provider record")

        do_svc = get_digitalocean_service(token)

        # Sync regions → NodeRegion
        sync_err = _sync_do_regions(do_svc, provider, result, dry_run)
        if sync_err is not None:
            return Err(sync_err)

        # Sync sizes → NodeSize
        sync_err = _sync_do_sizes(do_svc, provider, result, dry_run)
        if sync_err is not None:
            return Err(sync_err)

        result.panels_ensured = _ensure_panel_types(dry_run=dry_run)

        logger.info(f"✅ [ProviderSync] DigitalOcean sync complete: {result.summary}")
        return Ok(result)

    except Exception as e:
        logger.error(f"🔥 [ProviderSync] DigitalOcean sync failed: {e}")
        result.errors.append(str(e))
        return Err(f"DigitalOcean sync failed: {e}")


def _sync_do_regions(
    do_svc: DigitalOceanService,
    provider: CloudProvider,
    result: SyncResult,
    dry_run: bool,
) -> str | None:
    """Sync DigitalOcean regions into NodeRegion records. Returns error string or None."""
    from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        NodeRegion,  # Circular: cross-app  # Deferred: avoids circular import
    )

    locations_result = do_svc.get_locations()
    if locations_result.is_err():
        return f"Failed to fetch regions: {locations_result.unwrap_err()}"

    locations = locations_result.unwrap()
    seen_region_ids: set[str] = set()

    for loc in locations:
        loc_name = str(loc.name)
        seen_region_ids.add(loc_name)
        loc_info = DIGITALOCEAN_REGION_MAP.get(loc_name, {})
        normalized_code = loc_info.get("normalized_code", loc_name[:4])
        country_code = loc_info.get("country_code", str(loc.country or "xx"))
        city = loc_info.get("city", str(loc.city or loc.description or loc_name))

        if dry_run:
            logger.info(f"  [DRY-RUN] Would upsert region: {loc_name} ({city}, {country_code})")
            result.regions_created += 1
            continue

        _, created = NodeRegion.objects.update_or_create(
            provider=provider,
            provider_region_id=loc_name,
            defaults={
                "name": loc.description or loc_name,
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

    if not dry_run:
        deactivated = (
            NodeRegion.objects.filter(provider=provider, is_active=True)
            .exclude(provider_region_id__in=seen_region_ids)
            .update(is_active=False)
        )
        result.regions_deactivated = deactivated

    return None


def _sync_do_sizes(
    do_svc: DigitalOceanService,
    provider: CloudProvider,
    result: SyncResult,
    dry_run: bool,
) -> str | None:
    """Sync DigitalOcean sizes into NodeSize records. Returns error string or None."""
    from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        NodeSize,  # Circular: cross-app  # Deferred: avoids circular import
    )

    # Fetch raw size data directly to access pricing fields
    do_page_size = 200
    try:
        raw_sizes: list[dict[str, Any]] = []
        page = 1
        while True:
            response = do_svc.client.sizes.list(per_page=do_page_size, page=page)
            sizes_page = response.get("sizes", [])
            if not sizes_page:
                break
            raw_sizes.extend(s for s in sizes_page if s.get("available", False))
            if len(sizes_page) < do_page_size:
                break
            page += 1
    except Exception as e:
        return f"Failed to fetch sizes: {e}"

    seen_type_ids: set[str] = set()

    for size in raw_sizes:
        size_name = str(size["slug"])
        seen_type_ids.add(size_name)

        vcpus = size.get("vcpus", 0)
        memory_gb = int(size.get("memory", 0) / 1024)
        disk_gb = size.get("disk", 0)
        max_domains = _max_domains_for_memory(memory_gb)
        display_name = f"{vcpus} vCPU / {memory_gb}GB RAM / {disk_gb}GB"

        # Extract pricing from raw API response
        monthly_cost = Decimal(str(size.get("price_monthly", 0)))
        hourly_cost = Decimal(str(size.get("price_hourly", 0)))

        if dry_run:
            logger.info(f"  [DRY-RUN] Would upsert size: {size_name} ({display_name}, ${monthly_cost}/mo)")
            result.sizes_created += 1
            continue

        _, created = NodeSize.objects.update_or_create(
            provider=provider,
            provider_type_id=size_name,
            defaults={
                "name": size_name.upper(),
                "display_name": display_name,
                "vcpus": vcpus,
                "memory_gb": memory_gb,
                "disk_gb": disk_gb,
                "hourly_cost_eur": hourly_cost,
                "monthly_cost_eur": monthly_cost,
                "max_domains": max_domains,
                "is_active": True,
                "sort_order": vcpus,
            },
        )
        if created:
            result.sizes_created += 1
        else:
            result.sizes_updated += 1

    if not dry_run:
        deactivated = (
            NodeSize.objects.filter(provider=provider, is_active=True)
            .exclude(provider_type_id__in=seen_type_ids)
            .update(is_active=False)
        )
        result.sizes_deactivated = deactivated

    return None


# Vultr region → normalized code + country mapping
VULTR_REGION_MAP: dict[str, dict[str, str]] = {
    "ewr": {"normalized_code": "ewr1", "country_code": "us", "city": "New Jersey"},
    "ord": {"normalized_code": "ord1", "country_code": "us", "city": "Chicago"},
    "lax": {"normalized_code": "lax1", "country_code": "us", "city": "Los Angeles"},
    "ams": {"normalized_code": "ams1", "country_code": "nl", "city": "Amsterdam"},
    "fra": {"normalized_code": "fra1", "country_code": "de", "city": "Frankfurt"},
    "sgp": {"normalized_code": "sgp1", "country_code": "sg", "city": "Singapore"},
    "nrt": {"normalized_code": "nrt1", "country_code": "jp", "city": "Tokyo"},
    "syd": {"normalized_code": "syd1", "country_code": "au", "city": "Sydney"},
}


def sync_vultr_provider(token: str, dry_run: bool = False) -> Result[SyncResult, str]:
    """
    Sync Vultr catalog data into the database.

    Fetches regions and plans from the Vultr API and upserts
    them into NodeRegion and NodeSize.

    Args:
        token: Vultr API token
        dry_run: If True, don't write to database

    Returns:
        Result with SyncResult or error
    """
    from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        CloudProvider,  # Circular: cross-app  # Deferred: avoids circular import
    )
    from apps.infrastructure.vultr_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        get_vultr_service,  # Circular: cross-app  # Deferred: avoids circular import
    )

    result = SyncResult(provider_type="vultr")

    try:
        provider, created = CloudProvider.objects.update_or_create(
            provider_type="vultr",
            defaults={
                "name": "Vultr",
                "code": "vlt",
                "is_active": True,
                "credential_identifier": "vultr_api_key",
            },
        )
        if created:
            logger.info("✅ [ProviderSync] Created Vultr provider record")

        vultr_svc = get_vultr_service(token)

        # Sync regions → NodeRegion
        sync_err = _sync_vultr_regions(vultr_svc, provider, result, dry_run)
        if sync_err is not None:
            return Err(sync_err)

        # Sync plans → NodeSize
        sync_err = _sync_vultr_plans(vultr_svc, provider, result, dry_run)
        if sync_err is not None:
            return Err(sync_err)

        result.panels_ensured = _ensure_panel_types(dry_run=dry_run)

        logger.info(f"✅ [ProviderSync] Vultr sync complete: {result.summary}")
        return Ok(result)

    except Exception as e:
        logger.error(f"🔥 [ProviderSync] Vultr sync failed: {e}")
        result.errors.append(str(e))
        return Err(f"Vultr sync failed: {e}")


def _sync_vultr_regions(
    vultr_svc: VultrService,
    provider: CloudProvider,
    result: SyncResult,
    dry_run: bool,
) -> str | None:
    """Sync Vultr regions into NodeRegion records. Returns error string or None."""
    from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        NodeRegion,  # Circular: cross-app  # Deferred: avoids circular import
    )

    locations_result = vultr_svc.get_locations()
    if locations_result.is_err():
        return f"Failed to fetch regions: {locations_result.unwrap_err()}"

    locations = locations_result.unwrap()
    seen_region_ids: set[str] = set()

    for loc in locations:
        loc_name = str(loc.name)
        seen_region_ids.add(loc_name)
        loc_info = VULTR_REGION_MAP.get(loc_name, {})
        normalized_code = loc_info.get("normalized_code", loc_name[:4])
        country_code = loc_info.get("country_code", str(loc.country or "xx"))
        city = loc_info.get("city", str(loc.city or loc.description or loc_name))

        if dry_run:
            logger.info(f"  [DRY-RUN] Would upsert region: {loc_name} ({city}, {country_code})")
            result.regions_created += 1
            continue

        _, created = NodeRegion.objects.update_or_create(
            provider=provider,
            provider_region_id=loc_name,
            defaults={
                "name": loc.description or loc_name,
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

    if not dry_run:
        deactivated = (
            NodeRegion.objects.filter(provider=provider, is_active=True)
            .exclude(provider_region_id__in=seen_region_ids)
            .update(is_active=False)
        )
        result.regions_deactivated = deactivated

    return None


def _sync_vultr_plans(
    vultr_svc: VultrService,
    provider: CloudProvider,
    result: SyncResult,
    dry_run: bool,
) -> str | None:
    """Sync Vultr plans into NodeSize records. Returns error string or None."""
    from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        NodeSize,  # Circular: cross-app  # Deferred: avoids circular import
    )

    # Fetch raw plan data via the service's internal request helper
    # to access pricing fields not exposed by get_server_types()
    try:
        resp = vultr_svc._request("GET", "/plans")  # internal helper, no public API for raw plans
        raw_plans: list[dict[str, Any]] = resp.json().get("plans", [])
    except Exception as e:
        return f"Failed to fetch plans: {e}"

    seen_type_ids: set[str] = set()

    for plan in raw_plans:
        plan_name = str(plan.get("id", ""))
        seen_type_ids.add(plan_name)

        vcpus = plan.get("vcpu_count", 0)
        memory_gb = int(round(plan.get("ram", 0) / 1024, 0))
        disk_gb = plan.get("disk", 0)
        max_domains = _max_domains_for_memory(memory_gb)
        display_name = f"{vcpus} vCPU / {memory_gb}GB RAM / {disk_gb}GB"

        # Extract pricing from raw API response
        monthly_cost = Decimal(str(plan.get("monthly_cost", 0)))
        hourly_cost = Decimal(str(plan.get("hourly_cost", 0)))

        if dry_run:
            logger.info(f"  [DRY-RUN] Would upsert size: {plan_name} ({display_name}, ${monthly_cost}/mo)")
            result.sizes_created += 1
            continue

        _, created = NodeSize.objects.update_or_create(
            provider=provider,
            provider_type_id=plan_name,
            defaults={
                "name": plan_name.upper(),
                "display_name": display_name,
                "vcpus": vcpus,
                "memory_gb": memory_gb,
                "disk_gb": disk_gb,
                "hourly_cost_eur": hourly_cost,
                "monthly_cost_eur": monthly_cost,
                "max_domains": max_domains,
                "is_active": True,
                "sort_order": vcpus,
            },
        )
        if created:
            result.sizes_created += 1
        else:
            result.sizes_updated += 1

    if not dry_run:
        deactivated = (
            NodeSize.objects.filter(provider=provider, is_active=True)
            .exclude(provider_type_id__in=seen_type_ids)
            .update(is_active=False)
        )
        result.sizes_deactivated = deactivated

    return None


def _ensure_panel_types(dry_run: bool = False) -> int:
    """Ensure standard PanelType records exist."""
    from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        PanelType,  # Circular: cross-app  # Deferred: avoids circular import
    )

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


# =============================================================================
# AWS EC2 Provider Sync
# =============================================================================

# AWS region → 4-char normalized code (max_length=4 on NodeRegion.normalized_code)
# Pattern: first letter of each part + digit, e.g. "us-east-1" → "use1"
AWS_REGION_CODE_MAP: dict[str, str] = {
    "us-east-1": "use1",
    "us-east-2": "use2",
    "us-west-1": "usw1",
    "us-west-2": "usw2",
    "eu-west-1": "euw1",
    "eu-west-2": "euw2",
    "eu-west-3": "euw3",
    "eu-central-1": "euc1",
    "eu-central-2": "euc2",
    "eu-north-1": "eun1",
    "eu-south-1": "eus1",
    "ap-southeast-1": "ase1",
    "ap-southeast-2": "ase2",
    "ap-northeast-1": "ane1",
    "ap-northeast-2": "ane2",
    "ap-northeast-3": "ane3",
    "ap-south-1": "aps1",
    "ap-east-1": "ape1",
    "sa-east-1": "sae1",
    "ca-central-1": "cac1",
    "me-south-1": "mes1",
    "af-south-1": "afs1",
}

# Monthly cost estimates for common AWS instance types (USD, us-east-1 on-demand)
AWS_MONTHLY_ESTIMATES: dict[str, Decimal] = {
    "t3.micro": Decimal("7.59"),
    "t3.small": Decimal("15.18"),
    "t3.medium": Decimal("30.37"),
    "t3.large": Decimal("60.74"),
    "t3.xlarge": Decimal("121.47"),
    "m5.large": Decimal("69.12"),
    "m5.xlarge": Decimal("138.24"),
    "c5.large": Decimal("61.20"),
    "c5.xlarge": Decimal("122.40"),
}

# Hours in a month for hourly rate calculation
HOURS_PER_MONTH = 730


def sync_aws_provider(token: str, dry_run: bool = False) -> Result[SyncResult, str]:
    """
    Sync AWS EC2 catalog data into the database.

    Fetches availability zones and instance types from the EC2 API and upserts
    them into NodeRegion and NodeSize.

    Args:
        token: AWS credentials JSON (access_key_id, secret_access_key, region)
        dry_run: If True, don't write to database

    Returns:
        Result with SyncResult or error
    """
    from apps.infrastructure.aws_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        get_aws_service,  # Circular: cross-app  # Deferred: avoids circular import
    )
    from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        CloudProvider,  # Circular: cross-app  # Deferred: avoids circular import
    )

    result = SyncResult(provider_type="aws")

    try:
        provider, created = CloudProvider.objects.update_or_create(
            provider_type="aws",
            defaults={
                "name": "Amazon Web Services",
                "code": "aws",
                "is_active": True,
                "credential_identifier": "aws_credentials",
            },
        )
        if created:
            logger.info("✅ [ProviderSync] Created AWS provider record")

        aws_svc = get_aws_service(token)

        # Sync availability zones → NodeRegion
        sync_err = _sync_aws_regions(aws_svc, provider, result, dry_run)
        if sync_err is not None:
            return Err(sync_err)

        # Sync instance types → NodeSize
        sync_err = _sync_aws_instance_types(aws_svc, provider, result, dry_run)
        if sync_err is not None:
            return Err(sync_err)

        result.panels_ensured = _ensure_panel_types(dry_run=dry_run)

        logger.info(f"✅ [ProviderSync] AWS sync complete: {result.summary}")
        return Ok(result)

    except Exception as e:
        logger.error(f"🔥 [ProviderSync] AWS sync failed: {e}")
        result.errors.append(str(e))
        return Err(f"AWS sync failed: {e}")


def _sync_aws_regions(
    aws_svc: AWSService,
    provider: CloudProvider,
    result: SyncResult,
    dry_run: bool,
) -> str | None:
    """Sync AWS availability zones into NodeRegion records."""
    from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        NodeRegion,  # Circular: cross-app  # Deferred: avoids circular import
    )

    locations_result = aws_svc.get_locations()
    if locations_result.is_err():
        return f"Failed to fetch AZs: {locations_result.unwrap_err()}"

    locations = locations_result.unwrap()
    seen_region_ids: set[str] = set()

    for loc in locations:
        loc_name = str(loc.name)
        seen_region_ids.add(loc_name)
        # Extract region from AZ name (e.g., us-east-1a → us-east-1)
        region_name = loc_name.rstrip("abcdef")
        country_code = "us" if region_name.startswith("us-") else region_name[:2]

        if dry_run:
            logger.info(f"  [DRY-RUN] Would upsert region: {loc_name} ({country_code})")
            result.regions_created += 1
            continue

        # Map AWS region to a 4-char code that fits NodeRegion.normalized_code(max_length=4)
        normalized_code = AWS_REGION_CODE_MAP.get(region_name, region_name[:4])

        _, created = NodeRegion.objects.update_or_create(
            provider=provider,
            provider_region_id=loc_name,
            defaults={
                "name": loc_name,
                "normalized_code": normalized_code,
                "country_code": country_code,
                "city": loc.description or loc_name,
                "is_active": True,
            },
        )
        if created:
            result.regions_created += 1
        else:
            result.regions_updated += 1

    if not dry_run:
        deactivated = (
            NodeRegion.objects.filter(provider=provider, is_active=True)
            .exclude(provider_region_id__in=seen_region_ids)
            .update(is_active=False)
        )
        result.regions_deactivated = deactivated

    return None


def _sync_aws_instance_types(
    aws_svc: AWSService,
    provider: CloudProvider,
    result: SyncResult,
    dry_run: bool,
) -> str | None:
    """Sync AWS instance types into NodeSize records."""
    from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        NodeSize,  # Circular: cross-app  # Deferred: avoids circular import
    )

    types_result = aws_svc.get_server_types()
    if types_result.is_err():
        return f"Failed to fetch instance types: {types_result.unwrap_err()}"

    server_types = types_result.unwrap()
    seen_type_ids: set[str] = set()

    for st in server_types:
        st_name = str(st.name)
        seen_type_ids.add(st_name)

        memory_gb = int(st.memory_gb)
        max_domains = _max_domains_for_memory(memory_gb)
        display_name = f"{st.vcpus} vCPU / {memory_gb}GB RAM"

        # Use estimated pricing if available
        monthly_cost = AWS_MONTHLY_ESTIMATES.get(st_name, Decimal("0"))
        hourly_cost = (monthly_cost / HOURS_PER_MONTH).quantize(Decimal("0.0001")) if monthly_cost else Decimal("0")

        if dry_run:
            logger.info(f"  [DRY-RUN] Would upsert size: {st_name} ({display_name}, ${monthly_cost}/mo)")
            result.sizes_created += 1
            continue

        _, created = NodeSize.objects.update_or_create(
            provider=provider,
            provider_type_id=st_name,
            defaults={
                "name": st_name.upper(),
                "display_name": display_name,
                "vcpus": st.vcpus,
                "memory_gb": memory_gb,
                "disk_gb": st.disk_gb,
                "hourly_cost_eur": hourly_cost,
                "monthly_cost_eur": monthly_cost,
                "max_domains": max_domains,
                "is_active": True,
                "sort_order": st.vcpus,
            },
        )
        if created:
            result.sizes_created += 1
        else:
            result.sizes_updated += 1

    if not dry_run:
        deactivated = (
            NodeSize.objects.filter(provider=provider, is_active=True)
            .exclude(provider_type_id__in=seen_type_ids)
            .update(is_active=False)
        )
        result.sizes_deactivated = deactivated

    return None


# ---------------------------------------------------------------------------
# Eager registration — fires at import time so get_provider_sync_fn() needs
# no dynamic import at call time (eliminates non-literal-import semgrep finding)
# ---------------------------------------------------------------------------
from apps.infrastructure.provider_config import register_sync_fn  # noqa: E402

register_sync_fn("hetzner", sync_hetzner_provider)
register_sync_fn("digitalocean", sync_digitalocean_provider)
register_sync_fn("vultr", sync_vultr_provider)
register_sync_fn("aws", sync_aws_provider)
