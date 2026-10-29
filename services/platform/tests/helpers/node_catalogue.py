"""Build node regions and sizes, with the regions each size is offered in."""

from __future__ import annotations

from decimal import Decimal

from apps.infrastructure.models import CloudProvider, NodeRegion, NodeSize


def make_region(provider: CloudProvider, location: str, *, active: bool = True) -> NodeRegion:
    return NodeRegion.objects.create(
        provider=provider, name=location, provider_region_id=location, normalized_code=location[:4],
        country_code="fi", city=location, is_active=active,
    )


def make_size(provider: CloudProvider, type_id: str, *regions: NodeRegion, active: bool = True) -> NodeSize:
    size = NodeSize.objects.create(
        provider=provider, name=type_id.upper(), display_name=type_id, provider_type_id=type_id,
        vcpus=2, memory_gb=4, disk_gb=40, hourly_cost_eur=Decimal("0.0100"), monthly_cost_eur=Decimal("4.99"),
        is_active=active,
    )
    size.available_regions.add(*regions)
    return size
