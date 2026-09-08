"""Deterministic placement policy shared by provisioning and migration."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from .virtualmin_models import VirtualminServer


def order_placement_candidates(
    servers: Iterable[VirtualminServer],
    preferred_region: str | None = None,
    required_tags: Sequence[str] | None = None,
) -> list[VirtualminServer]:
    """Apply hard tag requirements, then region, strict weight, load and UUID."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    required = set(required_tags or ()) | set(
        SettingsService.get_list_setting("provisioning.placement_required_tags", [])
    )
    excluded = set(SettingsService.get_list_setting("provisioning.placement_excluded_tags", []))
    candidates = [server for server in servers if required.issubset(server.tags) and excluded.isdisjoint(server.tags)]
    region = preferred_region.casefold() if preferred_region else None
    return sorted(
        candidates,
        key=lambda server: (
            bool(region and server.region.casefold() != region),
            -server.weight,
            server.current_domains,
            str(server.pk),
        ),
    )
