"""Recorded Hetzner Cloud API shapes, served to the real hcloud SDK through its HTTP seam.

The server type payloads mirror GET /v1/server_types after Hetzner started retiring types per
location (2025-09-24): cpx11 still lists hel1, fsn1, nbg1 and sin, each with a deprecation,
and is still sold in ash and hil.
"""

from __future__ import annotations

import copy
from typing import Any

from hcloud import APIException

_LOCATION_IDS = {"fsn1": 1, "nbg1": 2, "hel1": 3, "ash": 4, "hil": 5, "sin": 6}

_RETIRED = {
    "announced": "2025-09-24T00:00:00+00:00",
    "unavailable_after": "2025-12-31T23:59:59+00:00",
}


def _price(location: str, monthly_gross: str) -> dict[str, Any]:
    return {
        "location": location,
        "price_hourly": {"net": "0.0060", "gross": "0.0071"},
        "price_monthly": {"net": monthly_gross, "gross": monthly_gross},
        "included_traffic": 21990232555520,
        "price_per_tb_traffic": {"net": "1.0000", "gross": "1.1900"},
    }


def server_type(
    name: str,
    *,
    sold: tuple[str, ...] = (),
    retired: tuple[str, ...] = (),
    specs: tuple[int, float, int] = (2, 2.0, 40),
    type_id: int = 1,
) -> dict[str, Any]:
    """One server type as the API returns it: every listed location, retired ones with a deprecation.

    ``specs`` is (cores, memory GB, disk GB).
    """
    cores, memory, disk = specs
    listed = [*sold, *retired]
    return {
        "id": type_id,
        "name": name,
        "description": name.upper(),
        "category": "regular_purpose",
        "cores": cores,
        "memory": memory,
        "disk": disk,
        "deprecated": False,
        "deprecation": None,
        "prices": [_price(location, "4.99") for location in listed],
        "storage_type": "local",
        "cpu_type": "shared",
        "architecture": "x86",
        "locations": [
            {
                "id": _LOCATION_IDS[location],
                "name": location,
                "deprecation": copy.deepcopy(_RETIRED) if location in retired else None,
            }
            for location in listed
        ],
    }


CPX11 = server_type("cpx11", sold=("ash", "hil"), retired=("fsn1", "nbg1", "hel1", "sin"), type_id=22)
CX23 = server_type("cx23", sold=("fsn1", "nbg1", "hel1"), specs=(2, 4.0, 40), type_id=104)
CPX22 = server_type("cpx22", sold=("fsn1", "nbg1", "hel1", "sin"), specs=(2, 4.0, 80), type_id=108)
# Retired everywhere it is listed; the type-level `deprecated` flag is no longer maintained.
CX11 = server_type("cx11", retired=("fsn1", "nbg1", "hel1"), specs=(1, 2.0, 20), type_id=1)


_LOCATION_DETAILS = {
    "fsn1": ("Falkenstein DC Park 1", "DE", "Falkenstein"),
    "nbg1": ("Nuremberg DC Park 1", "DE", "Nuremberg"),
    "hel1": ("Helsinki DC Park 1", "FI", "Helsinki"),
    "ash": ("Ashburn, VA", "US", "Ashburn, VA"),
    "hil": ("Hillsboro, OR", "US", "Hillsboro, OR"),
    "sin": ("Singapore", "SG", "Singapore"),
}


def location(name: str) -> dict[str, Any]:
    """One location as GET /v1/locations returns it."""
    description, country, city = _LOCATION_DETAILS[name]
    return {
        "id": _LOCATION_IDS[name],
        "name": name,
        "description": description,
        "country": country,
        "city": city,
        "latitude": 0.0,
        "longitude": 0.0,
        "network_zone": "us-east" if country == "US" else "eu-central",
    }


ALL_LOCATIONS = [location(name) for name in _LOCATION_IDS]


def _page(key: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(items),
        "meta": {
            "pagination": {
                "page": 1,
                "per_page": 50,
                "previous_page": None,
                "next_page": None,
                "last_page": 1,
                "total_entries": len(items),
            }
        },
    }


def server(server_id: int, name: str, labels: dict[str, str]) -> dict[str, Any]:
    """The fields of a GET /v1/servers entry that a label lookup reads."""
    return {"id": server_id, "name": name, "status": "running", "labels": dict(labels)}


def _selectors(server_payload: dict[str, Any]) -> set[str]:
    return {f"{key}={value}" for key, value in server_payload["labels"].items()}


class RecordedHcloudTransport:
    """Stands in for hcloud's ClientBase.request: answers the two catalogue listings, server
    listings by label, and lookups by id with not_found.

    Any other request (a lazy BoundLocation reload, or any write) fails the test, so code under
    test can be proven to read only what the listings carry and to write nothing.
    """

    def __init__(
        self,
        server_types: list[dict[str, Any]],
        locations: list[dict[str, Any]] | None = None,
        servers: list[dict[str, Any]] | None = None,
    ) -> None:
        self._server_types = server_types
        self._locations = ALL_LOCATIONS if locations is None else locations
        self._servers = servers or []
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, url: str, method: str, **kwargs: Any) -> dict[str, Any]:
        params = dict(kwargs.get("params") or {})
        self.requests.append((url, params))
        if method == "GET" and url == "/server_types":
            return _page(
                "server_types",
                [st for st in self._server_types if "name" not in params or st["name"] == params["name"]],
            )
        if method == "GET" and url == "/locations":
            return _page("locations", self._locations)
        if method == "GET" and url == "/servers":
            selector = params.get("label_selector", "")
            return _page("servers", [sv for sv in self._servers if selector in _selectors(sv)])
        if method == "GET" and url.startswith("/servers/"):
            # Servers are found only by label: a stored server id is stale.
            raise APIException(code="not_found", message="server not found", details=None)
        raise AssertionError(f"unexpected hcloud request: {method} {url}")
