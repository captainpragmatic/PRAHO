"""Recorded Hetzner Cloud API shapes, served to the real hcloud SDK through its HTTP seam.

The server type payloads mirror GET /v1/server_types after Hetzner started retiring types per
location (2025-09-24): cpx11 still lists hel1, fsn1, nbg1 and sin, each with a deprecation,
and is still sold in ash and hil.
"""

from __future__ import annotations

import copy
from typing import Any

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


class RecordedHcloudTransport:
    """Stands in for hcloud's ClientBase.request and answers only the server type endpoint.

    Any other request (a lazy BoundLocation reload, say) fails the test, so code under test
    can be proven to read only what the server type listing already carries.
    """

    def __init__(self, server_types: list[dict[str, Any]]) -> None:
        self._server_types = server_types
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, url: str, method: str, **kwargs: Any) -> dict[str, Any]:
        params = dict(kwargs.get("params") or {})
        self.requests.append((url, params))
        if method != "GET" or url != "/server_types":
            raise AssertionError(f"unexpected hcloud request: {method} {url}")
        types = [st for st in self._server_types if "name" not in params or st["name"] == params["name"]]
        return {
            "server_types": copy.deepcopy(types),
            "meta": {
                "pagination": {
                    "page": 1,
                    "per_page": 50,
                    "previous_page": None,
                    "next_page": None,
                    "last_page": 1,
                    "total_entries": len(types),
                }
            },
        }
