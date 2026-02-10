"""
Fixture factories for Virtualmin list-bandwidth responses.
"""

from __future__ import annotations

from typing import Any


def success(
    domain: str = "example.com",
    bytes_in: int = 524288000,
    bytes_out: int = 1048576000,
) -> dict[str, Any]:
    """Successful bandwidth listing response.

    Default: ~500MB in, ~1GB out.
    """
    return {
        "command": "list-bandwidth",
        "status": "success",
        "data": [
            {
                "name": domain,
                "values": {
                    "Bytes in": str(bytes_in),
                    "Bytes out": str(bytes_out),
                    "Total bytes": str(bytes_in + bytes_out),
                },
            }
        ],
    }


def empty(domain: str = "example.com") -> dict[str, Any]:
    """Empty bandwidth response (no data for period)."""
    return {
        "command": "list-bandwidth",
        "status": "success",
        "data": [],
    }
