"""
Fixture factories for Virtualmin list-domains responses.
"""

from __future__ import annotations

from typing import Any


def multiline_response(
    domains: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Full multiline list-domains response with disk/bandwidth details.

    Each domain dict should have: name, username, disk_usage, disk_quota,
    bandwidth_usage, bandwidth_quota.
    """
    if domains is None:
        domains = [
            {
                "name": "example.com",
                "username": "example",
                "disk_usage": "150 MB",
                "disk_quota": "1000 MB",
                "bandwidth_usage": "500 MB",
                "bandwidth_quota": "10000 MB",
            },
            {
                "name": "test.org",
                "username": "testorg",
                "disk_usage": "50 MB",
                "disk_quota": "500 MB",
                "bandwidth_usage": "100 MB",
                "bandwidth_quota": "5000 MB",
            },
        ]

    data = []
    for d in domains:
        data.append({
            "name": d["name"],
            "values": {
                "Username": d.get("username", d["name"].split(".")[0]),
                "Disk space used": d.get("disk_usage", "0 MB"),
                "Server byte quota": d.get("disk_quota", "Unlimited"),
                "Bandwidth usage": d.get("bandwidth_usage", "0 MB"),
                "Bandwidth limit": d.get("bandwidth_quota", "Unlimited"),
                "Features": "web dns mail mysql",
                "Status": "Enabled" if d.get("enabled", True) else "Disabled",
            },
        })

    return {
        "command": "list-domains",
        "status": "success",
        "data": data,
    }


def name_only(domain_names: list[str] | None = None) -> dict[str, Any]:
    """Simple list-domains response with just domain names."""
    if domain_names is None:
        domain_names = ["example.com", "test.org", "demo.net"]

    return {
        "command": "list-domains",
        "status": "success",
        "data": [{"name": name} for name in domain_names],
    }


def empty() -> dict[str, Any]:
    """Empty list-domains response (no domains on server)."""
    return {
        "command": "list-domains",
        "status": "success",
        "data": [],
    }


def single_domain(
    domain: str = "example.com",
    username: str = "example",
    disk_usage: str = "150 MB",
    disk_quota: str = "1000 MB",
    bandwidth_usage: str = "500 MB",
    bandwidth_quota: str = "10000 MB",
) -> dict[str, Any]:
    """Single domain multiline response (used by get_domain_info)."""
    return multiline_response(
        domains=[{
            "name": domain,
            "username": username,
            "disk_usage": disk_usage,
            "disk_quota": disk_quota,
            "bandwidth_usage": bandwidth_usage,
            "bandwidth_quota": bandwidth_quota,
        }]
    )
