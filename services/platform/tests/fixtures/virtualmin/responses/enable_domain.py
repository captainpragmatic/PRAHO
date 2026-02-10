"""
Fixture factories for Virtualmin enable-domain responses.
"""

from __future__ import annotations

from typing import Any


def success(domain: str = "example.com") -> dict[str, Any]:
    """Successful domain enable (unsuspend) response."""
    return {
        "command": "enable-domain",
        "status": "success",
        "output": (
            f"Enabling virtual server {domain} ..\n"
            f"  Enabling Apache virtual host ..\n"
            f"  .. done\n"
            f"  Enabling DNS zone ..\n"
            f"  .. done\n"
            f"  Enabling mail domain ..\n"
            f"  .. done\n"
            f"  Unlocking Unix user ..\n"
            f"  .. done\n"
            f"Domain {domain} enabled successfully"
        ),
    }


def not_found(domain: str = "example.com") -> dict[str, Any]:
    """Domain not found error."""
    return {
        "command": "enable-domain",
        "status": "failure",
        "error": f"Virtual server {domain} does not exist",
    }


def already_enabled(domain: str = "example.com") -> dict[str, Any]:
    """Domain already enabled."""
    return {
        "command": "enable-domain",
        "status": "failure",
        "error": f"Virtual server {domain} is already enabled",
    }
