"""
Fixture factories for Virtualmin disable-domain responses.
"""

from __future__ import annotations

from typing import Any


def success(domain: str = "example.com") -> dict[str, Any]:
    """Successful domain disable (suspend) response."""
    return {
        "command": "disable-domain",
        "status": "success",
        "output": (
            f"Disabling virtual server {domain} ..\n"
            f"  Disabling Apache virtual host ..\n"
            f"  .. done\n"
            f"  Disabling DNS zone ..\n"
            f"  .. done\n"
            f"  Disabling mail domain ..\n"
            f"  .. done\n"
            f"  Locking Unix user ..\n"
            f"  .. done\n"
            f"Domain {domain} disabled successfully"
        ),
    }


def not_found(domain: str = "example.com") -> dict[str, Any]:
    """Domain not found error."""
    return {
        "command": "disable-domain",
        "status": "failure",
        "error": f"Virtual server {domain} does not exist",
    }


def already_disabled(domain: str = "example.com") -> dict[str, Any]:
    """Domain already disabled."""
    return {
        "command": "disable-domain",
        "status": "failure",
        "error": f"Virtual server {domain} is already disabled",
    }
