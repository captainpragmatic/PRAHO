"""
Fixture factories for Virtualmin delete-domain responses.
"""

from __future__ import annotations

from typing import Any


def success(domain: str = "example.com") -> dict[str, Any]:
    """Successful domain deletion response."""
    return {
        "command": "delete-domain",
        "status": "success",
        "output": (
            f"Deleting virtual server {domain} ..\n"
            f"  Deleting mail domain {domain} ..\n"
            f"  .. done\n"
            f"  Deleting MySQL database ..\n"
            f"  .. done\n"
            f"  Deleting DNS zone for {domain} ..\n"
            f"  .. done\n"
            f"  Deleting Apache virtual host for {domain} ..\n"
            f"  .. done\n"
            f"  Deleting Unix user ..\n"
            f"  .. done\n"
            f"Domain {domain} deleted successfully"
        ),
    }


def not_found(domain: str = "example.com") -> dict[str, Any]:
    """Domain not found error."""
    return {
        "command": "delete-domain",
        "status": "failure",
        "error": f"Virtual server {domain} does not exist",
    }
