"""
Fixture factories for Virtualmin create-domain responses.

Matches the real Virtualmin JSON API format from remote.cgi.
"""

from __future__ import annotations

from typing import Any


def success(
    domain: str = "example.com",
    username: str = "example",
    home: str = "/home/example",
) -> dict[str, Any]:
    """Successful domain creation response."""
    return {
        "command": "create-domain",
        "status": "success",
        "output": (
            f"Creating virtual server {domain} ..\n"
            f".. home directory /home/{username}\n"
            f"  Creating Unix user {username} ..\n"
            f"  .. done\n"
            f"  Creating Apache virtual host for {domain} ..\n"
            f"  .. done\n"
            f"  Creating DNS zone for {domain} ..\n"
            f"  .. done\n"
            f"  Creating MySQL database {username} ..\n"
            f"  .. done\n"
            f"  Creating mail domain {domain} ..\n"
            f"  .. done\n"
            f"Domain {domain} created successfully"
        ),
    }


def conflict(domain: str = "example.com") -> dict[str, Any]:
    """Domain already exists conflict error."""
    return {
        "command": "create-domain",
        "status": "failure",
        "error": f"Virtual server {domain} already exists",
    }


def quota_exceeded(domain: str = "example.com") -> dict[str, Any]:
    """Server quota exceeded error."""
    return {
        "command": "create-domain",
        "status": "failure",
        "error": f"Cannot create virtual server {domain} - server quota exceeded",
    }


def invalid_domain(domain: str = "bad..domain") -> dict[str, Any]:
    """Invalid domain name error."""
    return {
        "command": "create-domain",
        "status": "failure",
        "error": f"Invalid domain name : {domain}",
    }
