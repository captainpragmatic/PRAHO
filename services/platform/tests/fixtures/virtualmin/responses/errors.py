"""
Fixture factories for common Virtualmin API error responses.
"""

from __future__ import annotations

from typing import Any


def auth_failure(program: str = "list-domains") -> dict[str, Any]:
    """Authentication failure response (401/403)."""
    return {
        "command": program,
        "status": "failure",
        "error": "Login failed : Invalid username or password",
    }


def not_found(resource: str = "example.com", program: str = "get-domain") -> dict[str, Any]:
    """Resource not found response."""
    return {
        "command": program,
        "status": "failure",
        "error": f"Virtual server {resource} does not exist",
    }


def generic(
    program: str = "modify-domain",
    error_message: str = "An internal error occurred",
) -> dict[str, Any]:
    """Generic Virtualmin error response."""
    return {
        "command": program,
        "status": "failure",
        "error": error_message,
    }


def rate_limited(program: str = "create-domain") -> dict[str, Any]:
    """Rate limit exceeded response."""
    return {
        "command": program,
        "status": "failure",
        "error": "Too many requests, please try again later",
    }


def server_offline(program: str = "info") -> dict[str, Any]:
    """Server/service unavailable response."""
    return {
        "command": program,
        "status": "failure",
        "error": "Webmin server is not running or not accessible",
    }
