"""
Structural CI test: every API view must declare its auth intent.

Uses Django's URL resolver to find all /api/ endpoints, then verifies each
view function has at least one recognized auth mechanism:

  - @public_api_endpoint marker        (intentionally unauthenticated)
  - @require_customer_authentication   (HMAC + customer membership)
  - @require_user_authentication       (HMAC + user identity)
  - @require_portal_service_authentication  (HMAC service-level)
  - @require_portal_authentication     (lightweight HMAC check)
  - IsAuthenticated in permission_classes   (DRF token/session auth)

If an endpoint is added without auth, this test fails with a clear message.
"""

from __future__ import annotations

import inspect
from typing import Any

from django.test import SimpleTestCase
from django.urls import URLPattern, URLResolver, get_resolver
from rest_framework import permissions as drf_permissions
from rest_framework.views import APIView

from apps.api.core.permissions import IsAuthenticatedAndAccessible

# Names of auth decorator wrapper functions (matched via __qualname__)
_AUTH_DECORATOR_QUALNAMES = {
    "require_customer_authentication",
    "require_user_authentication",
    "require_portal_service_authentication",
    "require_portal_authentication",
}

# Permission classes that satisfy the auth requirement
_AUTH_PERMISSION_CLASSES = {
    "IsAuthenticated",
    "IsAuthenticatedAndAccessible",
    "IsAdminUser",
}

# Base classes — any subclass of these also satisfies the auth requirement
_AUTH_PERMISSION_BASE_CLASSES = (
    drf_permissions.IsAuthenticated,
    drf_permissions.IsAdminUser,
    IsAuthenticatedAndAccessible,
)


def _walk_url_patterns(
    patterns: list[URLPattern | URLResolver], prefix: str = ""
) -> list[tuple[str, Any]]:
    """Recursively walk URL patterns and yield (url_path, view_func) tuples."""
    results = []
    for pattern in patterns:
        if isinstance(pattern, URLResolver):
            new_prefix = prefix + str(pattern.pattern)
            results.extend(_walk_url_patterns(pattern.url_patterns, new_prefix))
        elif isinstance(pattern, URLPattern):
            url = prefix + str(pattern.pattern)
            results.append((url, pattern.callback))
    return results


def _check_qualname_for_auth(obj: Any) -> bool:
    """Check if an object's qualname contains an auth decorator name."""
    qualname = getattr(obj, "__qualname__", "")
    return any(name in qualname for name in _AUTH_DECORATOR_QUALNAMES)


def _has_auth_decorator_in_chain(func: Any) -> bool:
    """Walk the wrapper chain looking for auth decorator qualnames."""
    # Direct check on the view function
    if _check_qualname_for_auth(func):
        return True

    # Walk __wrapped__ chain
    current = func
    seen: set[int] = {id(func)}
    for _ in range(15):
        next_func = getattr(current, "__wrapped__", None)
        if next_func is None or id(next_func) in seen:
            break
        seen.add(id(next_func))
        if _check_qualname_for_auth(next_func):
            return True
        current = next_func

    # For DRF views, check the cls HTTP methods and their closures
    cls = getattr(func, "cls", None)
    if cls:
        for method_name in ("get", "post", "put", "patch", "delete"):
            method = getattr(cls, method_name, None)
            if method is None:
                continue
            if _check_qualname_for_auth(method):
                return True
            # Check closure cells — DRF stores the original decorated function there
            for cell in getattr(method, "__closure__", None) or ():
                try:
                    cell_val = cell.cell_contents
                except ValueError:
                    continue
                if callable(cell_val) and _check_qualname_for_auth(cell_val):
                    return True

    return False


def _has_public_marker(func: Any) -> bool:
    """Check if the view or any function in its wrapper chain has _is_public_api_endpoint."""
    # Direct check
    if getattr(func, "_is_public_api_endpoint", False):
        return True

    # DRF @api_view: check the cls HTTP method handlers and their closures.
    # DRF wraps the original function inside handler closures, so the marker
    # attribute ends up on a function stored in handler.__closure__[0].
    cls = getattr(func, "cls", None)
    if cls:
        for method_name in ("get", "post", "put", "patch", "delete"):
            method = getattr(cls, method_name, None)
            if method is None:
                continue
            if getattr(method, "_is_public_api_endpoint", False):
                return True
            # Check closure cells for the original decorated function
            for cell in getattr(method, "__closure__", None) or ():
                try:
                    cell_val = cell.cell_contents
                except ValueError:
                    continue
                if callable(cell_val) and getattr(cell_val, "_is_public_api_endpoint", False):
                    return True

    # Walk __wrapped__ chain
    current = func
    for _ in range(15):
        current = getattr(current, "__wrapped__", None)
        if current is None:
            break
        if getattr(current, "_is_public_api_endpoint", False):
            return True

    return False


def _pc_satisfies_auth(pc: Any) -> bool:
    """Return True if a permission class (or name) satisfies the auth requirement."""
    if isinstance(pc, type):
        pc_name = pc.__name__
        if pc_name in _AUTH_PERMISSION_CLASSES:
            return True
        # Also accept any subclass of the known auth base classes
        return issubclass(pc, _AUTH_PERMISSION_BASE_CLASSES)
    pc_name = type(pc).__name__
    return pc_name in _AUTH_PERMISSION_CLASSES


def _has_auth_permission_class(func: Any) -> bool:
    """Check if the view has IsAuthenticated or similar in permission_classes."""
    # DRF @api_view: check cls.permission_classes
    cls = getattr(func, "cls", None)
    if cls:
        pcs = getattr(cls, "permission_classes", [])
        if any(_pc_satisfies_auth(pc) for pc in pcs):
            return True

    # CBV: check class directly
    if inspect.isclass(func) and issubclass(func, APIView) and any(
        _pc_satisfies_auth(pc) for pc in getattr(func, "permission_classes", [])
    ):
        return True

    # Check initkwargs (sometimes used by ViewSets)
    initkwargs = getattr(func, "initkwargs", {})
    return any(_pc_satisfies_auth(pc) for pc in initkwargs.get("permission_classes", []))


def _view_has_auth_coverage(func: Any) -> bool:
    """Check if a view has any recognized auth mechanism."""
    return (
        _has_public_marker(func)
        or _has_auth_permission_class(func)
        or _has_auth_decorator_in_chain(func)
    )


class TestAPIAuthCoverage(SimpleTestCase):
    """Every API endpoint must have an explicit auth intent."""

    def test_all_api_endpoints_have_auth_coverage(self) -> None:
        """Scan all /api/ URL patterns and verify auth decorator coverage."""
        resolver = get_resolver()
        all_urls = _walk_url_patterns(resolver.url_patterns)

        # Filter to /api/ paths only
        api_urls = [(url, view) for url, view in all_urls if url.startswith("api/")]

        self.assertGreater(len(api_urls), 0, "No /api/ URLs found -- resolver misconfigured?")

        unprotected: list[str] = []

        for url_path, view_func in api_urls:
            if not _view_has_auth_coverage(view_func):
                view_name = getattr(view_func, "__name__", None) or type(view_func).__name__
                module = getattr(view_func, "__module__", "unknown")
                unprotected.append(f"  /{url_path}  ({module}.{view_name})")

        self.assertEqual(
            unprotected,
            [],
            "\n\nUnprotected API endpoints found (missing auth decorator):\n"
            + "\n".join(unprotected)
            + "\n\nEach API view must have one of:\n"
            "  @public_api_endpoint\n"
            "  @require_customer_authentication\n"
            "  @require_user_authentication\n"
            "  @require_portal_service_authentication\n"
            "  @require_portal_authentication\n"
            "  permission_classes=[IsAuthenticated]\n",
        )
