"""Tenant-scoped cached DNS diagnostics and durable owner/tech recheck requests."""

from __future__ import annotations

from typing import Any

from django.views.decorators.cache import never_cache
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response

from apps.api.secure_auth import TECH_ROLES, require_customer_authentication, require_customer_role_in
from apps.customers.models import Customer
from apps.provisioning import hosted_domain_dns_service as monitoring
from apps.provisioning.service_models import Service
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.users.models import User


def _response(payload: dict[str, Any], *, status: int = 200) -> Response:
    return Response(payload, status=status, headers={"Cache-Control": "no-store"})


def _account_for_customer(customer: Customer, service_id: int) -> tuple[VirtualminAccount | None, Response | None]:
    service = Service.objects.filter(customer_id=customer.pk, pk=service_id).only("pk").first()
    if service is None:
        return None, _response({"success": False, "error": "Service not found"}, status=404)
    return VirtualminAccount.objects.filter(service_id=service.pk).first(), None


def _not_applicable() -> monitoring.PublicDnsStatus:
    return {
        "version": 1,
        "state": "not_applicable",
        "dns_path": "unknown",
        "pending": False,
        "stale": False,
        "checked_at": None,
        "account_name": None,
        "instructions": [],
        "components": {},
    }


@never_cache
@api_view(["POST"])  # type: ignore[untyped-decorator]  # DRF decorators have no typed public wrapper.
@authentication_classes([])  # type: ignore[untyped-decorator]  # DRF decorators have no typed public wrapper.
@permission_classes([AllowAny])  # type: ignore[untyped-decorator]  # DRF decorators have no typed public wrapper.
@require_customer_authentication
def service_dns_status_api(request: Request, customer: Customer, service_id: int) -> Response:
    """Membership authorizes a database-only read; private probe evidence stays on Platform."""
    account, error = _account_for_customer(customer, service_id)
    if error is not None:
        return error
    status = monitoring.cached_status(account) if account is not None else _not_applicable()
    return _response({"success": True, "data": {"dns_status": status}})


@never_cache
@api_view(["POST"])  # type: ignore[untyped-decorator]  # DRF decorators have no typed public wrapper.
@authentication_classes([])  # type: ignore[untyped-decorator]  # DRF decorators have no typed public wrapper.
@permission_classes([AllowAny])  # type: ignore[untyped-decorator]  # DRF decorators have no typed public wrapper.
@require_customer_role_in(*TECH_ROLES)
def service_dns_recheck_api(request: Request, customer: Customer, service_id: int) -> Response:
    """Persist due work; the bounded dispatcher owns network work and queue admission."""
    actor = getattr(request, "_customer_user", None)
    if not isinstance(actor, User) or not actor.is_active:
        # actor=None is a backend system capability and is never accepted from HTTP.
        return _response({"success": False, "error": "Access denied"}, status=403)
    account, error = _account_for_customer(customer, service_id)
    if error is not None:
        return error
    if account is None:
        return _response({"success": False, "error": "DNS recheck unavailable"}, status=409)
    result = monitoring.request_recheck(account, actor=actor)
    if result.is_err():
        return _response({"success": False, "error": "DNS recheck unavailable"}, status=409)
    return _response({"success": True, "data": {"dns_status": result.unwrap()}}, status=202)
