"""Tenant-scoped database-only DNS reads and durable owner/tech mutation intents, export included."""

from __future__ import annotations

import base64
import re
from http import HTTPStatus
from typing import TYPE_CHECKING, Any
from uuid import UUID

from django.shortcuts import get_object_or_404
from django.views.decorators.cache import never_cache
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response

from apps.api.secure_auth import TECH_ROLES, require_customer_authentication, require_customer_role_in
from apps.domains import dns_zone_services as zones
from apps.domains.dns_zone_models import HostedZone
from apps.provisioning.virtualmin_models import VirtualminAccount

from .serializers import bounded_text, digest_text, positive_integer, upload_bytes

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.users.models import User


def _response(data: dict[str, Any], *, status: int = HTTPStatus.OK) -> Response:
    return Response({"success": True, "data": data}, status=status, headers={"Cache-Control": "no-store"})


def _error(code: str, *, status: int = HTTPStatus.CONFLICT) -> Response:
    safe_code = code if re.fullmatch(r"[a-z][a-z0-9_]{0,79}", code) else "dns_operation_unavailable"
    return Response({"success": False, "error": safe_code}, status=status, headers={"Cache-Control": "no-store"})


def _actor(request: Request) -> User | None:
    from apps.users.models import User  # noqa: PLC0415  # Canonical principal at the HTTP boundary

    actor = getattr(request, "_customer_user", None)
    return actor if isinstance(actor, User) and actor.is_active else None


@never_cache
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def zone_record_detail_api(request: Request, customer: Customer, zone_id: UUID, record_id: UUID) -> Response:
    zone = _zone(customer, zone_id)
    row = get_object_or_404(zone.records, pk=record_id, desired_deleted=False)
    return _response(
        {
            "record": {
                "id": str(row.pk),
                "name": row.name,
                "record_type": row.record_type,
                "ttl": row.ttl,
                "rdata": str(row.rdata.get("text", "")),
                "managed": row.managed_by == "praho",
                "managed_by": row.managed_by,
            },
            "revision": zone.current_revision,
        }
    )


def _zone(customer: Customer, zone_id: UUID) -> HostedZone:
    return get_object_or_404(HostedZone, pk=zone_id, customer_id=customer.pk)


@never_cache
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def zone_list_api(request: Request, customer: Customer) -> Response:
    try:
        page = positive_integer(request.data.get("page", 1))
    except ValueError as error:
        return _error(str(error), status=HTTPStatus.BAD_REQUEST)
    rows = HostedZone.objects.filter(customer_id=customer.pk).exclude(status="deleted").order_by("name")
    total = rows.count()
    pages = max(1, (total + 24) // 25)
    page = min(page, pages)
    # Lists expose summary fields only; complete inventory is paginated on detail.
    items = [
        {"id": str(row.pk), "name": row.name, "status": row.status, "revision": row.current_revision}
        for row in rows[(page - 1) * 25 : page * 25]
    ]
    return _response({"zones": items, "page": page, "pages": pages, "total": total})


@never_cache
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def zone_detail_api(request: Request, customer: Customer, zone_id: UUID) -> Response:
    zone = _zone(customer, zone_id)
    try:
        page = positive_integer(request.data.get("page", 1))
    except ValueError as error:
        return _error(str(error), status=HTTPStatus.BAD_REQUEST)
    return _response({"zone": zones.cached_zone_status(zone, page=page, actor=_actor(request))})


@never_cache
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*TECH_ROLES)
def zone_import_api(request: Request, customer: Customer) -> Response:
    actor = _actor(request)
    if actor is None:
        return _error("zone_access_denied", status=HTTPStatus.FORBIDDEN)
    try:
        service_id = positive_integer(request.data.get("service_id"))
        raw = upload_bytes(request.data.get("zone_file"))
    except ValueError as error:
        return _error(str(error), status=HTTPStatus.BAD_REQUEST)
    account = get_object_or_404(VirtualminAccount, service_id=service_id, service__customer_id=customer.pk)
    result = zones.preview_zone_import(account, raw, actor=actor)
    if result.is_err():
        return _error(result.unwrap_err())
    return _response({"zone": zones.cached_zone_status(result.unwrap().zone, actor=actor)}, status=HTTPStatus.CREATED)


@never_cache
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*TECH_ROLES)
def zone_action_api(request: Request, customer: Customer, zone_id: UUID, action: str) -> Response:
    actor = _actor(request)
    if actor is None:
        return _error("zone_access_denied", status=HTTPStatus.FORBIDDEN)
    zone = _zone(customer, zone_id)
    try:
        revision = positive_integer(request.data.get("expected_revision"))
        if action == "confirm":
            result = zones.confirm_import(zone, revision, digest_text(request.data.get("manifest_digest")), actor=actor)
        elif action == "crosscheck":
            result = zones.request_crosscheck(zone, revision, actor=actor)
        elif action == "switch":
            result = zones.request_nameserver_switch(zone, revision, actor=actor)
        elif action == "delete":
            result = zones.request_zone_delete(
                zone, revision, actor=actor, export_digest=digest_text(request.data.get("export_digest"))
            )
        else:
            return _error("invalid_zone_action", status=HTTPStatus.BAD_REQUEST)
    except ValueError as error:
        return _error(str(error), status=HTTPStatus.BAD_REQUEST)
    if result.is_err():
        return _error(result.unwrap_err())
    return _response({"zone": zones.cached_zone_status(zone, actor=actor)}, status=HTTPStatus.ACCEPTED)


@never_cache
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*TECH_ROLES)
def zone_export_api(request: Request, customer: Customer, zone_id: UUID) -> Response:
    actor = _actor(request)
    if actor is None:
        return _error("zone_access_denied", status=HTTPStatus.FORBIDDEN)
    result = zones.export_zone_file(_zone(customer, zone_id), actor=actor)
    if result.is_err():
        return _error(result.unwrap_err())
    return _response({"zone_file": base64.b64encode(result.unwrap()).decode("ascii")})


@never_cache
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*TECH_ROLES)
def zone_record_api(request: Request, customer: Customer, zone_id: UUID, record_id: UUID | None = None) -> Response:
    actor = _actor(request)
    if actor is None:
        return _error("zone_access_denied", status=HTTPStatus.FORBIDDEN)
    zone = _zone(customer, zone_id)
    if record_id is not None:
        row = get_object_or_404(zone.records, pk=record_id, desired_deleted=False)
        if row.managed_by == "praho":
            return _error("managed_record")
    try:
        revision = positive_integer(request.data.get("expected_revision"))
        delete = request.data.get("delete", False)
        if type(delete) is not bool:
            raise ValueError("invalid_delete")
        result = zones.request_record_change(
            zone,
            revision,
            actor=actor,
            record_id=record_id,
            name=bounded_text(request.data.get("name", ""), maximum=253),
            record_type=bounded_text(request.data.get("record_type", ""), maximum=16),
            rdata=bounded_text(request.data.get("rdata", ""), maximum=4096),
            ttl=positive_integer(request.data.get("ttl", 300)),
            delete=delete,
        )
    except ValueError as error:
        return _error(str(error), status=HTTPStatus.BAD_REQUEST)
    if result.is_err():
        return _error(result.unwrap_err())
    return _response({"zone": zones.cached_zone_status(zone, actor=actor)}, status=HTTPStatus.ACCEPTED)
