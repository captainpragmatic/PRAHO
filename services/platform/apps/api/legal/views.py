"""Published legal documents for the HMAC-authenticated customer portal (ADR-0062).

A release is public text, so any portal request may read one: the release in force for a kind and
language, or a given release by id, as an acceptance names it.
"""

from __future__ import annotations

import uuid

from django.http import HttpRequest
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.api.secure_auth import require_portal_service_authentication
from apps.common.legal import LegalDocument, current_legal_document
from apps.common.performance.rate_limiting import (
    BurstRateThrottle,
    CustomerRateThrottle,
    PortalHMACBurstThrottle,
    PortalHMACRateThrottle,
)


def _requested_document(request_data: dict[str, object]) -> LegalDocument | None:
    document_id = str(request_data.get("id") or "")
    if document_id:
        try:
            return LegalDocument.objects.filter(pk=uuid.UUID(document_id)).first()
        except ValueError:
            return None
    return current_legal_document(str(request_data.get("kind") or ""), str(request_data.get("language") or ""))


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])  # HMAC authentication is required by the service decorator.
@throttle_classes([PortalHMACRateThrottle, PortalHMACBurstThrottle, CustomerRateThrottle, BurstRateThrottle])
@require_portal_service_authentication
def legal_document(request: HttpRequest, request_data: dict[str, object]) -> Response:
    """POST {"kind": "terms", "language": "ro"} or {"id": "<uuid>"}: the release, or 404 `not_published`."""
    document = _requested_document(request_data)
    if document is None:
        return Response({"success": False, "code": "not_published"}, status=status.HTTP_404_NOT_FOUND)
    return Response(
        {
            "success": True,
            "document": {
                "id": str(document.pk),
                "kind": document.kind,
                "language": document.language,
                "release": document.release,
                "effective_on": document.effective_on.isoformat(),
                "html": document.body_html,
                "sha256": document.sha256,
            },
        }
    )
