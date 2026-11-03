"""Signed, customer-scoped access to accepted hosting plan changes."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from django.utils.translation import gettext as _
from django.db import transaction
from django.core.exceptions import ValidationError
from rest_framework import serializers
from django.views.decorators.cache import never_cache
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response

from apps.api.secure_auth import BILLING_ROLES, require_customer_role_in
from apps.api.step_up import step_up_refusal
from apps.provisioning.hosting_limit_policy import HostingAssignmentTerms

if TYPE_CHECKING:
    from apps.billing.plan_change_models import PlanChange
    from apps.customers.models import Customer


class QuoteInput(serializers.Serializer):
    target_product_id = serializers.UUIDField()
    submission_id = serializers.UUIDField()
    expected_limit_revision = serializers.IntegerField(min_value=1)


class ConfirmationInput(serializers.Serializer):
    quote_fingerprint = serializers.RegexField(regex=r"^[a-f0-9]{64}$")
    accept_zero_due = serializers.BooleanField(required=False, default=False)

    def validate_accept_zero_due(self, value: bool) -> bool:
        if type(self.initial_data.get("accept_zero_due", False)) is not bool:
            raise serializers.ValidationError(_("Expected an explicit boolean acceptance."))
        return value


def _operation_response(
    request: Request, *, customer_id: int, actor_id: int, service_id: int, operation: str, change_id: UUID | None,
) -> Response:
    from apps.billing.plan_change_models import PlanChange  # noqa: PLC0415 -- Cross-app API boundary.
    from apps.billing.plan_change_quote_service import (  # noqa: PLC0415 -- Commercial service boundary.
        confirm_plan_change, plan_change_options, quote_plan_change,
    )

    if operation == "options":
        return Response({"success": True, "data": plan_change_options(service_id, customer_id=customer_id, actor_id=actor_id)})
    if operation == "quote":
        payload = QuoteInput(data=request.data)
        payload.is_valid(raise_exception=True)
        values = payload.validated_data
        # This controls HTTP presentation only. The service's locked unique
        # submission contract owns all idempotence and changed-payload refusal.
        existed = PlanChange.objects.filter(customer_id=customer_id, requested_by_id=actor_id, submission_id=values["submission_id"]).exists()
        change = quote_plan_change(service_id, customer_id=customer_id, actor_id=actor_id, **values)
        return Response({"success": True, "data": plan_change_data(change)}, status=200 if existed else 201)
    if operation == "confirm" and change_id is not None:
        acceptance = ConfirmationInput(data=request.data)
        acceptance.is_valid(raise_exception=True)
        change = confirm_plan_change(change_id, customer_id=customer_id, actor_id=actor_id,
                                     expected_fingerprint=acceptance.validated_data["quote_fingerprint"],
                                     accept_zero_due=acceptance.validated_data["accept_zero_due"])
        return Response({"success": True, "data": plan_change_data(change)})
    return Response({"success": False, "error": _("Plan change not found.")}, status=404)


def plan_change_data(change: PlanChange) -> dict[str, object]:
    """Customer-safe state; native receipts, review details and card secrets stay private."""
    limits = HostingAssignmentTerms.from_snapshot(change.quote_snapshot.get("accepted_limits"))
    return {
        "id": str(change.pk),
        "status": change.status,
        "direction": change.direction,
        "net_cents": change.net_cents,
        "tax_cents": change.tax_cents,
        "total_cents": change.total_cents,
        "currency": change.currency_id,
        "quote_fingerprint": change.request_fingerprint,
        "quote_revision": change.expected_limit_revision,
        "expires_at": change.expires_at.isoformat(),
        "authority_expires_at": change.authority_expires_at.isoformat(),
        "effective_at": change.effective_at.isoformat(),
        "next_recurring_net_cents": change.target_period_price_cents,
        "proposed_limits": {"disk_mib": limits.disk_allowance_mib, "bandwidth_mib": limits.bandwidth_allowance_mib},
        "periods": [
            {
                "start": part.period_start.isoformat(),
                "end": part.period_end.isoformat(),
                "slice_start": part.slice_start.isoformat(),
                "net_cents": part.net_cents,
                "current": part.current_slice,
            }
            for part in change.intervals.order_by("ordinal")
        ],
        "payment_received": change.invoice_id is not None,
        "limits_pending": change.status in {"applying_limits", "limits_attention"},
        "requires_review": change.status == "paid_review",
    }


@never_cache
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*BILLING_ROLES)
def plan_change_status_api(request: Request, customer: Customer, service_id: int, change_id: UUID) -> Response:
    from apps.billing.plan_change_models import PlanChange  # noqa: PLC0415 -- Cross-app API boundary.
    from apps.provisioning.models import Service  # noqa: PLC0415 -- Cross-app API boundary.

    if not Service.objects.filter(pk=service_id, customer=customer).exists():
        return Response({"success": False, "error": _("Plan change not found.")}, status=404)
    change = PlanChange.objects.filter(pk=change_id, service_id=service_id, customer=customer).first()
    if change is None:
        return Response({"success": False, "error": _("Plan change not found.")}, status=404)
    if refusal := step_up_refusal(request):
        return refusal
    try:
        data = plan_change_data(change)
    except ValueError:
        return Response({"success": False, "error": _("This plan change requires staff review.")}, status=409)
    return Response({"success": True, "data": data})


@transaction.non_atomic_requests
@never_cache
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*BILLING_ROLES)
def plan_change_action_api(
    request: Request, customer: Customer, service_id: int, operation: str, change_id: UUID | None = None,
) -> Response:
    from apps.billing.plan_change_models import PlanChange  # noqa: PLC0415 -- Cross-app API boundary.
    from apps.provisioning.models import Service  # noqa: PLC0415 -- Cross-app API boundary.

    if not Service.objects.filter(pk=service_id, customer=customer).exists():
        return Response({"success": False, "error": _("Plan change not found.")}, status=404)
    if change_id is not None and not PlanChange.objects.filter(pk=change_id, customer=customer, service_id=service_id).exists():
        return Response({"success": False, "error": _("Plan change not found.")}, status=404)
    if refusal := step_up_refusal(request):
        return refusal
    from apps.billing.plan_change_validation import PlanChangeConflict  # noqa: PLC0415 -- Typed service refusal.

    try:
        return _operation_response(request, customer_id=customer.pk, actor_id=int(request.data["user_id"]),
                                   service_id=service_id, operation=operation, change_id=change_id)
    except ValidationError as error:
        return Response({"success": False, "error": " ".join(error.messages),
                         "code": getattr(error, "code", None) or "plan_change_unavailable"},
                        status=409 if isinstance(error, PlanChangeConflict) else 400)
