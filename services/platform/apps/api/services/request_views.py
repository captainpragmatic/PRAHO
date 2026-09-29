"""Customer submission endpoint; staff decisions are never serialized here."""

from django.utils.translation import gettext as _
from rest_framework import serializers
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response

from apps.api.secure_auth import SUPPORT_ROLES, require_customer_role_in
from apps.customers.models import Customer
from apps.provisioning.service_request_models import ServiceRequest
from apps.provisioning.service_request_service import ServiceRequestError, submit_service_request
from apps.users.models import User


class ServiceRequestSerializer(serializers.Serializer):
    action = serializers.ChoiceField(choices=ServiceRequest.Action.choices)
    reason = serializers.CharField(required=False, default="", allow_blank=True, max_length=4000)
    submission_id = serializers.UUIDField()

    def validate_reason(self, value: str) -> str:
        if not isinstance(self.initial_data.get("reason", ""), str):
            raise serializers.ValidationError(_("Expected a text reason."))
        return value


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*SUPPORT_ROLES)
def service_request_api(request: Request, customer: Customer, service_id: int) -> Response:
    serializer = ServiceRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({"success": False, "errors": serializer.errors}, status=400)
    user = User.objects.get(pk=request.data["user_id"], is_active=True)
    try:
        receipt, created = submit_service_request(
            customer=customer,
            user=user,
            service_id=service_id,
            **serializer.validated_data,
        )
    except ServiceRequestError as exc:
        return Response({"success": False, "error": str(exc)}, status=exc.status_code)
    return Response({"success": True, "data": receipt}, status=201 if created else 200)
