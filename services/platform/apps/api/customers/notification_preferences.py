"""Customer-owned optional quota warnings; critical notices retain their policy."""

from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from rest_framework import serializers
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response

from apps.api.secure_auth import BILLING_ROLES, require_customer_role_in
from apps.customers.models import Customer
from apps.notifications.models import EmailPreference
from apps.notifications.services import EmailPreferenceService


class QuotaWarningPreferenceInput(serializers.Serializer):
    action = serializers.ChoiceField(choices=("get", "update"))
    quota_warnings = serializers.BooleanField(required=False)

    def validate(self, attrs: dict[str, object]) -> dict[str, object]:
        if any(key in self.initial_data for key in ("critical_notices", "global_unsubscribe")):
            raise serializers.ValidationError(_("This form changes optional hosting warnings only."))
        if attrs["action"] == "update" and type(self.initial_data.get("quota_warnings")) is not bool:
            raise serializers.ValidationError(_("Submit an explicit boolean quota warning preference."))
        return attrs


@never_cache
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*BILLING_ROLES)
def quota_warning_preferences_api(request: Request, customer: Customer) -> Response:
    payload = QuotaWarningPreferenceInput(data=request.data)
    payload.is_valid(raise_exception=True)
    if payload.validated_data["action"] == "update":
        EmailPreferenceService.update_preferences(
            customer, {"quota_warnings": payload.validated_data["quota_warnings"]}
        )
    preference = EmailPreference.objects.filter(customer=customer).first() or EmailPreference(customer=customer)
    return Response(
        {
            "success": True,
            "data": {
                "quota_warnings": preference.quota_warnings,
                "global_unsubscribe": preference.global_unsubscribe,
                "critical_notices": True,
            },
        }
    )
