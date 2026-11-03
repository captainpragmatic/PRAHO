"""Customer-scoped optional hosting notifications stored on the Platform."""

from django import forms
from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods

from apps.api_client.services import PlatformAPIError, api_client
from apps.common.decorators import require_billing_access
from apps.common.rate_limit_feedback import render_platform_unavailable

from .views import _get_customer_context


class QuotaWarningPreferenceForm(forms.Form):
    quota_warnings = forms.BooleanField(required=False, label=_("Receive optional hosting allowance warnings"))


@never_cache
@require_billing_access()
@require_http_methods(["GET", "POST"])
def notification_preferences_view(request: HttpRequest) -> HttpResponse:
    customer_id, user_id = _get_customer_context(request)
    if customer_id is None or user_id is None:
        return redirect("users:company_profile")
    form = QuotaWarningPreferenceForm(request.POST if request.method == "POST" else None)
    context: dict[str, object] = {"form": form}
    try:
        values = None
        if request.method == "POST" and form.is_valid():
            values = bool(form.cleaned_data["quota_warnings"])
        result = api_client.hosting_warning_preferences(customer_id, user_id, quota_warnings=values)
        if (
            not isinstance(result, dict)
            or result.get("success") is not True
            or not isinstance(result.get("data"), dict)
        ):
            context["save_failed"] = request.method == "POST"
            context["load_failed"] = request.method == "GET"
            return render(request, "customers/notification_preferences.html", context, status=503)
        if request.method == "POST" and form.is_valid():
            messages.success(request, _("Hosting warning preferences saved."))
            return redirect("customers:notification_preferences")
        data = result["data"]
        context.update(
            {
                "form": QuotaWarningPreferenceForm(initial={"quota_warnings": data.get("quota_warnings") is True}),
                "global_unsubscribe": data.get("global_unsubscribe") is True,
            }
        )
    except PlatformAPIError as error:
        return render_platform_unavailable(request, error)
    return render(request, "customers/notification_preferences.html", context)
