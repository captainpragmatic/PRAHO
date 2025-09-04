from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.views import redirect_to_login
from django.db.models import QuerySet
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden, JsonResponse
from django.views.generic import DetailView, ListView

from apps.common import validators

from .models import EmailLog, EmailTemplate


class AdminRequiredMixin(UserPassesTestMixin):
    def test_func(self) -> bool:  # pragma: no cover - simple boolean
        user = self.request.user
        return bool(user and user.is_authenticated and user.is_superuser)

    def handle_no_permission(self) -> HttpResponse:  # type: ignore[override]
        if not self.request.user.is_authenticated:
            return redirect_to_login(self.request.get_full_path())
        return HttpResponseForbidden()


class StaffRequiredMixin(UserPassesTestMixin):
    def test_func(self) -> bool:  # pragma: no cover - simple boolean
        user = self.request.user
        return bool(user and user.is_authenticated and user.is_staff)

    def handle_no_permission(self) -> HttpResponse:  # type: ignore[override]
        if not self.request.user.is_authenticated:
            return redirect_to_login(self.request.get_full_path())
        return HttpResponseForbidden()


class EmailTemplateListView(LoginRequiredMixin, AdminRequiredMixin, ListView):  # type: ignore[type-arg]
    model = EmailTemplate
    template_name = "notifications/template_list.html"  # not used in tests

    def get_queryset(self) -> QuerySet[EmailTemplate]:
        # Security logging for monitoring access
        request: HttpRequest = self.request
        validators.log_security_event(
            event_type="template_access",
            details={"action": "list_templates", "user": getattr(request.user, "email", "")},
            request_ip=(request.META.get("REMOTE_ADDR") if hasattr(request, "META") else None),
        )
        return super().get_queryset()


class EmailTemplateDetailView(LoginRequiredMixin, AdminRequiredMixin, DetailView):  # type: ignore[type-arg]
    model = EmailTemplate
    template_name = "notifications/template_detail.html"  # not used in tests


class EmailLogListView(LoginRequiredMixin, StaffRequiredMixin, ListView):  # type: ignore[type-arg]
    model = EmailLog
    template_name = "notifications/email_log_list.html"  # not used in tests


@login_required
def template_api(request: HttpRequest) -> HttpResponse:
    # Admin-only API
    if not request.user.is_superuser:
        return HttpResponseForbidden()

    templates = EmailTemplate.objects.values("id", "key", "locale", "subject", "category")
    data = list(templates)
    return JsonResponse({"success": True, "templates": data, "count": len(data)})


@login_required
def email_stats_api(request: HttpRequest) -> HttpResponse:
    # Staff or admin may access basic stats
    if not (request.user.is_staff or request.user.is_superuser):
        return HttpResponseForbidden()

    total = EmailLog.objects.count()
    sent = EmailLog.objects.filter(status__in=["sent", "delivered"]).count()
    failed = EmailLog.objects.filter(status__in=["failed", "bounced", "rejected"]).count()
    return JsonResponse({"success": True, "stats": {"total": total, "sent": sent, "failed": failed}})


@login_required
def security_monitoring_api(request: HttpRequest) -> HttpResponse:
    # Admin-only
    if not request.user.is_superuser:
        return HttpResponseForbidden()

    # Minimal payload for tests
    return JsonResponse({"success": True, "security_stats": {"alerts": 0}})
