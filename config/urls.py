"""
URL configuration for PRAHO Platform
Romanian hosting provider with security-first routing.
"""

from django.conf import settings
from django.conf.urls.static import static

# ===============================================================================
# MAIN URL PATTERNS
# ===============================================================================
from django.http import HttpRequest
from django.http.response import HttpResponseBase
from django.urls import include, path
from django.views.generic import RedirectView

# Import dashboard view
from apps.common.views import dashboard_view


def root_redirect(request: HttpRequest) -> HttpResponseBase:
    """Redirect root URL based on authentication status"""
    if request.user.is_authenticated:
        return RedirectView.as_view(url="/app/", permanent=False)(request)
    else:
        return RedirectView.as_view(url="/auth/login/", permanent=False)(request)


urlpatterns = [
    # Root redirect - to dashboard if authenticated, to login if not
    path("", root_redirect, name="root"),
    # Dashboard - main app after login
    path("app/", dashboard_view, name="dashboard"),
    # Authentication URLs
    path("auth/", include("apps.users.urls")),
    # Backward-compatible alias expected by some tests
    path("users/", include("apps.users.urls")),
    # Django i18n for language switching
    path("i18n/", include("django.conf.urls.i18n")),
    # Core business apps
    path("app/customers/", include("apps.customers.urls")),
    path("app/products/", include("apps.products.urls")),
    path("app/orders/", include("apps.orders.urls")),
    path("app/billing/", include("apps.billing.urls")),
    path("app/tickets/", include("apps.tickets.urls")),
    path("app/provisioning/", include("apps.provisioning.urls")),
    path("app/domains/", include("apps.domains.urls")),
    # Notifications (admin/staff tools)
    path("app/notifications/", include("apps.notifications.urls")),
    # External integrations & webhooks
    path("integrations/", include("apps.integrations.urls")),
    # GDPR compliance and audit
    path("app/audit/", include("apps.audit.urls")),
    # System configuration (staff only)
    path("app/settings/", include("apps.settings.urls")),
    # API endpoints
    path("api/customers/", include("apps.customers.urls")),
    # Background job monitoring (DISABLED - Redis not needed yet)
    # path('django-rq/', include('django_rq.urls')),  # noqa: ERA001
]

# ===============================================================================
# DEVELOPMENT URLS (Debug toolbar, static files)
# ===============================================================================

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

    # Debug toolbar
    if "debug_toolbar" in settings.INSTALLED_APPS:
        import debug_toolbar  # type: ignore[import-untyped]

        urlpatterns = [path("__debug__/", include(debug_toolbar.urls)), *urlpatterns]
