"""
URL configuration for PRAHO Platform
Romanian hosting provider with security-first routing.
"""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin

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
        return RedirectView.as_view(url="/dashboard/", permanent=False)(request)
    else:
        return RedirectView.as_view(url="/users/login/", permanent=False)(request)


urlpatterns = [
    # Root redirect - to dashboard if authenticated, to login if not
    path("", root_redirect, name="root"),
    # Django admin interface
    path("admin/", admin.site.urls),
    # Dashboard - main app after login
    path("dashboard/", dashboard_view, name="dashboard"),
    # Authentication URLs
    path("auth/", include("apps.users.urls")),
    # Backward-compatible alias expected by some tests
    path("users/", include("apps.users.urls")),
    # Django i18n for language switching
    path("i18n/", include("django.conf.urls.i18n")),
    # Core business apps
    path("customers/", include("apps.customers.urls")),
    path("products/", include("apps.products.urls")),
    path("orders/", include("apps.orders.urls")),
    path("order/", include("apps.orders.urls")),  # Singular alias for cart operations
    path("billing/", include("apps.billing.urls")),
    path("tickets/", include("apps.tickets.urls")),
    path("provisioning/", include("apps.provisioning.urls")),
    path("domains/", include("apps.domains.urls")),
    # Notifications (admin/staff tools)
    path("notifications/", include("apps.notifications.urls")),
    # External integrations & webhooks
    path("integrations/", include("apps.integrations.urls")),
    # GDPR compliance and audit
    path("audit/", include("apps.audit.urls")),
    # System configuration (staff only)
    path("settings/", include("apps.settings.urls")),
    # Centralized API endpoints (v1)
    path("api/", include("apps.api.urls")),
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
