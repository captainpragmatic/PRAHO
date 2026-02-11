"""
URL configuration for PRAHO Portal Service
Customer-facing URLs only - authentication handled via platform API.
"""

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.shortcuts import redirect
from django.urls import include, path

from apps.common.views import cookie_consent_view, cookie_policy_view


# Portal status endpoint
def portal_status(request: HttpRequest) -> JsonResponse:
    return JsonResponse({'status': 'healthy', 'service': 'portal'})

urlpatterns = [
    # Authentication - login/logout
    path('', include('apps.users.urls')),
    
    # Dashboard - main customer interface  
    path('dashboard/', include('apps.dashboard.urls')),
    
    # Billing - customer invoices and payments
    path('billing/', include('apps.billing.urls')),
    
    # Support tickets - customer support
    path('tickets/', include('apps.tickets.urls')),
    
    # Hosting services - customer service management
    path('services/', include('apps.services.urls')),
    
    # Order flow - product catalog and cart management
    path('order/', include('apps.orders.urls')),
    
    # GDPR / Legal pages (public, no auth required)
    path('cookie-policy/', cookie_policy_view, name='cookie_policy'),
    path('api/cookie-consent/', cookie_consent_view, name='cookie_consent'),

    # API client health check
    path('status/', portal_status, name='portal_status'),

    # API proxy endpoints
    path('api/', include('apps.api_client.urls')),

    # Internationalization (language switch)
    path('i18n/', include('django.conf.urls.i18n')),
    
    # Root redirect to login
    path('', lambda request: redirect('/login/') if not request.COOKIES.get('portal_token') else redirect('/dashboard/'), name='root'),
]

# ===============================================================================
# DEVELOPMENT URLS (Debug toolbar)
# ===============================================================================

if settings.DEBUG and "debug_toolbar" in settings.INSTALLED_APPS:
        import debug_toolbar  # type: ignore[import-untyped]

        urlpatterns = [path("__debug__/", include(debug_toolbar.urls)), *urlpatterns]
