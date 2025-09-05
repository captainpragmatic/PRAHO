"""
PRAHO Portal - URL Configuration
Customer-facing service URLs (NO admin interface)
"""

from django.urls import path, include

urlpatterns = [
    # Portal customer interface
    path('', include('portal.urls')),
    
    # API endpoints for AJAX calls
    path('api/', include('portal.api_urls')),
]
