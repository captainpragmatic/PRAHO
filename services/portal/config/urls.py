"""
URL configuration for PRAHO Portal Service
Customer-facing URLs only - authentication handled via platform API.
"""

from django.urls import include, path
from django.http import JsonResponse
from django.shortcuts import redirect

# Portal status endpoint
def portal_status(request):
    return JsonResponse({'status': 'healthy', 'service': 'portal'})

urlpatterns = [
    # Authentication - login/logout
    path('', include('apps.users.urls')),
    
    # Dashboard - main customer interface  
    path('dashboard/', include('apps.dashboard.urls')),
    
    # API client health check
    path('status/', portal_status, name='portal_status'),
    
    # Root redirect to login
    path('', lambda request: redirect('/login/') if not request.COOKIES.get('portal_token') else redirect('/dashboard/'), name='root'),
]