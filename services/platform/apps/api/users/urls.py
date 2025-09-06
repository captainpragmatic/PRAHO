"""
Authentication API URLs for platform service
"""

from django.urls import path
from . import views

urlpatterns = [
    # Legacy portal service endpoints  
    path('login/', views.portal_login_api, name='portal_login'),
    path('user/', views.user_info_api, name='user_info'),
    path('health/', views.health_check, name='health_check'),
    
    # Secure session validation (OWASP compliant - no ID enumeration)
    path('session/validate/', views.validate_session_secure, name='validate_session_secure'),
    
    # Token authentication endpoints for API access
    path('token/', views.obtain_token, name='obtain_token'),
    path('token/revoke/', views.revoke_token, name='revoke_token'), 
    path('token/verify/', views.verify_token, name='verify_token'),
]