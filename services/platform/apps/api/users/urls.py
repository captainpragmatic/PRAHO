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
    
    # Multi-Factor Authentication endpoints
    path('mfa/setup/', views.mfa_setup_api, name='mfa_setup'),
    path('mfa/verify/', views.mfa_verify_api, name='mfa_verify'),
    path('mfa/disable/', views.mfa_disable_api, name='mfa_disable'),
    path('mfa/status/', views.mfa_status_api, name='mfa_status'),
    
    # Password Reset endpoints
    path('password/reset/', views.password_reset_request_api, name='password_reset_request'),
    path('password/reset/confirm/', views.password_reset_confirm_api, name='password_reset_confirm'),
    
    # Customer registration and profile management
    path('register/', views.customer_registration_api, name='customer_registration'),
    path('profile/', views.customer_profile_api, name='customer_profile'),

    # Accessible customers for user (HMAC-signed; identity from signed body)
    path('customers/', views.user_customers_api, name='user_customers'),
]
