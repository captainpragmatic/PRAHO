"""
User signals for PRAHO Platform
Auto-creation of user profiles and comprehensive audit logging.
"""

import logging
from typing import Any

from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.http import HttpRequest

from apps.audit.services import (
    AuthenticationAuditService,
    AuthenticationEventData,
    LoginFailureEventData,
    LogoutEventData,
)

from .models import User, UserProfile

logger = logging.getLogger(__name__)


@receiver(post_save, sender=User)
def create_user_profile(sender: type[User], instance: User, created: bool, **kwargs: Any) -> None:
    """Create user profile when user is created"""
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender: type[User], instance: User, **kwargs: Any) -> None:
    """Save user profile when user is saved"""
    if hasattr(instance, 'profile'):
        instance.profile.save()


@receiver(user_logged_in)
def log_user_login(sender: Any, request: HttpRequest, user: User, **kwargs: Any) -> None:
    """
    Log successful user login via Django signals
    
    This signal handler captures all successful logins regardless of the authentication method.
    It works in conjunction with view-level logging to provide comprehensive coverage.
    """
    try:
        # Determine authentication method based on session data
        authentication_method = 'password'
        
        # Check if this was a 2FA login completion
        if request.session.get('pre_2fa_user_id'):
            # This was a 2FA verification completion
            authentication_method = '2fa_totp'  # Default to TOTP, will be refined in view
            # Clean up 2FA session marker
            if 'pre_2fa_user_id' in request.session:
                del request.session['pre_2fa_user_id']
        
        # Log the successful login
        auth_event_data = AuthenticationEventData(
            user=user,
            request=request,
            authentication_method=authentication_method,
            metadata={
                'signal_triggered': True,
                'login_method': 'django_signal',
                'session_exists': bool(request.session.session_key),
            }
        )
        AuthenticationAuditService.log_login_success(auth_event_data)
        
        logger.info(f"✅ [Auth Signal] Login success logged for {user.email} via {authentication_method}")
        
    except Exception as e:
        # Never let audit logging break authentication
        logger.error(f"🔥 [Auth Signal] Failed to log login for {user.email}: {e}")


@receiver(user_logged_out)
def log_user_logout(sender: Any, request: HttpRequest, user: User | None, **kwargs: Any) -> None:
    """
    Log user logout via Django signals
    
    This signal is triggered after the user has been logged out and session cleared.
    We try to capture as much context as possible before the session is destroyed.
    """
    try:
        if not user:
            logger.warning("⚠️ [Auth Signal] Logout signal triggered with no user")
            return
        
        # Determine logout reason - manual is default for signal-based logout
        logout_reason = 'manual'
        
        # Try to get session context (may be limited after logout)
        session_key = getattr(request.session, 'session_key', None)
        
        logout_event_data = LogoutEventData(
            user=user,
            logout_reason=logout_reason,
            request=request,
            metadata={
                'signal_triggered': True,
                'logout_method': 'django_signal',
                'session_flushed': True,
                'session_key': session_key,
            }
        )
        AuthenticationAuditService.log_logout(logout_event_data)
        
        logger.info(f"✅ [Auth Signal] Logout logged for {user.email}")
        
    except Exception as e:
        # Never let audit logging break logout functionality
        logger.error(f"🔥 [Auth Signal] Failed to log logout: {e}")


@receiver(user_login_failed)
def log_failed_login(sender: Any, credentials: dict[str, Any], request: HttpRequest, **kwargs: Any) -> None:
    """
    Log failed login attempt via Django signals
    
    This signal captures login failures at the authentication backend level.
    It works alongside view-level logging to ensure comprehensive coverage.
    """
    try:
        # Extract attempted email from credentials
        email = credentials.get('username') or credentials.get('email')
        
        # Try to find user to determine failure reason
        user = None
        failure_reason = 'invalid_credentials'
        
        if email:
            try:
                user = User.objects.get(email=email)
                # User exists, so this was likely a password failure
                failure_reason = 'invalid_password'
                
                # Check if account is locked
                if hasattr(user, 'is_account_locked') and user.is_account_locked():
                    failure_reason = 'account_locked'
                
            except User.DoesNotExist:
                failure_reason = 'user_not_found'
        
        failure_event_data = LoginFailureEventData(
            email=email,
            user=user,
            failure_reason=failure_reason,
            request=request,
            metadata={
                'signal_triggered': True,
                'login_method': 'django_signal',
                'backend': kwargs.get('backend_path', 'unknown'),
                'credentials_provided': list(credentials.keys()) if credentials else [],
            }
        )
        AuthenticationAuditService.log_login_failed(failure_event_data)
        
        logger.info(f"✅ [Auth Signal] Login failure logged for {email}: {failure_reason}")
        
    except Exception as e:
        # Never let audit logging break authentication
        logger.error(f"🔥 [Auth Signal] Failed to log login failure: {e}")


def _get_client_ip(request: HttpRequest) -> str:
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR', '127.0.0.1')

    # Ensure we always return a valid IP address
    return ip if ip else '127.0.0.1'
