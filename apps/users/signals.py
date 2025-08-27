"""
User signals for PRAHO Platform
Auto-creation of user profiles and audit logging.
"""

from typing import Any, Type
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.http import HttpRequest

from .models import User, UserProfile


@receiver(post_save, sender=User)
def create_user_profile(sender: Type[User], instance: User, created: bool, **kwargs: Any) -> None:
    """Create user profile when user is created"""
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender: Type[User], instance: User, **kwargs: Any) -> None:
    """Save user profile when user is saved"""
    if hasattr(instance, 'profile'):
        instance.profile.save()


@receiver(user_logged_in)
def log_user_login(sender: Any, request: HttpRequest, user: User, **kwargs: Any) -> None:
    """Log successful user login"""
    # 🚨 DISABLED: Login logging now handled in login view with account lockout integration
    pass


@receiver(user_login_failed)
def log_failed_login(sender: Any, credentials: dict[str, Any], request: HttpRequest, **kwargs: Any) -> None:
    """Log failed login attempt"""
    # 🚨 DISABLED: Failed login logging now handled in login view with account lockout integration
    pass


def _get_client_ip(request: HttpRequest) -> str:
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR', '127.0.0.1')

    # Ensure we always return a valid IP address
    return ip if ip else '127.0.0.1'
