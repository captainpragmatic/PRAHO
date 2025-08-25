"""
User signals for PRAHO Platform
Auto-creation of user profiles and audit logging.
"""

from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import User, UserProfile


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Create user profile when user is created"""
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Save user profile when user is saved"""
    if hasattr(instance, 'profile'):
        instance.profile.save()


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    """Log successful user login"""
    # 🚨 DISABLED: Login logging now handled in login view with account lockout integration
    # UserLoginLog.objects.create(
    #     user=user,
    #     ip_address=_get_client_ip(request),
    #     user_agent=request.META.get('HTTP_USER_AGENT', ''),
    #     status='success'
    # )


@receiver(user_login_failed)
def log_failed_login(sender, credentials, request, **kwargs):
    """Log failed login attempt"""
    # 🚨 DISABLED: Failed login logging now handled in login view with account lockout integration
    # email = credentials.get('username') or credentials.get('email')
    #
    # if email:
    #     try:
    #         user = User.objects.get(email=email)
    #         UserLoginLog.objects.create(
    #             user=user,
    #             ip_address=_get_client_ip(request),
    #             user_agent=request.META.get('HTTP_USER_AGENT', ''),
    #             status='failed_password'
    #         )
    #     except User.DoesNotExist:
    #         # Create anonymous failed login log
    #         UserLoginLog.objects.create(
    #             user=None,
    #             ip_address=_get_client_ip(request),
    #             user_agent=request.META.get('HTTP_USER_AGENT', ''),
    #             status='failed_password'
    #         )


def _get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR', '127.0.0.1')

    # Ensure we always return a valid IP address
    return ip if ip else '127.0.0.1'
