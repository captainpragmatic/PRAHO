"""
User management views for PRAHO Platform
Romanian-localized authentication and profile forms.
"""

import pyotp
import qrcode
import io
import base64
from typing import Any

from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import ListView, DetailView, UpdateView

from apps.common.utils import (
    require_permission, json_success, json_error,
    get_romanian_now, mask_sensitive_data
)
from .models import User, UserProfile, UserLoginLog, CustomerMembership
from .forms import (
    LoginForm, UserRegistrationForm, UserProfileForm,
    TwoFactorSetupForm, TwoFactorVerifyForm
)
from .forms import CustomerOnboardingRegistrationForm


# ===============================================================================
# AUTHENTICATION VIEWS
# ===============================================================================

def login_view(request: HttpRequest) -> HttpResponse:
    """Romanian-localized login view"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            
            # Check if user exists and account is not locked
            try:
                user = User.objects.get(email=email)
                if user.is_account_locked():
                    messages.error(
                        request,
                        _('Account temporarily locked for security reasons.')
                    )
                    return render(request, 'users/login.html', {'form': form})
            except User.DoesNotExist:
                pass
            
            # Authenticate user
            user = authenticate(request, username=email, password=password)
            
            if user:
                # Regular login
                login(request, user)
                
                messages.success(request, _('Welcome, {user_full_name}!').format(user_full_name=user.get_full_name()))
                
                next_url = request.GET.get('next', 'dashboard')
                return redirect(next_url)
            else:
                messages.error(request, _('Incorrect email or password.'))
    else:
        form = LoginForm()
    
    return render(request, 'users/login.html', {'form': form})


def register_view(request: HttpRequest) -> HttpResponse:
    """Enhanced user registration with proper customer onboarding"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = CustomerOnboardingRegistrationForm(request.POST)
        if form.is_valid():
            try:
                user = form.save()
                messages.success(
                    request, 
                    _('Account created successfully! Please check your email for next steps.')
                )
                return redirect('users:login')
            except ValidationError as e:
                messages.error(request, str(e))
    else:
        form = CustomerOnboardingRegistrationForm()
    
    return render(request, 'users/register.html', {'form': form})


def logout_view(request: HttpRequest) -> HttpResponse:
    """Logout view with Romanian messages"""
    if request.user.is_authenticated:
        messages.success(request, _('You have been successfully logged out.'))
    
    logout(request)
    return redirect('users:login')


# ===============================================================================
# PASSWORD RESET
# ===============================================================================

def password_reset_view(request: HttpRequest) -> HttpResponse:
    """Password reset request view"""
    return HttpResponse(_("Password reset - under development!"), content_type="text/html")


def password_reset_done_view(request: HttpRequest) -> HttpResponse:
    """Password reset done view"""
    return HttpResponse(_("Password reset email sent!"), content_type="text/html")


def password_reset_confirm_view(request: HttpRequest, uidb64: str, token: str) -> HttpResponse:
    """Password reset confirmation view"""
    return HttpResponse(_("Password reset confirmation - under development!"), content_type="text/html")


def password_reset_complete_view(request: HttpRequest) -> HttpResponse:
    """Password reset complete view"""
    return HttpResponse(_("Password reset successfully!"), content_type="text/html")


# ===============================================================================
# TWO-FACTOR AUTHENTICATION
# ===============================================================================

def two_factor_setup(request: HttpRequest) -> HttpResponse:
    """Set up 2FA for user account"""
    if not request.user.is_authenticated:
        return redirect('login')
    
    if request.user.two_factor_enabled:
        messages.info(request, _('2FA is already enabled for your account.'))
        return redirect('user_profile')
    
    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data['token']
            secret = request.session.get('2fa_secret')
            
            if secret and pyotp.TOTP(secret).verify(token):
                # Enable 2FA
                user = request.user
                user.two_factor_secret = secret
                user.two_factor_enabled = True
                user.save()
                
                # Clear session
                del request.session['2fa_secret']
                
                messages.success(
                    request,
                    _('Two-factor authentication has been successfully enabled!')
                )
                return redirect('user_profile')
            else:
                messages.error(request, _('The entered code is invalid.'))
    else:
        form = TwoFactorSetupForm()
        
        # Generate new secret
        secret = pyotp.random_base32()
        request.session['2fa_secret'] = secret
        
        # Generate QR code
        totp = pyotp.TOTP(secret)
        qr_url = totp.provisioning_uri(
            request.user.email,
            issuer_name="PragmaticHost România"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_url)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_buffer = io.BytesIO()
        qr_img.save(qr_buffer, format='PNG')
        qr_data = base64.b64encode(qr_buffer.getvalue()).decode()
        
        form.qr_code = qr_data
        form.secret = secret
    
    return render(request, 'users/two_factor_setup.html', {'form': form})


def two_factor_verify(request: HttpRequest) -> HttpResponse:
    """Verify 2FA token during login"""
    user_id = request.session.get('pre_2fa_user_id')
    if not user_id:
        return redirect('login')
    
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        del request.session['pre_2fa_user_id']
        return redirect('login')
    
    if request.method == 'POST':
        form = TwoFactorVerifyForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data['token']
            
            if pyotp.TOTP(user.two_factor_secret).verify(token):
                # Complete login
                login(request, user)
                del request.session['pre_2fa_user_id']
                
                _log_user_login(request, user, 'success')
                messages.success(request, _('Welcome, {user_full_name}!').format(user_full_name=user.get_full_name()))
                
                next_url = request.GET.get('next', 'dashboard')
                return redirect(next_url)
            else:
                _log_user_login(request, user, 'failed_2fa')
                messages.error(request, _('The 2FA code is invalid.'))
    else:
        form = TwoFactorVerifyForm()
    
    return render(request, 'users/two_factor_verify.html', {
        'form': form,
        'user': user
    })


# ===============================================================================
# USER PROFILE MANAGEMENT
# ===============================================================================

@login_required
def user_profile(request: HttpRequest) -> HttpResponse:
    """User profile view and editing"""
    profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, _('Profile updated successfully.'))
            return redirect('user_profile')
    else:
        form = UserProfileForm(instance=profile)
    
    context = {
        'form': form,
        'profile': profile,
        'user': request.user,
        'accessible_customers': request.user.get_accessible_customers(),
        'recent_logins': UserLoginLog.objects.filter(
            user=request.user,
            status='success'
        ).order_by('-timestamp')[:5],
    }
    
    return render(request, 'users/profile.html', context)


# ===============================================================================
# USER MANAGEMENT (ADMIN)
# ===============================================================================

class UserListView(LoginRequiredMixin, ListView):
    """List all users (admin only)"""
    model = User
    template_name = 'users/user_list.html'
    context_object_name = 'users'
    paginate_by = 50
    
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_staff:
            messages.error(request, _('You do not have permission to access this page.'))
            return redirect('dashboard')
        return super().dispatch(request, *args, **kwargs)
    
    def get_queryset(self):
        queryset = User.objects.select_related('primary_customer').order_by('-date_joined')
        
        # Filter by role
        role = self.request.GET.get('role')
        if role:
            queryset = queryset.filter(role=role)
        
        # Search
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                models.Q(email__icontains=search) |
                models.Q(first_name__icontains=search) |
                models.Q(last_name__icontains=search)
            )
        
        return queryset


class UserDetailView(LoginRequiredMixin, DetailView):
    """User detail view (admin only)"""
    model = User
    template_name = 'users/user_detail.html'
    context_object_name = 'user_detail'
    
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_staff:
            messages.error(request, _('You do not have permission to access this page.'))
            return redirect('dashboard')
        return super().dispatch(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.object
        
        context.update({
            'profile': getattr(user, 'profile', None),
            'accessible_customers': user.get_accessible_customers(),
            'recent_logins': UserLoginLog.objects.filter(
                user=user
            ).order_by('-timestamp')[:10],
            'customer_memberships': CustomerMembership.objects.filter(
                user=user,
                is_active=True
            ).select_related('customer'),
        })
        
        return context


# ===============================================================================
# API ENDPOINTS
# ===============================================================================

@csrf_exempt
@require_http_methods(["POST"])
def api_check_email(request: HttpRequest) -> JsonResponse:
    """Check if email is already registered"""
    email = request.POST.get('email')
    
    if not email:
        return json_error(_('Email is required'))
    
    exists = User.objects.filter(email=email).exists()
    
    return json_success({
        'email': email,
        'exists': exists,
        'message': _('Email available') if not exists else _('Email already in use')
    })


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================

def _log_user_login(request: HttpRequest, user: User, status: str) -> None:
    """Log user login attempt"""
    UserLoginLog.objects.create(
        user=user,
        ip_address=_get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        status=status
    )
    
    # Update user's last login IP
    if status == 'success':
        user.last_login_ip = _get_client_ip(request)
        user.failed_login_attempts = 0  # Reset failed attempts
        user.account_locked_until = None
        user.save(update_fields=['last_login_ip', 'failed_login_attempts', 'account_locked_until'])


def _get_client_ip(request: HttpRequest) -> str:
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR', '')
    return ip
