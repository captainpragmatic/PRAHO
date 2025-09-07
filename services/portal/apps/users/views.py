"""
Portal Users Views
Customer-facing login/logout with Platform API validation using Django sessions.
"""

import logging
from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.utils.translation import gettext as _
from django.contrib import messages
from django.utils import timezone

from apps.api_client.services import api_client, PlatformAPIError
from apps.users.forms import CustomerLoginForm, CustomerRegistrationForm, CustomerProfileForm, PasswordResetRequestForm, ChangePasswordForm

logger = logging.getLogger(__name__)


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    """
    Portal login view using Django sessions.
    Validates credentials via Platform API and creates secure sessions.
    """
    
    # Redirect if already authenticated
    if request.session.get('customer_id'):
        return redirect('/dashboard/')
    
    if request.method == 'GET':
        form = CustomerLoginForm()
    else:  # POST
        form = CustomerLoginForm(request.POST)
        
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            remember_me = form.cleaned_data.get('remember_me', False)
            
            try:
                # Validate credentials via Platform API
                auth_response = api_client.authenticate_customer(email, password)
                
                if auth_response and auth_response.get('valid'):
                    # Successful authentication - create Django session
                    customer_id = auth_response.get('customer_id')
                    
                    logger.info(f"✅ [Portal Auth] Customer {email} authenticated successfully")
                    
                    # ✅ CRITICAL: Prevent session fixation attacks
                    request.session.cycle_key()
                    
                    # Store in Django session (secure, handled by framework)
                    # Note: In legacy code, 'customer_id' stored the platform user_id. Keep it for backward compatibility
                    # and also store an explicit 'user_id'. Middleware will derive an active_customer_id.
                    request.session['customer_id'] = customer_id
                    request.session['user_id'] = customer_id
                    request.session['email'] = email
                    request.session['authenticated_at'] = timezone.now().isoformat()
                    request.session['remember_me'] = remember_me
                    
                    # Set session expiry based on remember me checkbox
                    if remember_me:
                        session_age = settings.SESSION_COOKIE_AGE_REMEMBER_ME  # 30 days
                        logger.info(f"✅ [Portal Session] Extended session set for {email} (30 days)")
                    else:
                        session_age = settings.SESSION_COOKIE_AGE_DEFAULT  # 24 hours  
                        logger.info(f"✅ [Portal Session] Standard session set for {email} (24 hours)")
                    
                    request.session.set_expiry(session_age)
                    
                    messages.success(request, f"✅ Welcome back, {email}!")
                    return redirect('/dashboard/')
                    
                else:
                    logger.warning(f"⚠️ [Portal Auth] Invalid credentials for {email}")
                    messages.error(request, _("Invalid email address or password. Please try again."))
                    
            except PlatformAPIError as e:
                logger.error(f"🔥 [Portal Auth] Platform API error during login: {e}")
                messages.error(request, _("Authentication service is temporarily unavailable. Please try again later."))
            
            except Exception as e:
                logger.error(f"🔥 [Portal Auth] Unexpected error during login: {e}")
                messages.error(request, _("An unexpected error occurred. Please try again."))
    
    context = {
        'form': form,
        'page_title': _('Customer Login'),
        'brand_name': 'PRAHO Portal',
    }
    
    return render(request, 'users/login.html', context)


@never_cache
@require_http_methods(["GET", "POST"])
def logout_view(request: HttpRequest) -> HttpResponse:
    """
    Secure logout using Django session flush (rotates session key).
    """
    
    # Log the logout
    customer_id = request.session.get('customer_id', 'unknown')
    logger.info(f"✅ [Portal Auth] Customer {customer_id} logged out")
    
    if request.method == 'POST':
        # Flush session (secure - rotates session key)
        request.session.flush()
        messages.success(request, _("You have been logged out successfully."))
        return redirect('/login/')
    
    # GET requests redirect to login
    return redirect('/login/')


def check_authentication(request: HttpRequest) -> dict | None:
    """
    Helper function to check if request is authenticated via Django session.
    
    Note: This only checks session existence. For views that need fresh customer data,
    call Platform API directly. Session validation happens at middleware level.
    """
    customer_id = request.session.get('customer_id')
    
    if not customer_id:
        return None
    
    # Return session data - middleware will handle deeper validation if needed
    return {
        'customer_id': customer_id,
        'email': request.session.get('email'),
        'authenticated_at': request.session.get('authenticated_at')
    }


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def register_view(request: HttpRequest) -> HttpResponse:
    """
    Customer registration view using Platform API.
    Creates new customer accounts with Romanian business compliance.
    """
    
    # Redirect if already authenticated
    if request.session.get('customer_id'):
        return redirect('/dashboard/')
    
    if request.method == 'GET':
        form = CustomerRegistrationForm()
    else:  # POST
        form = CustomerRegistrationForm(request.POST)
        
        if form.is_valid():
            try:
                # Register customer via Platform API
                registration_result = form.register_customer()
                
                if registration_result:
                    email = form.cleaned_data['email']
                    logger.info(f"✅ [Portal Registration] Customer {email} registered successfully")
                    
                    messages.success(request, _("Registration successful! You can now login with your credentials."))
                    return redirect('/login/')
                else:
                    messages.error(request, _("Registration failed. Please check your information and try again."))
                    
            except Exception as e:
                logger.error(f"🔥 [Portal Registration] Unexpected error: {e}")
                messages.error(request, _("An unexpected error occurred during registration. Please try again."))
    
    context = {
        'form': form,
        'page_title': _('Customer Registration'),
        'brand_name': 'PRAHO Portal',
    }
    
    return render(request, 'users/register.html', context)


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def profile_view(request: HttpRequest) -> HttpResponse:
    """
    Customer profile management view.
    Updates customer profile via Platform API.
    """
    
    # Check authentication
    if not request.session.get('customer_id'):
        return redirect('/login/')
    
    # Get customer ID from session
    customer_id = request.session.get('customer_id')
    customer_email = request.session.get('email')
    
    if request.method == 'GET':
        # Load current profile data from Platform API
        try:
            # Call Platform API to get current profile data
            from apps.api_client.services import api_client
            profile_data = api_client.get_customer_profile(customer_id)
            
            if profile_data:
                # Initialize form with existing data
                form = CustomerProfileForm(initial={
                    'first_name': profile_data.get('first_name', ''),
                    'last_name': profile_data.get('last_name', ''),
                    'phone': profile_data.get('phone', ''),
                    'preferred_language': profile_data.get('profile', {}).get('preferred_language', 'en'),
                    'timezone': profile_data.get('profile', {}).get('timezone', 'Europe/Bucharest'),
                })
            else:
                form = CustomerProfileForm()
                
        except Exception as e:
            logger.error(f"🔥 [Portal Profile] Error loading profile: {e}")
            messages.error(request, _("Error loading profile data."))
            form = CustomerProfileForm()
    else:  # POST
        form = CustomerProfileForm(request.POST)
        
        if form.is_valid():
            try:
                # Update profile via Platform API
                from apps.api_client.services import api_client
                update_data = {
                    'first_name': form.cleaned_data['first_name'],
                    'last_name': form.cleaned_data['last_name'],
                    'phone': form.cleaned_data['phone'],
                    'preferred_language': form.cleaned_data.get('preferred_language', 'en'),
                    'timezone': form.cleaned_data.get('timezone', 'Europe/Bucharest'),
                }
                
                result = api_client.update_customer_profile(customer_id, update_data)
                
                if result:
                    logger.info(f"✅ [Portal Profile] Profile updated for customer {customer_id}")
                    messages.success(request, _("Profile updated successfully!"))
                    # Redirect to prevent duplicate form submissions
                    return redirect('users:profile')
                else:
                    messages.error(request, _("Error updating profile. Please try again."))
                
            except Exception as e:
                logger.error(f"🔥 [Portal Profile] Error updating profile: {e}")
                messages.error(request, _("Error updating profile. Please try again."))
    
    # Get profile data from Platform API
    profile_data = {}
    try:
        from apps.api_client.services import api_client
        profile_data = api_client.get_customer_profile(customer_id) or {}
    except Exception as e:
        logger.debug(f"Could not load profile data from Platform API: {e}")
    
    # Prepare context with direct API data - no mock objects
    context = {
        'form': form,
        'profile': profile_data,
        'customer_email': customer_email,
        'customer_id': customer_id,
        'page_title': _('Account Settings'),
        'brand_name': 'PRAHO Portal',
    }
    
    return render(request, 'users/profile.html', context)


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def password_reset_view(request: HttpRequest) -> HttpResponse:
    """
    Password reset request view.
    Sends reset email via Platform API.
    """
    
    # Allow authenticated users to reset password
    
    if request.method == 'GET':
        form = PasswordResetRequestForm()
    else:  # POST
        form = PasswordResetRequestForm(request.POST)
        
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                # TODO: Call Platform API to send password reset email
                logger.info(f"✅ [Portal Password Reset] Reset requested for {email}")
                messages.success(request, _("If an account with that email exists, you will receive password reset instructions."))
                return redirect('/login/')
                
            except Exception as e:
                logger.error(f"🔥 [Portal Password Reset] Error requesting reset: {e}")
                messages.error(request, _("Error processing password reset request. Please try again."))
    
    context = {
        'form': form,
        'page_title': _('Password Reset'),
        'brand_name': 'PRAHO Portal',
    }
    
    return render(request, 'users/password_reset.html', context)


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def change_password_view(request: HttpRequest) -> HttpResponse:
    """
    Change password view for authenticated users.
    Allows logged-in users to change their password by providing current password.
    """
    
    # Check authentication - redirect to login if not authenticated
    if not request.session.get('customer_id'):
        return redirect('/login/')
    
    customer_id = request.session.get('customer_id')
    customer_email = request.session.get('email')
    
    if request.method == 'GET':
        form = ChangePasswordForm()
    else:  # POST
        form = ChangePasswordForm(request.POST)
        
        if form.is_valid():
            current_password = form.cleaned_data['current_password']
            new_password = form.cleaned_data['new_password']
            
            try:
                # First verify current password via Platform API
                auth_response = api_client.authenticate_customer(customer_email, current_password)
                
                if not auth_response or not auth_response.get('valid'):
                    logger.warning(f"⚠️ [Portal Change Password] Invalid current password for {customer_email}")
                    messages.error(request, _("Current password is incorrect."))
                else:
                    # Update password via Platform API
                    update_result = api_client.update_customer_password(customer_id, new_password)
                    
                    if update_result:
                        logger.info(f"✅ [Portal Change Password] Password changed successfully for customer {customer_id}")
                        messages.success(request, _("Password changed successfully!"))
                        return redirect('users:profile')
                    else:
                        logger.error(f"🔥 [Portal Change Password] Failed to update password for customer {customer_id}")
                        messages.error(request, _("Error updating password. Please try again."))
                        
            except PlatformAPIError as e:
                logger.error(f"🔥 [Portal Change Password] Platform API error: {e}")
                messages.error(request, _("Authentication service is temporarily unavailable. Please try again later."))
            
            except Exception as e:
                logger.error(f"🔥 [Portal Change Password] Unexpected error: {e}")
                messages.error(request, _("An unexpected error occurred. Please try again."))
    
    context = {
        'form': form,
        'customer_email': customer_email,
        'page_title': _('Change Password'),
        'brand_name': 'PRAHO Portal',
    }
    
    return render(request, 'users/change_password.html', context)


@never_cache
@require_http_methods(["GET"])
def privacy_dashboard_view(request: HttpRequest) -> HttpResponse:
    """
    Privacy dashboard view for authenticated users.
    Displays privacy settings and GDPR controls.
    """
    
    # Check authentication - redirect to login if not authenticated
    if not request.session.get('customer_id'):
        return redirect('/login/')
    
    customer_id = request.session.get('customer_id')
    customer_email = request.session.get('email')
    
    # Get customer profile data with privacy information
    profile_data = {}
    try:
        profile_data = api_client.get_customer_profile(customer_id) or {}
    except Exception as e:
        logger.debug(f"Could not load profile data from Platform API: {e}")
    
    context = {
        'profile': profile_data,
        'customer_email': customer_email,
        'customer_id': customer_id,
        'page_title': _('Privacy Dashboard'),
        'brand_name': 'PRAHO Portal',
    }
    
    return render(request, 'users/privacy_dashboard.html', context)


@never_cache
@require_http_methods(["GET", "POST"])
def data_export_view(request: HttpRequest) -> HttpResponse:
    """
    Data export request view for authenticated users.
    Allows users to request export of their personal data (GDPR Article 20).
    """
    
    # Check authentication - redirect to login if not authenticated
    if not request.session.get('customer_id'):
        return redirect('/login/')
    
    customer_id = request.session.get('customer_id')
    customer_email = request.session.get('email')
    
    if request.method == 'POST':
        # Handle data export request
        try:
            # TODO: Implement actual data export request via Platform API
            logger.info(f"✅ [Portal Data Export] Request submitted for customer {customer_id}")
            messages.success(request, _("Data export request submitted successfully. You will receive an email with download instructions within 48 hours."))
            return redirect('users:data_export')
            
        except Exception as e:
            logger.error(f"🔥 [Portal Data Export] Error processing request: {e}")
            messages.error(request, _("Error processing your data export request. Please try again."))
    
    context = {
        'customer_email': customer_email,
        'customer_id': customer_id,
        'page_title': _('Export My Data'),
        'brand_name': 'PRAHO Portal',
    }
    
    return render(request, 'users/data_export.html', context)


@never_cache
@require_http_methods(["GET"])
def consent_history_view(request: HttpRequest) -> HttpResponse:
    """
    Consent history view for authenticated users.
    Displays history of GDPR consents and marketing preferences.
    """
    
    # Check authentication - redirect to login if not authenticated
    if not request.session.get('customer_id'):
        return redirect('/login/')
    
    customer_id = request.session.get('customer_id')
    customer_email = request.session.get('email')
    
    # Get customer profile data with consent information
    profile_data = {}
    try:
        profile_data = api_client.get_customer_profile(customer_id) or {}
    except Exception as e:
        logger.debug(f"Could not load profile data from Platform API: {e}")
    
    # Mock consent history data - in real implementation this would come from Platform API
    consent_history = [
        {
            'date': '2024-01-15',
            'type': 'GDPR Data Processing',
            'status': 'Granted',
            'description': 'Initial account registration consent'
        },
        {
            'date': '2024-01-15', 
            'type': 'Marketing Communications',
            'status': 'Declined',
            'description': 'Newsletter and promotional emails'
        }
    ]
    
    context = {
        'profile': profile_data,
        'customer_email': customer_email,
        'customer_id': customer_id,
        'consent_history': consent_history,
        'page_title': _('Consent History'),
        'brand_name': 'PRAHO Portal',
    }
    
    return render(request, 'users/consent_history.html', context)


@never_cache
@require_http_methods(["GET"])
def mfa_management_view(request: HttpRequest) -> HttpResponse:
    """
    Multi-factor authentication management view for authenticated users.
    Allows users to enable/disable MFA and manage backup codes.
    """
    
    # Check authentication - redirect to login if not authenticated
    if not request.session.get('customer_id'):
        return redirect('/login/')
    
    customer_id = request.session.get('customer_id')
    customer_email = request.session.get('email')
    
    # Get customer profile data with 2FA status
    profile_data = {}
    try:
        profile_data = api_client.get_customer_profile(customer_id) or {}
    except Exception as e:
        logger.debug(f"Could not load profile data from Platform API: {e}")
    
    # Check if MFA is enabled for this customer
    mfa_enabled = profile_data.get('mfa_enabled', False)
    
    context = {
        'profile': profile_data,
        'customer_email': customer_email,
        'customer_id': customer_id,
        'mfa_enabled': mfa_enabled,
        'page_title': _('Multi-Factor Authentication'),
        'brand_name': 'PRAHO Portal',
    }
    
    return render(request, 'users/mfa_management.html', context)


@never_cache
@require_http_methods(["GET", "POST"])
def mfa_setup_totp_view(request: HttpRequest) -> HttpResponse:
    """
    TOTP (Authenticator App) MFA setup view for authenticated users.
    """
    
    # Check authentication - redirect to login if not authenticated
    if not request.session.get('customer_id'):
        return redirect('/login/')
    
    customer_id = request.session.get('customer_id')
    customer_email = request.session.get('email')
    
    if request.method == 'GET':
        # Initialize TOTP setup
        try:
            totp_data = api_client.setup_totp_mfa(str(customer_id))
            if totp_data:
                context = {
                    'qr_code': totp_data.get('qr_code'),
                    'secret': totp_data.get('secret'),
                    'customer_email': customer_email,
                    'customer_id': customer_id,
                    'page_title': _('Set Up Authenticator App'),
                    'brand_name': 'PRAHO Portal',
                }
                return render(request, 'users/mfa_setup_totp.html', context)
            else:
                messages.error(request, _("Failed to initialize MFA setup. Please try again."))
                return redirect('users:mfa_management')
                
        except Exception as e:
            logger.error(f"🔥 [Portal MFA] Error initializing TOTP setup: {e}")
            messages.error(request, _("An error occurred. Please try again."))
            return redirect('users:mfa_management')
    
    else:  # POST - verify TOTP token
        token = request.POST.get('token', '').strip()
        if not token:
            messages.error(request, _("Please enter the verification code."))
            return redirect('users:mfa_setup_totp')
        
        try:
            success = api_client.verify_totp_mfa(str(customer_id), token)
            if success:
                logger.info(f"✅ [Portal 2FA] TOTP enabled successfully for customer {customer_id}")
                messages.success(request, _("Two-factor authentication has been enabled successfully!"))
                return redirect('users:mfa_management')
            else:
                messages.error(request, _("Invalid verification code. Please try again."))
                return redirect('users:mfa_setup_totp')
                
        except Exception as e:
            logger.error(f"🔥 [Portal 2FA] Error verifying TOTP: {e}")
            messages.error(request, _("An error occurred. Please try again."))
            return redirect('users:mfa_setup_totp')


@never_cache
@require_http_methods(["GET"])
def mfa_backup_codes_view(request: HttpRequest) -> HttpResponse:
    """
    View and regenerate backup codes for authenticated users.
    """
    
    # Check authentication - redirect to login if not authenticated
    if not request.session.get('customer_id'):
        return redirect('/login/')
    
    customer_id = request.session.get('customer_id')
    customer_email = request.session.get('email')
    
    # Check if user has 2FA enabled
    profile_data = {}
    try:
        profile_data = api_client.get_customer_profile(str(customer_id)) or {}
    except Exception as e:
        logger.debug(f"Could not load profile data from Platform API: {e}")
    
    if not profile_data.get('mfa_enabled'):
        messages.warning(request, _("You need to enable 2FA first before accessing backup codes."))
        return redirect('users:mfa_management')
    
    # Get backup codes
    backup_codes = []
    try:
        backup_codes = api_client.get_backup_codes(str(customer_id)) or []
    except Exception as e:
        logger.error(f"🔥 [Portal 2FA] Error getting backup codes: {e}")
        messages.error(request, _("Error loading backup codes."))
    
    context = {
        'backup_codes': backup_codes,
        'customer_email': customer_email,
        'customer_id': customer_id,
        'page_title': _('Backup Codes'),
        'brand_name': 'PRAHO Portal',
    }
    
    return render(request, 'users/mfa_backup_codes.html', context)


@never_cache
@require_http_methods(["POST"])
def mfa_disable_view(request: HttpRequest) -> HttpResponse:
    """
    Disable 2FA for authenticated users.
    """
    
    # Check authentication - redirect to login if not authenticated
    if not request.session.get('customer_id'):
        return redirect('/login/')
    
    customer_id = request.session.get('customer_id')
    
    try:
        success = api_client.disable_mfa(str(customer_id))
        if success:
            logger.info(f"✅ [Portal 2FA] 2FA disabled successfully for customer {customer_id}")
            messages.success(request, _("Two-factor authentication has been disabled."))
        else:
            messages.error(request, _("Failed to disable 2FA. Please try again."))
            
    except Exception as e:
        logger.error(f"🔥 [Portal 2FA] Error disabling 2FA: {e}")
        messages.error(request, _("An error occurred. Please try again."))
    
    return redirect('users:mfa_management')
