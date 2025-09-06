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
from apps.users.forms import CustomerLoginForm

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
                    request.session['customer_id'] = customer_id
                    request.session['email'] = email
                    request.session['authenticated_at'] = timezone.now().isoformat()
                    
                    # Set session expiry: 30 days or 24 hours
                    session_age = 2592000 if remember_me else 86400  # 30 days or 24 hours
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
    
    return render(request, 'auth/login.html', context)


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