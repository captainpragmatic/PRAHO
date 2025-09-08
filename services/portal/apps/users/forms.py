"""
Portal Customer Forms
Customer-facing forms with dark theme styling and Platform API integration.
"""

import re
import logging
from typing import Any, Dict, Optional
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

from apps.api_client.services import api_client, PlatformAPIError

logger = logging.getLogger(__name__)

# Romanian VAT number validation constants
MIN_VAT_DIGITS = 6


class CustomerLoginForm(forms.Form):
    """
    Customer login form with dark theme styling.
    Authenticates against Platform API service.
    """
    
    email = forms.EmailField(
        label=_("Email Address"),
        widget=forms.EmailInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('your@company.com'),
            'autofocus': True,
        })
    )
    
    password = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('Your password'),
        })
    )
    
    remember_me = forms.BooleanField(
        label=_("Remember me for 30 days"),
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800'
        })
    )


class CustomerRegistrationForm(forms.Form):
    """
    Customer registration form with Romanian business context.
    Sends registration data to Platform API for processing.
    """
    
    # ===============================================================================
    # USER INFORMATION
    # ===============================================================================
    
    email = forms.EmailField(
        label=_("Email Address"),
        help_text=_("This will be used for authentication and billing notifications."),
        widget=forms.EmailInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('your@company.com'),
        })
    )
    
    first_name = forms.CharField(
        label=_("First Name"),
        max_length=30,
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('Ion'),
        })
    )
    
    last_name = forms.CharField(
        label=_("Last Name"),
        max_length=30,
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('Popescu'),
        })
    )
    
    phone = forms.CharField(
        label=_("Phone Number"),
        required=False,
        help_text=_("Romanian phone number (+40.XX.XXX.XXXX)"),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': '+40.21.123.4567',
        })
    )
    
    password1 = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('Minimum 12 characters'),
        })
    )
    
    password2 = forms.CharField(
        label=_("Confirm Password"),
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('Repeat password'),
        })
    )
    
    # ===============================================================================
    # COMPANY INFORMATION
    # ===============================================================================
    
    customer_type = forms.ChoiceField(
        label=_("Organization Type"),
        choices=[
            ('srl', _('SRL (Limited Liability Company)')),
            ('pfa', _('PFA (Authorized Individual)')),
            ('sa', _('SA (Joint Stock Company)')),
            ('ong', _('ONG (Non-Profit Organization)')),
            ('individual', _('Individual')),
        ],
        initial='srl',
        help_text=_("Select your business type for proper invoicing and VAT handling."),
        widget=forms.Select(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500',
            'onchange': 'toggleIndividualFields(this.value)'
        })
    )
    
    company_name = forms.CharField(
        label=_("Company/Organization Name"),
        max_length=255,
        help_text=_("Official name as it appears on legal documents."),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('Your Company SRL'),
        })
    )
    
    vat_number = forms.CharField(
        label=_("VAT Number"),
        max_length=20,
        required=False,
        help_text=_("Romanian VAT number (RO12345678) - required for VAT registered companies."),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': 'RO12345678',
            'id': 'id_vat_number'
        })
    )
    
    cnp = forms.CharField(
        label=_("CNP (Cod Numeric Personal)"),
        max_length=13,
        required=False,
        help_text=_("Romanian Personal Identification Number - required for individuals."),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': '1234567890123',
            'id': 'id_cnp'
        })
    )
    
    # ===============================================================================
    # ADDRESS INFORMATION
    # ===============================================================================
    
    address_line1 = forms.CharField(
        label=_("Address"),
        max_length=200,
        help_text=_("Street address of your business."),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('Str. Example Nr. 123'),
        })
    )
    
    city = forms.CharField(
        label=_("City"),
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('București'),
        })
    )
    
    county = forms.CharField(
        label=_("County"),
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('București'),
        })
    )
    
    postal_code = forms.CharField(
        label=_("Postal Code"),
        max_length=10,
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': '010001',
        })
    )
    
    # ===============================================================================
    # GDPR COMPLIANCE
    # ===============================================================================
    
    data_processing_consent = forms.BooleanField(
        label=_("I agree to data processing according to GDPR"),
        help_text=_("Required: Agreement to process personal data according to GDPR."),
        widget=forms.CheckboxInput(attrs={
            'class': 'h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800'
        })
    )
    
    marketing_consent = forms.BooleanField(
        label=_("I agree to receive marketing communications"),
        required=False,
        help_text=_("Optional: Receive newsletters and product updates."),
        widget=forms.CheckboxInput(attrs={
            'class': 'h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800'
        })
    )
    
    terms_accepted = forms.BooleanField(
        label=_("I accept the terms and conditions"),
        help_text=_("Required: Agreement to terms of service."),
        widget=forms.CheckboxInput(attrs={
            'class': 'h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800'
        })
    )
    
    def clean_email(self) -> str:
        email = self.cleaned_data.get('email', '').lower().strip()
        return email
    
    def clean_password2(self) -> str:
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        
        if password1 and password2 and password1 != password2:
            raise ValidationError(_("The two password fields didn't match."))
        
        if password1 and len(password1) < 12:
            raise ValidationError(_("Password must be at least 12 characters long."))
            
        return password2 or ''
    
    def clean_phone(self) -> str:
        """Validate Romanian phone number format"""
        phone = self.cleaned_data.get('phone', '').strip()
        if phone:
            # Romanian phone patterns: +40.XX.XXX.XXXX, +40 XXX XXX XXX, 07XXXXXXXX
            if not re.match(r"^(\+40[\.\s]*[0-9][\.\s0-9]{8,11}[0-9]|0[0-9]{9})$", phone):
                raise ValidationError(_("Invalid phone number format. Use Romanian format: +40.XX.XXX.XXXX"))
        return phone
    
    def clean_vat_number(self) -> str:
        """Validate VAT number format"""
        vat_number = self.cleaned_data.get('vat_number', '').strip()
        if vat_number:
            if not vat_number.startswith("RO"):
                if vat_number.isdigit() and len(vat_number) >= MIN_VAT_DIGITS:
                    vat_number = f"RO{vat_number}"
                else:
                    raise ValidationError(_("VAT number must start with RO followed by digits (e.g., RO12345678)"))
            else:
                vat_digits = vat_number[2:]
                if not vat_digits.isdigit() or len(vat_digits) < MIN_VAT_DIGITS:
                    raise ValidationError(_("VAT number must start with RO followed by digits (e.g., RO12345678)"))
        return vat_number
    
    def clean_cnp(self) -> str:
        """Validate Romanian CNP (Cod Numeric Personal) format"""
        cnp = self.cleaned_data.get('cnp', '').strip()
        if cnp:
            # CNP must be exactly 13 digits
            if not cnp.isdigit() or len(cnp) != 13:
                raise ValidationError(_("CNP must be exactly 13 digits."))
            
            # Basic CNP checksum validation (simplified)
            # Full validation would include birth date validation, county codes, etc.
            if cnp[0] not in '1234567890':  # Valid century markers
                raise ValidationError(_("Invalid CNP format."))
                
        return cnp
    
    def clean(self):
        """Custom validation that depends on multiple fields"""
        cleaned_data = super().clean()
        customer_type = cleaned_data.get('customer_type')
        vat_number = cleaned_data.get('vat_number')
        cnp = cleaned_data.get('cnp')
        
        # Validate that individuals have CNP, companies have VAT
        if customer_type == 'individual':
            if not cnp:
                raise ValidationError({
                    'cnp': _('CNP is required for individuals.')
                })
            if vat_number:
                # Clear VAT number for individuals
                cleaned_data['vat_number'] = ''
        else:
            # For companies, CNP should be cleared
            if cnp:
                cleaned_data['cnp'] = ''
                
        return cleaned_data
    
    def register_customer(self) -> Optional[Dict[str, Any]]:
        """
        Register customer via Platform API.
        Returns customer data on success, None on failure.
        """
        try:
            registration_data = {
                'user_data': {
                    'email': self.cleaned_data['email'],
                    'first_name': self.cleaned_data['first_name'],
                    'last_name': self.cleaned_data['last_name'],
                    'phone': self.cleaned_data.get('phone', ''),
                    'password': self.cleaned_data['password1'],
                },
                'customer_data': {
                    'customer_type': self.cleaned_data['customer_type'],
                    'company_name': self.cleaned_data['company_name'],
                    'vat_number': self.cleaned_data.get('vat_number', ''),
                    'cnp': self.cleaned_data.get('cnp', ''),
                    'address_line1': self.cleaned_data['address_line1'],
                    'city': self.cleaned_data['city'],
                    'county': self.cleaned_data['county'],
                    'postal_code': self.cleaned_data['postal_code'],
                    'data_processing_consent': self.cleaned_data['data_processing_consent'],
                    'marketing_consent': self.cleaned_data.get('marketing_consent', False),
                }
            }
            
            # Call Platform API for customer registration
            response = api_client._make_request('POST', '/customers/register/', data=registration_data)
            return response
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Portal Registration] Platform API error: {e}")
            return None
        except Exception as e:
            logger.error(f"🔥 [Portal Registration] Unexpected error: {e}")
            return None


class CustomerProfileForm(forms.Form):
    """
    Customer profile editing form with dark theme.
    Updates customer data via Platform API.
    """
    
    first_name = forms.CharField(
        label=_("First Name"),
        max_length=30,
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400'
        })
    )
    
    last_name = forms.CharField(
        label=_("Last Name"),
        max_length=30,
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400'
        })
    )
    
    phone = forms.CharField(
        label=_("Phone Number"),
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': '+40.21.123.4567',
        })
    )
    
    preferred_language = forms.ChoiceField(
        label=_("Preferred Language"),
        choices=[
            ('ro', _('Română')),
            ('en', _('English')),
        ],
        initial='ro',
        widget=forms.Select(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
        })
    )
    
    timezone = forms.ChoiceField(
        label=_("Timezone"),
        choices=[
            ('Europe/Bucharest', _('Europe/Bucharest (Romania)')),
            ('UTC', _('UTC (Universal Time)')),
            ('Europe/London', _('Europe/London')),
            ('Europe/Paris', _('Europe/Paris')),
        ],
        initial='Europe/Bucharest',
        widget=forms.Select(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
        })
    )
    
    email_notifications = forms.BooleanField(
        label=_("Email notifications"),
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800'
        })
    )
    
    sms_notifications = forms.BooleanField(
        label=_("SMS notifications"),
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800'
        })
    )
    
    marketing_emails = forms.BooleanField(
        label=_("Marketing emails"),
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800'
        })
    )
    
    def clean_phone(self) -> str:
        """Validate Romanian phone number format"""
        phone = self.cleaned_data.get('phone', '').strip()
        if phone:
            if not re.match(r"^(\+40[\.\s]*[0-9][\.\s0-9]{8,11}[0-9]|0[0-9]{9})$", phone):
                raise ValidationError(_("Invalid phone number format. Use Romanian format: +40.XX.XXX.XXXX"))
        return phone


class TwoFactorSetupForm(forms.Form):
    """Two-factor authentication setup form with dark theme"""
    
    token = forms.CharField(
        label=_("Verification Code"),
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg text-center focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': '123456',
            'autocomplete': 'off',
            'pattern': '[0-9]{6}',
            'inputmode': 'numeric',
        }),
        help_text=_("Enter the code from the authenticator app"),
    )
    
    def clean_token(self) -> str:
        token = self.cleaned_data.get('token', '').strip()
        if token and not token.isdigit():
            raise ValidationError(_("The code must contain only digits."))
        return token


class TwoFactorVerifyForm(forms.Form):
    """Two-factor authentication verification form with dark theme"""
    
    token = forms.CharField(
        label=_("2FA Code"),
        max_length=8,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg text-center focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': '123456',
            'autocomplete': 'off',
            'autofocus': True,
            'pattern': '[0-9]{6,8}',
            'inputmode': 'numeric',
        }),
        help_text=_("Enter the code from the authenticator app or backup code"),
    )
    
    def clean_token(self) -> str:
        token = self.cleaned_data.get('token', '').strip()
        if token and not token.isdigit():
            raise ValidationError(_("The code must contain only digits."))
        return token


class PasswordResetRequestForm(forms.Form):
    """Password reset request form with dark theme"""
    
    email = forms.EmailField(
        label=_("Email Address"),
        widget=forms.EmailInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('your@company.com'),
            'autofocus': True,
        }),
        help_text=_("Enter the email associated with your account."),
    )


class ChangePasswordForm(forms.Form):
    """Change password form for authenticated users"""
    
    current_password = forms.CharField(
        label=_("Current Password"),
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('Enter your current password'),
            'autocomplete': 'current-password',
        }),
        help_text=_("Enter your current password to verify identity."),
    )
    
    new_password = forms.CharField(
        label=_("New Password"),
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('Enter your new password'),
            'autocomplete': 'new-password',
        }),
        help_text=_("Choose a strong password with at least 8 characters."),
    )
    
    confirm_password = forms.CharField(
        label=_("Confirm New Password"),
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400',
            'placeholder': _('Confirm your new password'),
            'autocomplete': 'new-password',
        }),
        help_text=_("Re-enter your new password to confirm."),
    )
    
    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')
        
        if new_password and confirm_password:
            if new_password != confirm_password:
                raise ValidationError(_("New password and confirmation don't match."))
                
        if new_password and len(new_password) < 8:
            raise ValidationError(_("Password must be at least 8 characters long."))
            
        return cleaned_data