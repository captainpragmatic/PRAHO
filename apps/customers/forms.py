# ===============================================================================
# CUSTOMER FORMS - NORMALIZED MODEL STRUCTURE
# ===============================================================================

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar, cast

from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.forms.models import ModelChoiceField  # For form field type checking
from django.utils.translation import gettext_lazy as _

from apps.users.models import CustomerMembership

from .models import (
    Customer,
    CustomerAddress,
    CustomerBillingProfile,
    CustomerNote,
    CustomerTaxProfile,
)

if TYPE_CHECKING:
    from apps.users.models import User
else:
    User = get_user_model()


# ===============================================================================
# CORE CUSTOMER FORM (SIMPLIFIED)
# ===============================================================================

class CustomerForm(forms.ModelForm):
    """
    Core customer information form.
    Only essential identifying information.
    """

    class Meta:
        model = Customer
        fields: ClassVar[list[str]] = (
            'name',
            'customer_type',
            'company_name',
            'primary_email',
            'primary_phone',
            'industry',
            'website',
            'data_processing_consent',
            'marketing_consent'
        )

        widgets: ClassVar[dict[str, forms.Widget]] = {
            'name': forms.TextInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('Customer name/designation')
            }),
            'company_name': forms.TextInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('SC EXAMPLE SRL')
            }),
            'primary_email': forms.EmailInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('contact@example.com')
            }),
            'primary_phone': forms.TextInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('+40 721 123 456')
            }),
            'industry': forms.TextInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('IT & Software')
            }),
            'website': forms.URLInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('https://example.com')
            }),
        }

    def clean_company_name(self) -> str:
        """Require company name for companies"""
        customer_type: str | None = self.cleaned_data.get('customer_type')
        company_name: str | None = self.cleaned_data.get('company_name')

        if customer_type == 'company' and not company_name:
            raise ValidationError(_('Company name is required for companies'))

        return cast(str, company_name or '')


# ===============================================================================
# TAX PROFILE FORM (ROMANIAN COMPLIANCE)
# ===============================================================================

class CustomerTaxProfileForm(forms.ModelForm):
    """
    Romanian tax compliance form - CUI, VAT, registration.
    """

    class Meta:
        model = CustomerTaxProfile
        fields: ClassVar[list[str]] = (
            'cui',
            'registration_number',
            'is_vat_payer',
            'vat_number',
            'vat_rate',
            'reverse_charge_eligible'
        )

        widgets: ClassVar[dict[str, forms.Widget]] = {
            'cui': forms.TextInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('RO12345678')
            }),
            'vat_number': forms.TextInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('RO12345678')
            }),
            'registration_number': forms.TextInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('J40/1234/2023')
            }),
            'vat_rate': forms.NumberInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'step': '0.01',
                'min': '0',
                'max': '100'
            }),
        }

    def clean_cui(self) -> str:
        """Validate Romanian CUI format"""
        cui: str | None = self.cleaned_data.get('cui')
        if cui and not re.match(r'^RO\d{2,10}$', cui):
            raise ValidationError(_('CUI must be in format RO followed by 2-10 digits'))
        return cast(str, cui or '')

    def clean_vat_number(self) -> str:
        """Validate VAT number format"""
        vat_number: str | None = self.cleaned_data.get('vat_number')
        is_vat_payer: bool | None = self.cleaned_data.get('is_vat_payer')

        if is_vat_payer and not vat_number:
            raise ValidationError(_('VAT number is required for VAT payers'))

        if vat_number and not re.match(r'^RO\d{2,10}$', vat_number):
            raise ValidationError(_('VAT number must be in format RO followed by 2-10 digits'))

        return cast(str, vat_number or '')


# ===============================================================================
# BILLING PROFILE FORM
# ===============================================================================

class CustomerBillingProfileForm(forms.ModelForm):
    """
    Customer billing and financial information form.
    """

    class Meta:
        model = CustomerBillingProfile
        fields: ClassVar[list[str]] = (
            'payment_terms',
            'credit_limit',
            'preferred_currency',
            'invoice_delivery_method',
            'auto_payment_enabled'
        )

        widgets: ClassVar[dict[str, forms.Widget]] = {
            'payment_terms': forms.NumberInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'min': '1',
                'max': '365'
            }),
            'credit_limit': forms.NumberInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'step': '0.01',
                'min': '0'
            }),
        }

    def clean_credit_limit(self) -> float:
        """Ensure credit limit is not negative"""
        credit_limit: float | None = self.cleaned_data.get('credit_limit')
        if credit_limit is not None and credit_limit < 0:
            raise ValidationError(_('Credit limit cannot be negative'))
        return credit_limit or 0.0


# ===============================================================================
# ADDRESS FORM
# ===============================================================================

class CustomerAddressForm(forms.ModelForm):
    """
    Customer address form with Romanian fields.
    """

    class Meta:
        model = CustomerAddress
        fields: ClassVar[list[str]] = (
            'address_type',
            'address_line1',
            'address_line2',
            'city',
            'county',
            'postal_code',
            'country'
        )

        widgets: ClassVar[dict[str, forms.Widget]] = {
            'address_line1': forms.TextInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('Example Street, no. 123')
            }),
            'address_line2': forms.TextInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('Block A, Apt. 45 (optional)')
            }),
            'city': forms.TextInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('Bucharest')
            }),
            'county': forms.TextInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('Sector 1 / Cluj')
            }),
            'postal_code': forms.TextInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('010101')
            }),
            'country': forms.TextInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'value': _('Romania')
            }),
        }

    def clean_postal_code(self) -> str:
        """Validate Romanian postal code format"""
        postal_code: str | None = self.cleaned_data.get('postal_code')
        country: str | None = self.cleaned_data.get('country')

        if country == 'România' and postal_code and not re.match(r'^\d{6}$', postal_code):
            raise ValidationError(_('Romanian postal codes must be 6 digits'))

        return cast(str, postal_code or '')


# ===============================================================================
# CUSTOMER NOTE FORM
# ===============================================================================

class CustomerNoteForm(forms.ModelForm):
    """
    Customer interaction notes form.
    """

    class Meta:
        model = CustomerNote
        fields: ClassVar[list[str]] = (
            'note_type',
            'title',
            'content',
            'is_important',
            'is_private'
        )

        widgets: ClassVar[dict[str, forms.Widget]] = {
            'title': forms.TextInput(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'placeholder': _('Note Title')
            }),
            'content': forms.Textarea(attrs={
                'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
                'rows': 4,
                'placeholder': _('Details...')
            }),
        }


# ===============================================================================
# COMPOSITE CUSTOMER CREATION FORM
# ===============================================================================

class CustomerCreationForm(forms.Form):
    """
    Composite form for creating a customer with all profiles.
    Aligned with registration form structure for consistency.
    """

    # User Account Assignment
    user_action = forms.ChoiceField(
        choices=[
            ('create', _('Create new user account')),
            ('link', _('Link existing user')),
            ('skip', _('Skip user assignment'))
        ],
        initial='create',
        label=_('User Account Assignment'),
        help_text=_('Choose how to handle user assignment for this customer'),
        widget=forms.RadioSelect(attrs={
            'class': 'user-action-radio'
        })
    )

    existing_user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        label=_('Existing User'),
        help_text=_('Select an existing user to assign as owner'),
        widget=forms.Select(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:ring-2 focus:ring-blue-500',
            'x-show': "userAction === 'link'",
            'x-cloak': 'true'
        }),
        empty_label=_('Select a user...')
    )

    send_welcome_email = forms.BooleanField(
        initial=True,
        required=False,
        label=_('Send welcome email'),
        help_text=_('Send welcome email with login instructions'),
        widget=forms.CheckboxInput(attrs={
            'class': 'rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500',
            'x-show': "userAction === 'create'",
            'x-cloak': 'true'
        })
    )

    # Personal/Contact Information (matching registration)
    first_name = forms.CharField(
        max_length=150,
        label=_('First Name'),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('First Name')
        })
    )
    last_name = forms.CharField(
        max_length=150,
        label=_('Last Name'),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('Last Name')
        })
    )
    email = forms.EmailField(
        label=_('Primary Email'),
        widget=forms.EmailInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('contact@example.com')
        })
    )
    phone = forms.CharField(
        max_length=20,
        label=_('Primary Phone'),
        help_text=_('Format: +40 21 123 4567 or 0712 345 678'),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('+40 721 123 456')
        })
    )

    # Business Information (matching registration)
    customer_type = forms.ChoiceField(
        choices=Customer.CUSTOMER_TYPE_CHOICES,
        label=_('Customer Type'),
        help_text=_('Individual, company, PFA, or NGO'),
        widget=forms.Select(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:ring-2 focus:ring-blue-500'
        })
    )
    company_name = forms.CharField(
        max_length=255,
        required=False,
        label=_('Company Name'),
        help_text=_('Required for companies, PFA, and NGOs'),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('SC EXAMPLE SRL')
        })
    )
    industry = forms.CharField(
        max_length=100,
        required=False,
        label=_('Industry'),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('IT & Software')
        })
    )
    website = forms.URLField(
        required=False,
        label=_('Website'),
        widget=forms.URLInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('https://example.com')
        })
    )

    # Romanian Tax Information
    cui = forms.CharField(
        max_length=20,
        required=False,
        label=_('CUI/CIF'),
        help_text=_('Format: RO12345678 (6-10 digits after RO)'),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('RO12345678')
        })
    )
    vat_number = forms.CharField(
        max_length=20,
        required=False,
        label=_('VAT Number'),
        help_text=_('Romanian VAT registration number'),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('RO12345678')
        })
    )
    is_vat_payer = forms.BooleanField(
        required=False,
        label=_('VAT Payer'),
        help_text=_('Customer is registered for VAT'),
        widget=forms.CheckboxInput(attrs={
            'class': 'rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500'
        })
    )

    # Address Information (matching registration)
    address_line1 = forms.CharField(
        max_length=200,
        label=_('Address Line 1'),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('Example Street, no. 123')
        })
    )
    address_line2 = forms.CharField(
        max_length=200,
        required=False,
        label=_('Address Line 2'),
        help_text=_('Apartment, suite, unit, building, floor, etc.'),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('Block A, Apt. 45 (optional)')
        })
    )
    city = forms.CharField(
        max_length=100,
        label=_('City'),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('Bucharest')
        })
    )
    county = forms.CharField(
        max_length=100,
        label=_('County'),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('Sector 1 / Cluj')
        })
    )
    postal_code = forms.CharField(
        max_length=10,
        label=_('Postal Code'),
        help_text=_('Romanian postal codes are 6 digits'),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('010101')
        })
    )

    # Billing Configuration
    payment_terms = forms.IntegerField(
        initial=30,
        label=_('Payment Terms (days)'),
        help_text=_('Number of days for payment'),
        widget=forms.NumberInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'min': '1',
            'max': '365'
        })
    )
    credit_limit = forms.DecimalField(
        max_digits=10,
        decimal_places=2,
        initial=0,
        label=_('Credit Limit (RON)'),
        help_text=_('Maximum credit allowed'),
        widget=forms.NumberInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'step': '0.01',
            'min': '0'
        })
    )
    preferred_currency = forms.ChoiceField(
        choices=[('RON', 'RON'), ('EUR', 'EUR'), ('USD', 'USD')],
        initial='RON',
        label=_('Preferred Currency'),
        widget=forms.Select(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:ring-2 focus:ring-blue-500'
        })
    )

    # GDPR Compliance (matching registration)
    data_processing_consent = forms.BooleanField(
        required=True,
        label=_('Data Processing Consent'),
        help_text=_('Customer has given consent for personal data processing according to GDPR'),
        widget=forms.CheckboxInput(attrs={
            'class': 'rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500'
        })
    )
    marketing_consent = forms.BooleanField(
        required=False,
        label=_('Marketing Communications Consent'),
        help_text=_('Customer consents to receive marketing communications'),
        widget=forms.CheckboxInput(attrs={
            'class': 'rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500'
        })
    )

    def clean(self) -> dict[str, Any]:
        """Cross-field validation"""
        cleaned_data = super().clean()
        customer_type: str | None = cleaned_data.get('customer_type')
        company_name: str | None = cleaned_data.get('company_name')
        vat_number: str | None = cleaned_data.get('vat_number')
        is_vat_payer: bool | None = cleaned_data.get('is_vat_payer')
        cui: str | None = cleaned_data.get('cui')
        user_action: str | None = cleaned_data.get('user_action')
        existing_user: User | None = cleaned_data.get('existing_user')
        email: str | None = cleaned_data.get('email')

        # Require company name for companies, PFA, and NGOs
        if customer_type in ['company', 'pfa', 'ngo'] and not company_name:
            raise ValidationError(_('Company name is required for companies, PFA, and NGOs'))

        # Validate CUI format
        if cui and not re.match(r'^RO\d{6,10}$', cui):
            raise ValidationError(_('CUI must be in format RO followed by 6-10 digits'))

        # Validate VAT number format and requirement
        if is_vat_payer and not vat_number:
            raise ValidationError(_('VAT number is required for VAT payers'))

        if vat_number and not re.match(r'^RO\d{6,10}$', vat_number):
            raise ValidationError(_('VAT number must be in format RO followed by 6-10 digits'))

        # User action validation
        if user_action == 'link' and not existing_user:
            raise ValidationError(_('Please select an existing user to link.'))

        if user_action == 'create' and email and User.objects.filter(email=email).exists():
            raise ValidationError(
                _('A user with email {email} already exists. Please choose "Link existing user" instead.').format(email=email)
            )

        return cleaned_data

    def save(self, user: User | None = None) -> dict[str, Any]:
        """Create customer with all related profiles and handle user assignment"""
        data = self.cleaned_data

        # Build customer name from first_name + last_name
        full_name = f"{data['first_name']} {data['last_name']}".strip()

        # Create core customer
        customer = Customer.objects.create(
            name=full_name,
            customer_type=data['customer_type'],
            company_name=data.get('company_name', ''),
            primary_email=data['email'],
            primary_phone=data['phone'],
            industry=data.get('industry', ''),
            website=data.get('website', ''),
            data_processing_consent=data['data_processing_consent'],
            marketing_consent=data.get('marketing_consent', False),
            created_by=user
        )

        # Create tax profile
        CustomerTaxProfile.objects.create(
            customer=customer,
            cui=data.get('cui', ''),
            is_vat_payer=data.get('is_vat_payer', False),
            vat_number=data.get('vat_number', ''),
            vat_rate=19.0 if data.get('is_vat_payer', False) else 0.0
        )

        # Create billing profile
        CustomerBillingProfile.objects.create(
            customer=customer,
            payment_terms=data['payment_terms'],
            credit_limit=data['credit_limit'],
            preferred_currency=data.get('preferred_currency', 'RON')
        )

        # Create primary address
        CustomerAddress.objects.create(
            customer=customer,
            address_type='primary',
            address_line1=data['address_line1'],
            address_line2=data.get('address_line2', ''),
            city=data['city'],
            county=data['county'],
            postal_code=data['postal_code'],
            country='Romania',
            is_current=True
        )

        # Return customer and user action data for view to handle
        return {
            'customer': customer,
            'user_action': data.get('user_action'),
            'existing_user': data.get('existing_user'),
            'send_welcome_email': data.get('send_welcome_email', True)
        }


# ===============================================================================
# USER ASSIGNMENT FORM (for existing customers)
# ===============================================================================

class CustomerUserAssignmentForm(forms.Form):
    """
    🔗 Form for assigning users to existing customers
    Provides the same three options as customer creation
    """

    USER_ACTION_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ('create', _('Create new user account')),
        ('link', _('Link existing user')),
        ('skip', _('Skip user assignment')),
    )

    user_action = forms.ChoiceField(
        choices=USER_ACTION_CHOICES,
        widget=forms.RadioSelect,
        label=_('User Assignment Action'),
        initial='create',
        help_text=_('Choose how to assign a user to this customer')
    )

    # Fields for creating new user
    first_name = forms.CharField(
        max_length=30,
        required=False,
        label=_('First Name'),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('John')
        })
    )

    last_name = forms.CharField(
        max_length=30,
        required=False,
        label=_('Last Name'),
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500',
            'placeholder': _('Doe')
        })
    )

    # Link existing user
    existing_user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        label=_('Select Existing User'),
        help_text=_('Choose a user to link to this customer'),
        widget=forms.Select(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:ring-2 focus:ring-blue-500'
        })
    )

    # User role in customer organization
    role = forms.ChoiceField(
        choices=CustomerMembership.CUSTOMER_ROLE_CHOICES,
        initial='owner',
        label=_('User Role'),
        help_text=_('Role this user will have within the customer organization'),
        widget=forms.Select(attrs={
            'class': 'w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:ring-2 focus:ring-blue-500'
        })
    )

    # Email options
    send_welcome_email = forms.BooleanField(
        required=False,
        initial=True,
        label=_('Send welcome email'),
        help_text=_('Send welcome email with password reset link to new user'),
        widget=forms.CheckboxInput(attrs={
            'class': 'text-blue-600 focus:ring-blue-500 border-slate-500 bg-slate-700 rounded'
        })
    )

    def __init__(self, customer: Customer | None = None, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.customer = customer

        # Exclude users who are already members of this customer
        if customer:
            existing_member_ids = CustomerMembership.objects.filter(
                customer=customer
            ).values_list('user_id', flat=True)

            # Update the queryset for existing_user field
            existing_user_field = self.fields['existing_user']
            if isinstance(existing_user_field, ModelChoiceField):
                existing_user_field.queryset = User.objects.filter(
                    is_active=True
                ).exclude(id__in=existing_member_ids)

    def clean(self) -> dict[str, Any]:
        cleaned_data = super().clean()
        user_action: str | None = cleaned_data.get('user_action')

        if user_action == 'create':
            # Validate required fields for user creation
            if not cleaned_data.get('first_name'):
                self.add_error('first_name', _('First name is required when creating a new user'))
            if not cleaned_data.get('last_name'):
                self.add_error('last_name', _('Last name is required when creating a new user'))

        elif user_action == 'link':
            # Validate existing user selection
            if not cleaned_data.get('existing_user'):
                self.add_error('existing_user', _('Please select a user to link'))

        return cleaned_data

    def save(self, customer: Customer, created_by: User | None) -> dict[str, Any]:
        """
        Process the user assignment
        Returns: Dict with assignment results
        """
        data = self.cleaned_data
        user_action = data['user_action']

        if user_action == 'create':
            # Create new user using customer's email
            return {
                'action': 'create',
                'first_name': data['first_name'],
                'last_name': data['last_name'],
                'role': data['role'],
                'send_welcome_email': data['send_welcome_email']
            }
        elif user_action == 'link':
            # Link existing user
            return {
                'action': 'link',
                'existing_user': data['existing_user'],
                'role': data['role']
            }
        else:  # skip
            return {
                'action': 'skip'
            }
