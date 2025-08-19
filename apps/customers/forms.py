# ===============================================================================
# CUSTOMER FORMS - NORMALIZED MODEL STRUCTURE
# ===============================================================================

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
import re

from .models import (
    Customer, 
    CustomerTaxProfile, 
    CustomerBillingProfile, 
    CustomerAddress, 
    CustomerPaymentMethod,
    CustomerNote
)


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
        fields = [
            'name', 
            'customer_type', 
            'company_name', 
            'primary_email', 
            'primary_phone',
            'industry',
            'website',
            'data_processing_consent', 
            'marketing_consent'
        ]
        
        widgets = {
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
    
    def clean_company_name(self):
        """Require company name for companies"""
        customer_type = self.cleaned_data.get('customer_type')
        company_name = self.cleaned_data.get('company_name')
        
        if customer_type == 'company' and not company_name:
            raise ValidationError(_('Company name is required for companies'))
        
        return company_name


# ===============================================================================
# TAX PROFILE FORM (ROMANIAN COMPLIANCE)
# ===============================================================================

class CustomerTaxProfileForm(forms.ModelForm):
    """
    Romanian tax compliance form - CUI, VAT, registration.
    """
    
    class Meta:
        model = CustomerTaxProfile
        fields = [
            'cui',
            'registration_number', 
            'is_vat_payer',
            'vat_number',
            'vat_rate',
            'reverse_charge_eligible'
        ]
        
        widgets = {
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
    
    def clean_cui(self):
        """Validate Romanian CUI format"""
        cui = self.cleaned_data.get('cui')
        if cui and not re.match(r'^RO\d{2,10}$', cui):
            raise ValidationError(_('CUI must be in format RO followed by 2-10 digits'))
        return cui
    
    def clean_vat_number(self):
        """Validate VAT number format"""
        vat_number = self.cleaned_data.get('vat_number')
        is_vat_payer = self.cleaned_data.get('is_vat_payer')
        
        if is_vat_payer and not vat_number:
            raise ValidationError(_('VAT number is required for VAT payers'))
        
        if vat_number and not re.match(r'^RO\d{2,10}$', vat_number):
            raise ValidationError(_('VAT number must be in format RO followed by 2-10 digits'))
        
        return vat_number


# ===============================================================================
# BILLING PROFILE FORM
# ===============================================================================

class CustomerBillingProfileForm(forms.ModelForm):
    """
    Customer billing and financial information form.
    """
    
    class Meta:
        model = CustomerBillingProfile
        fields = [
            'payment_terms',
            'credit_limit',
            'preferred_currency',
            'invoice_delivery_method',
            'auto_payment_enabled'
        ]
        
        widgets = {
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
    
    def clean_credit_limit(self):
        """Ensure credit limit is not negative"""
        credit_limit = self.cleaned_data.get('credit_limit')
        if credit_limit and credit_limit < 0:
            raise ValidationError(_('Credit limit cannot be negative'))
        return credit_limit


# ===============================================================================
# ADDRESS FORM
# ===============================================================================

class CustomerAddressForm(forms.ModelForm):
    """
    Customer address form with Romanian fields.
    """
    
    class Meta:
        model = CustomerAddress
        fields = [
            'address_type',
            'address_line1',
            'address_line2', 
            'city',
            'county',
            'postal_code',
            'country'
        ]
        
        widgets = {
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
    
    def clean_postal_code(self):
        """Validate Romanian postal code format"""
        postal_code = self.cleaned_data.get('postal_code')
        country = self.cleaned_data.get('country')
        
        if country == 'România' and postal_code:
            if not re.match(r'^\d{6}$', postal_code):
                raise ValidationError(_('Romanian postal codes must be 6 digits'))
        
        return postal_code


# ===============================================================================
# CUSTOMER NOTE FORM
# ===============================================================================

class CustomerNoteForm(forms.ModelForm):
    """
    Customer interaction notes form.
    """
    
    class Meta:
        model = CustomerNote
        fields = [
            'note_type',
            'title',
            'content',
            'is_important',
            'is_private'
        ]
        
        widgets = {
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
    
    def clean(self):
        """Cross-field validation"""
        cleaned_data = super().clean()
        customer_type = cleaned_data.get('customer_type')
        company_name = cleaned_data.get('company_name')
        vat_number = cleaned_data.get('vat_number')
        is_vat_payer = cleaned_data.get('is_vat_payer')
        cui = cleaned_data.get('cui')
        
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
        
        return cleaned_data
    
    def save(self, user=None):
        """Create customer with all related profiles"""
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
        
        return customer
