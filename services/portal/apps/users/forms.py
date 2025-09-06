"""
Portal Authentication Forms
Customer login forms for Portal service.
"""

from django import forms
from django.utils.translation import gettext as _


class CustomerLoginForm(forms.Form):
    """
    Customer login form for Portal authentication.
    Validates credentials via Platform API.
    """
    
    email = forms.EmailField(
        label=_("Email Address"),
        widget=forms.EmailInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors',
            'placeholder': _('Enter your email address'),
            'autofocus': True,
            'autocomplete': 'email',
        })
    )
    
    password = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors',
            'placeholder': _('Enter your password'),
            'autocomplete': 'current-password',
        })
    )
    
    remember_me = forms.BooleanField(
        label=_("Keep me logged in"),
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'w-4 h-4 text-blue-600 bg-slate-800 border-slate-600 rounded focus:ring-blue-500 focus:ring-2',
        })
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add custom error styling
        for field in self.fields.values():
            field.error_messages = {
                'required': _('This field is required.'),
                'invalid': _('Please enter a valid value.'),
            }